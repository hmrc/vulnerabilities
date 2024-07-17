/*
 * Copyright 2023 HM Revenue & Customs
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package uk.gov.hmrc.vulnerabilities.service

import org.apache.pekko.actor.ActorSystem
import cats.data.EitherT
import play.api.{Configuration, Logging}
import uk.gov.hmrc.vulnerabilities.connectors.XrayConnector
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.persistence.{RawReportsRepository, VulnerabilityAgeRepository}
import uk.gov.hmrc.http.HeaderCarrier

import cats.implicits._

import java.time.Instant
import javax.inject.{Inject, Singleton}
import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class XrayService @Inject()(
  configuration             : Configuration,
  xrayConnector             : XrayConnector,
  system                    : ActorSystem,
  rawReportsRepository      : RawReportsRepository,
  vulnerabilityAgeRepository: VulnerabilityAgeRepository
)(implicit ec: ExecutionContext) extends Logging {

  case class SlugInfo(
    serviceName: ServiceName,
    version    : Version,
    flags      : Seq[SlugInfoFlag]
  )

  def firstScan(serviceName: ServiceName, version: Version, flag: Option[SlugInfoFlag] = None)(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      _ <- deleteStaleReports()
      _ <- processReports(Seq(SlugInfo(serviceName, version, flag.toSeq)))
    } yield ()

  def rescanStaleReports(reportsBefore: Instant)(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      _          <- deleteStaleReports()
      oldReports <- rawReportsRepository.findGeneratedBefore(reportsBefore)
      slugs      =  oldReports.map(report => SlugInfo(
                      serviceName = report.serviceName
                    , version     = report.serviceVersion
                    , flags       = ( Option.when(report.latest      )(SlugInfoFlag.Latest      ) ++
                                      Option.when(report.development )(SlugInfoFlag.Development ) ++
                                      Option.when(report.integration )(SlugInfoFlag.Integration ) ++
                                      Option.when(report.qa          )(SlugInfoFlag.QA          ) ++
                                      Option.when(report.staging     )(SlugInfoFlag.Staging     ) ++
                                      Option.when(report.externalTest)(SlugInfoFlag.ExternalTest) ++
                                      Option.when(report.production  )(SlugInfoFlag.Production  )
                                    ).toSeq
                    ))
      _          <- processReports(slugs)
    } yield ()

  sealed trait XrayStatus
  case object XraySuccess extends XrayStatus
  case object XrayFailure extends XrayStatus
  case object XrayRetry   extends XrayStatus

  private val maxRetries = 3
  private def processReports(slugs: Seq[SlugInfo])(implicit hc: HeaderCarrier): Future[Unit] =
    slugs.foldLeftM(0) { case (acc, slug) =>
      def go(count: Int): Future[Int] =
        generateReport(slug).value.flatMap {
          case Left(XrayRetry) if count > 0 => go(count - 1)
          case Left(XrayRetry)              => Future.failed[Int](new RuntimeException(s"Tried to generate and download report for ${slug.serviceName.asString}:${slug.version.original} $maxRetries times."))
          case Left(_)                      => Future.successful(acc)
          case Right(report)                => rawReportsRepository.put(report).map(_ => acc + 1)
        }

      go(maxRetries)
    }.map(x => logger.info(s"Finished processing $x / ${slugs.size} reports."))

  private def generateReport(slug: SlugInfo)(implicit hc: HeaderCarrier): EitherT[Future, XrayStatus, Report] =
    EitherT
      .liftF(xrayConnector.generateReport(slug.serviceName, slug.version))
      .flatMap { resp =>
        logger.info(s"Began generating report for ${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")}. Report will have id ${resp.reportID}")
        val et =
          for {
            oStatus <- EitherT.liftF(checkIfReportReady(resp))
            count   =  oStatus.fold(0)(_.rowCount.getOrElse(0))
            _       =  logger.info(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - Report status ${oStatus.fold("report was not generated in time")(_ => s"report has $count rows")}")
            tuple   <-  oStatus match {
                         case Some(_) if count > 0 => EitherT.fromOptionF(xrayConnector.downloadAndUnzipReport(resp.reportID, slug.serviceName, slug.version), XrayFailure: XrayStatus)
                         case Some(_)              => EitherT.rightT[Future, XrayStatus]((Instant.now(),  Seq.empty[RawVulnerability]))
                         case None                 => EitherT.leftT[Future, (Instant, Seq[RawVulnerability])](XrayRetry: XrayStatus)
                       }
            (date, rows)
                    = tuple
            report  =  Report(
                         slug.serviceName
                       , slug.version
                       , latest        = slug.flags.contains(SlugInfoFlag.Latest)
                       , production    = slug.flags.contains(SlugInfoFlag.Production)
                       , qa            = slug.flags.contains(SlugInfoFlag.QA)
                       , staging       = slug.flags.contains(SlugInfoFlag.Staging)
                       , development   = slug.flags.contains(SlugInfoFlag.Development)
                       , externalTest  = slug.flags.contains(SlugInfoFlag.ExternalTest)
                       , integration   = slug.flags.contains(SlugInfoFlag.Integration)
                       , generatedDate = date
                       , rows          = rows
                       )
            _       <- EitherT.liftF[Future, XrayStatus, Unit](vulnerabilityAgeRepository.insertNonExisting(report))
          } yield report

        et.value.onComplete {
          case _ => xrayConnector
                      .deleteReportFromXray(resp.reportID)
                      .map( _ =>
                        logger.info(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - Report ${resp.reportID} has been deleted from the Xray UI")
                      )
                      .recover {
                        case ex => logger.error(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - Report ${resp.reportID} could not be deleted from the Xray UI", ex)
                      }
        }

        et
      }

  private val waitTimeSeconds: Long =
    configuration.get[FiniteDuration]("xray.reports.waitTime").toSeconds

  private [service] def checkIfReportReady(reportRequestResponse: ReportResponse, counter: Int = 0)(implicit hc: HeaderCarrier): Future[Option[ReportStatus]] =
    if (counter < waitTimeSeconds) {
      logger.info(s"checking report status for reportID: ${reportRequestResponse.reportID}")
      xrayConnector
        .checkStatus(reportRequestResponse.reportID)
        .flatMap {
          case rs if rs.status == "completed" => Future.successful(Some(rs))
          case _                              => org.apache.pekko.pattern.after(1000.millis, system.scheduler) {
                                                   checkIfReportReady(reportRequestResponse, counter + 1)
                                                 }
        }
    } else Future.successful(None)

  private [service] def deleteStaleReports()(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      ids   <- xrayConnector.getStaleReportIds()
      _     =  logger.info(s"Identified ${ids.size} stale reports to delete")
      count <- ids.foldLeftM[Future, Int](0){(acc, repId) =>
                 for {
                   _ <- xrayConnector
                          .deleteReportFromXray(repId.id)
                          .recover {
                            case ex => logger.error(s"Report ${repId.id} could not be deleted from the Xray UI - this report should be deleted manually", ex)
                          }
                   _ =  logger.info(s"Deleted stale report with id: ${repId.id}")
                 } yield acc + 1
               }
      _     =  logger.info(s"Deleted $count stale reports")
    } yield ()
}
