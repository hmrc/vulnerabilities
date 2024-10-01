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
  object SlugInfo {
    def fromReport(report: Report) =
      SlugInfo(
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
      )
  }

  def firstScan(serviceName: ServiceName, version: Version, flag: Option[SlugInfoFlag] = None)(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      _ <- deleteStaleReports()
      _ <- processReports(Seq(SlugInfo(serviceName, version, flag.toSeq)))
    } yield ()

  def rescanStaleReports(reportsBefore: Instant)(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      _       <- deleteStaleReports()
      reports <- rawReportsRepository.findGeneratedBefore(reportsBefore)
      _       <- processReports(reports.map(SlugInfo.fromReport))
    } yield ()

  def fixNotScanned()(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      _       <- deleteStaleReports()
      reports <- rawReportsRepository.findNotScanned()
      _       <- processReports(reports.map(SlugInfo.fromReport))
    } yield ()

  sealed trait XrayStatus
  case object XrayFailure extends XrayStatus
  case object XrayRetry   extends XrayStatus

  private val maxRetries = 3
  private def processReports(slugs: Seq[SlugInfo])(implicit hc: HeaderCarrier): Future[Unit] =
    slugs.foldLeftM(0) { case (acc, slug) =>
      def go(count: Int): Future[Int] =
        scan(slug).value.flatMap {
          case Left(XrayRetry)
            if count <= maxRetries => go(count + 1)
          case Left(XrayRetry)
             | Left(XrayFailure)   => logger.error(s"Tried to scan ${slug.serviceName.asString}:${slug.version.original} $count times.")
                                       val report = toReport(slug, generatedDate = Instant.now(), rows = Nil, scanned = false)
                                       for {
                                        _ <- rawReportsRepository.put(report)
                                       } yield acc + 1
          case Right((date, rows)) => val report = toReport(slug, generatedDate = date, rows = rows, scanned = true)
                                      for {
                                       _ <- vulnerabilityAgeRepository.insertNonExisting(report)
                                       _ <- rawReportsRepository.put(report)
                                      } yield acc
      }

      go(1)
    }.map(x => logger.info(s"Finished processing $x / ${slugs.size} reports."))

  private def toReport(slug: SlugInfo, generatedDate: Instant, rows: Seq[RawVulnerability], scanned: Boolean): Report =
    Report(
      slug.serviceName
    , slug.version
    , latest        = slug.flags.contains(SlugInfoFlag.Latest)
    , production    = slug.flags.contains(SlugInfoFlag.Production)
    , qa            = slug.flags.contains(SlugInfoFlag.QA)
    , staging       = slug.flags.contains(SlugInfoFlag.Staging)
    , development   = slug.flags.contains(SlugInfoFlag.Development)
    , externalTest  = slug.flags.contains(SlugInfoFlag.ExternalTest)
    , integration   = slug.flags.contains(SlugInfoFlag.Integration)
    , generatedDate = generatedDate
    , rows          = rows
    , scanned       = scanned
    )

  private def scan(slug: SlugInfo)(implicit hc: HeaderCarrier): EitherT[Future, XrayStatus, (Instant, Seq[RawVulnerability])] =
    EitherT
      .liftF(xrayConnector.generateReport(slug.serviceName, slug.version))
      .flatMap { resp =>
        logger.info(s"Began generating report for ${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")}. Report will have id ${resp.reportID}")
        val et =
          for {
            status  <- EitherT(checkIfReportReady(slug, resp))
            tuple   <- if (status.numberOfRows > 0) EitherT.fromOptionF(xrayConnector.downloadAndUnzipReport(resp.reportID, slug.serviceName, slug.version), XrayFailure: XrayStatus)
                       else                         EitherT.rightT[Future, XrayStatus]((Instant.now(), Seq.empty[RawVulnerability]))
          } yield tuple

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

  private [service] def checkIfReportReady(slug: SlugInfo, reportResponse: ReportResponse, counter: Int = 0)(implicit hc: HeaderCarrier): Future[Either[XrayStatus, ReportStatus]] =
    xrayConnector
      .checkStatus(reportResponse.reportID)
      .flatMap {
        case rs if counter >= waitTimeSeconds =>
          logger.error(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - report was not ready in time: last status ${rs.status} for reportID: ${reportResponse.reportID}")
          Future.successful(Left(XrayRetry))
        case rs if rs.status == "completed" && rs.totalArtifacts == 0 =>
          logger.error(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - no artefact scanned for reportID: ${reportResponse.reportID}")
          Future.successful(Left(XrayFailure))
        case rs if rs.status == "completed" =>
          logger.info(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - report status ${rs.status} number of rows ${rs.numberOfRows} total Artifacts scanned ${rs.totalArtifacts} for reportID: ${reportResponse.reportID}")
          Future.successful(Right(rs))
        case rs =>
          org.apache.pekko.pattern.after(1000.millis, system.scheduler) {
            logger.info(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - report status is ${rs.status} - rerunning for reportID: ${reportResponse.reportID}")
            checkIfReportReady(slug, reportResponse, counter + 1)
          }
      }

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
