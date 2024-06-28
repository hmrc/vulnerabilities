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
import play.api.{Configuration, Logger}
import play.api.libs.json.Json
import uk.gov.hmrc.vulnerabilities.connectors.XrayConnector
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.persistence.{RawReportsRepository, VulnerabilityAgeRepository}
import uk.gov.hmrc.http.HeaderCarrier

import cats.implicits._

import java.io.InputStream
import java.time.Instant
import java.util.zip.ZipInputStream
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
)(implicit ec: ExecutionContext) {

  private val logger = Logger(this.getClass)

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

  private val maxRetries = 3
  private def processReports(slugs: Seq[SlugInfo])(implicit hc: HeaderCarrier): Future[Unit] =
    slugs.foldLeftM(0) { case (acc, slug) =>
      def go(count: Int): Future[Int] =
        generateReport(slug).value.flatMap {
          case Left(XrayNotReady) if count > 0 => go(count - 1)
          case Left(XrayNotReady)              => Future.failed[Int](new RuntimeException(s"Tried to generate and download report for ${slug.serviceName.asString}:${slug.version.original} $maxRetries times."))
          case Left(_)                         => Future.successful(acc)
          case Right(report)                   => rawReportsRepository.put(report).map(_ => acc + 1)
        }

      go(maxRetries)
    }.map(x => logger.info(s"Finished processing $x / ${slugs.size} reports. Note this number may differ to the number of raw reports in the collection, as we don't download reports with no rows in."))

  private def generateReport(slug: SlugInfo)(implicit hc: HeaderCarrier): EitherT[Future, Status, Report] =
    for {
      resp   <- EitherT.liftF(xrayConnector.generateReport(slug.serviceName, slug.version))
      _      =  logger.info(s"Began generating report for ${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")}. Report will have id ${resp.reportID}")
      status <- EitherT.liftF(checkIfReportReady(resp))
      report <- status match {
                  case XraySuccess  => EitherT.fromOptionF(getReport(resp.reportID, slug), XrayNoData: Status)
                  case XrayNoData   => for {
                                         _ <- EitherT.liftF(xrayConnector.deleteReportFromXray(resp.reportID))
                                         _ =  logger.warn(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - Report ${resp.reportID} has no data ${status.statusMessage}. It has not been stored in mongo but has been deleted from the Xray UI")
                                         r <- EitherT.leftT[Future, Report](XrayNoData: Status)
                                       } yield r
                  case XrayNotReady => logger.warn(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - Report ${resp.reportID} was not created in time. It can not be stored in mongo or deleted.")
                                       EitherT.leftT[Future, Report](XrayNotReady: Status) // Error 500 if we add a delete here.
                }
      _      <- EitherT.liftF(vulnerabilityAgeRepository.insertNonExisting(report))
      _      <- EitherT.liftF(xrayConnector.deleteReportFromXray(resp.reportID))
      _      =  logger.info(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - Report ${resp.reportID} has been stored in mongo and deleted from the Xray UI")
    } yield report

  private [service] def getReport(reportId: Int, slug: SlugInfo)(implicit hc: HeaderCarrier): Future[Option[Report]] = {
    implicit val rfmt = Report.xrayFormat(
      slug.serviceName
    , slug.version
    , latest       = slug.flags.contains(SlugInfoFlag.Latest)
    , production   = slug.flags.contains(SlugInfoFlag.Production)
    , qa           = slug.flags.contains(SlugInfoFlag.QA)
    , staging      = slug.flags.contains(SlugInfoFlag.Staging)
    , development  = slug.flags.contains(SlugInfoFlag.Development)
    , externalTest = slug.flags.contains(SlugInfoFlag.ExternalTest)
    , integration  = slug.flags.contains(SlugInfoFlag.Integration)
    )
    for {
      zip    <- xrayConnector.downloadReport(reportId, slug.serviceName, slug.version)
      text   =  unzipReport(zip)
      report =  text.map(t => Json.parse(t).as[Report])
      _      =  zip.close()
    } yield report
  }

  private def unzipReport(inputStream: InputStream): Option[String] = {
    val zip = new ZipInputStream(inputStream)
    try {
      Iterator
        .continually(zip.getNextEntry)
        .takeWhile(_ != null)
        .foldLeft(Option.empty[String])((found, entry) => Some(scala.io.Source.fromInputStream(zip).mkString))
    } finally {
      zip.close()
    }
  }

  private val waitTimeSeconds: Long =
    configuration.get[FiniteDuration]("xray.reports.waitTime").toSeconds

  private [service] def checkIfReportReady(reportRequestResponse: ReportResponse, counter: Int = 0)(implicit hc: HeaderCarrier): Future[Status] =
    if (counter < waitTimeSeconds) {
      logger.info(s"checking report status for reportID: ${reportRequestResponse.reportID}")
      xrayConnector.checkStatus(reportRequestResponse.reportID).flatMap { rs => (rs.status, rs.rowCount) match {
        case ("completed", Some(rows)) if rows > 0 => Future.successful(XraySuccess)
        case ("completed", _)                      => Future.successful(XrayNoData)
        case _                                     => org.apache.pekko.pattern.after(1000.millis, system.scheduler) {
                                                        checkIfReportReady(reportRequestResponse, counter + 1)
                                                      }
      }}
    } else Future.successful(XrayNotReady)

  private [service] def deleteStaleReports()(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      ids   <- xrayConnector.getStaleReportIds()
      _     =  logger.info(s"Identified ${ids.size} stale reports to delete")
      count <- ids.foldLeftM[Future, Int](0){(acc, repId) =>
                 for {
                   _ <- xrayConnector.deleteReportFromXray(repId.id)
                   _ =  logger.info(s"Deleted stale report with id: ${repId.id}")
                 } yield acc + 1
               }
      _     =  logger.info(s"Deleted $count stale reports")
    } yield ()
}
