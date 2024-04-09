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
import play.api.Logger
import play.api.libs.json.Json
import uk.gov.hmrc.vulnerabilities.connectors.XrayConnector
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.persistence.RawReportsRepository

import java.util.zip.ZipInputStream
import javax.inject.{Inject, Singleton}
import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future}
import java.io.InputStream
import cats.implicits._
import uk.gov.hmrc.http.HeaderCarrier


@Singleton
class XrayService @Inject()(
 xrayConnector: XrayConnector,
 system       : ActorSystem,
 rawReportsRepository: RawReportsRepository
)(implicit ec: ExecutionContext) {

  private val logger = Logger(this.getClass)

  def processReports(svds: Seq[ServiceVersionDeployments])(implicit hc: HeaderCarrier): Future[Unit] = {
    svds.foldLeftM(0){(acc, svd) =>
      val maxRetries = 3
      def go(count: Int): Future[Int] =
        generateReport(svd).value.flatMap {
          case Left(XrayNoData)          => Future.successful(acc)
          case Left(XrayNotReady)        =>
            if (count > 0) go(count - 1)
            else Future.failed[Int](new RuntimeException(s"Tried to generate and download report for ${svd.serviceName}:${svd.serviceName} $maxRetries times. Scheduler will cancel, and resume from this point the next time it runs. Manual cleanup will be required in the UI."))
          case Right(report) => rawReportsRepository.insertReport(report, svd.serviceName).map(_ => acc + 1)
      }
      go(maxRetries)
    }.map { processedCount =>
      logger.info(s"Finished processing $processedCount / ${svds.size} reports. " +
        s"Note this number may differ to the number of raw reports in the collection, as we don't download reports with no rows in.")
    }
  }

  private def generateReport(svd: ServiceVersionDeployments)(implicit hc: HeaderCarrier): EitherT[Future, Status, Report] =
    for {
      resp    <- EitherT.liftF(xrayConnector.generateReport(svd))
      _       =  logger.info(s"Began generating report for ${svd.serviceName}:${svd.version}. Report will have id ${resp.reportID}")
      status  <- EitherT.liftF(checkIfReportReady(resp))
      report  <- status match {
                   case XraySuccess  => EitherT.fromOptionF(getReport(resp.reportID, svd), XrayNoData: Status)
                   case XrayNoData   => for {
                                          _       <- EitherT.liftF(xrayConnector.deleteReportFromXray(resp.reportID))
                                          _       =  logger.info(s"${status.statusMessage}. Report ${resp.reportID} has been deleted from the Xray UI")
                                          res     <- EitherT.leftT[Future, Report](XrayNoData: Status)
                                        } yield res
                   case XrayNotReady => EitherT.leftT[Future, Report](XrayNotReady: Status)
                 }
    } yield report

  def getReport(reportId: Int, svd: ServiceVersionDeployments)(implicit hc: HeaderCarrier): Future[Option[Report]] = {
    implicit val rfmt = Report.apiFormat(svd.serviceName, svd.version)
    for {
      zip     <- xrayConnector.downloadReport(reportId, svd)
      _       <- xrayConnector.deleteReportFromXray(reportId)
      _        = logger.info(s"Report ${reportId} has been deleted from the Xray UI")
      text     = unzipReport(zip)
      report   = text.map(t => Json.parse(t).as[Report])
      _        = zip.close()
    } yield report
  }

   def unzipReport(inputStream: InputStream): Option[String] = {
    val zip = new ZipInputStream(inputStream)
    try {
      Iterator.continually(zip.getNextEntry)
        .takeWhile(_ != null)
        .foldLeft(Option.empty[String])((found, entry) => Some(scala.io.Source.fromInputStream(zip).mkString))
    } finally {
     zip.close()
    }
   }

  def checkIfReportReady(reportRequestResponse: ReportResponse, counter: Int = 0)(implicit hc: HeaderCarrier): Future[Status] =
    //Timeout after 15 secs
    if (counter < 15) {
      logger.info(s"checking report status for reportID: ${reportRequestResponse.reportID}")
      xrayConnector.checkStatus(reportRequestResponse.reportID).flatMap { rs => (rs.status, rs.rowCount) match {
        case ("completed", Some(rows)) if rows > 0 => Future.successful(XraySuccess)
        case ("completed", _)                      => Future.successful(XrayNoData)
        case _                                     => org.apache.pekko.pattern.after(1000.millis, system.scheduler) {
                                                        checkIfReportReady(reportRequestResponse, counter + 1)
                                                      }
      }}
    } else
      Future.successful(XrayNotReady)

  def deleteStaleReports()(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      ids          <- xrayConnector.getStaleReportIds()
      _            =  logger.info(s"Identified ${ids.size} stale reports to delete")
      deletedCount <- ids.foldLeftM[Future, Int](0){(acc, repId) =>
                        for {
                          _ <- xrayConnector.deleteReportFromXray(repId.id)
                          _ =  logger.info(s"Deleted stale report with id: ${repId.id}")
                        } yield acc + 1
                      }
      _            =  logger.info(s"Deleted ${deletedCount} stale reports")
    } yield ()
}
