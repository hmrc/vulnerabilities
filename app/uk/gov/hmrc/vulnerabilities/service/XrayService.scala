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

import akka.actor.ActorSystem
import cats.data.{EitherT}
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
    val payloads = svds.map(createXrayPayload).toList
    payloads.foldLeftM(0){(acc, payload) =>
      val maxRetries = 3
      def go(count: Int): Future[Int] =
        generateReport(payload).value.flatMap {
          case Left(XrayNoData)   => Future.successful(acc)
          case Left(XrayNotReady) => if (count > 0) go(count - 1)
                                     else Future.failed[Int](new RuntimeException(s"Tried to generate and download report $maxRetries times. Scheduler will cancel, and resume from this point the next time it runs. Manual cleanup will be required in the UI."))
          case Right(report)      => rawReportsRepository.insertReport(report, payload.name).map {_ => acc + 1}
      }
      go(maxRetries)
    }.map { processedCount =>
      logger.info(s"Finished processing $processedCount / ${payloads.size} payloads. " +
      s"Note this number may differ to the number of raw reports in the collection, as we don't download reports with no rows in.")
    }
  }

  private def generateReport(payload: ReportRequestPayload)(implicit hc: HeaderCarrier): EitherT[Future, Status, Report] =
    for {
      resp    <- EitherT.liftF(xrayConnector.generateReport(payload))
      status  <- EitherT.liftF(checkIfReportReady(resp))
      report  <- status match {
        case XraySuccess  => EitherT.fromOptionF(getReport(resp.reportID, payload.name), XrayNoData: Status)
        case XrayNoData   => for {
                               deleted <- EitherT.liftF(xrayConnector.deleteReportFromXray((resp.reportID)))
                               _       =  logger.info(s"${status.statusMessage} ${deleted.info}")
                               res     <- EitherT.leftT[Future, Report](XrayNoData: Status)
                             } yield res
        case XrayNotReady => EitherT.leftT[Future, Report](XrayNotReady: Status)
      }
    } yield report

  def createXrayPayload(svd: ServiceVersionDeployments): ReportRequestPayload =
    ReportRequestPayload(
      name      = s"AppSec-report-${svd.serviceName}_${svd.version}",
      resources = Resource(
        Seq(
          XrayRepo(name = "webstore-local")
        )
      ),
      filters   = Filter(impactedArtifact = s"*/${svd.serviceName}_${svd.version}*")
    )

  def getReport(reportId: Int, name: String)(implicit hc: HeaderCarrier): Future[Option[Report]] = {
    implicit val rfmt = Report.apiFormat
    for {
      zip     <- xrayConnector.downloadReport(reportId, name)
      _       <- xrayConnector.deleteReportFromXray(reportId)
      _        = logger.info("Report has been deleted from the Xray UI")
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

  def checkIfReportReady(reportRequestResponse: ReportRequestResponse, counter: Int = 0)(implicit hc: HeaderCarrier): Future[Status] =
    //Timeout after 15 secs
    if (counter < 15) {
      xrayConnector.checkStatus(reportRequestResponse.reportID).flatMap { rs => (rs.status, rs.rowCount) match {
        case ("completed", Some(rows)) if rows > 0 => Future.successful(XraySuccess)
        case ("completed", _)                      => Future.successful(XrayNoData)
        case _                                     => akka.pattern.after(1000.millis, system.scheduler) {
          checkIfReportReady(reportRequestResponse, counter + 1)
        }
      }}
    } else {
      Future.successful(XrayNotReady)
    }


}
