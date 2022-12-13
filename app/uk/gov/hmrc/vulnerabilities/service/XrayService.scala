/*
 * Copyright 2022 HM Revenue & Customs
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
import play.api.Logger
import play.api.libs.json.Json
import uk.gov.hmrc.vulnerabilities.connectors.XrayConnector
import uk.gov.hmrc.vulnerabilities.model.{Filter, Report, ReportDelete, ReportRequestPayload, ReportRequestResponse, Resource, ServiceVersionDeployments, Status, XrayFailure, XrayNoData, XrayRepo, XraySuccess}
import uk.gov.hmrc.vulnerabilities.persistence.RawReportsRepository

import java.util.zip.ZipInputStream
import javax.inject.{Inject, Singleton}
import scala.concurrent.duration.{FiniteDuration, MILLISECONDS}
import scala.concurrent.{ExecutionContext, Future}
import java.io.InputStream
import cats.implicits._

@Singleton
class XrayService @Inject()(
 xrayConnector: XrayConnector,
 system       : ActorSystem,
 rawReportsRepository: RawReportsRepository
)(implicit ec: ExecutionContext) {

  private val logger = Logger(this.getClass)

  def generateAndInsertReports(svds: Seq[ServiceVersionDeployments]): Future[Unit] = {
    val payloads = svds.map(createXrayPayload).toList
    payloads.foldLeftM(Seq.empty[String]){(processedPayloads, payload) =>
        for {
          resp   <- xrayConnector.generateReport(payload)
          status <- checkIfReportReady(resp, counter = 0)
          report <- status match {
            case XraySuccess => getReport(resp.reportID, payload.name)
            case _ => {
              logger.info(status.statusMessage)
              Future.successful(None)
            }
          }
          deleted <- status match {
            case XrayFailure => Future.successful(ReportDelete(info = "Report not successfully generated, won't attempt to delete. This may require manual cleanup in UI"))
            case _           => xrayConnector.deleteReport(resp.reportID)
          }
          _       = logger.info(s"${deleted.info} for ${payload.name}")
          _       = report match {
            case Some(rep) => {
              rawReportsRepository.insertReport(rep)
              logger.info(s"Inserted report for ${payload.name} into rawReports repository")
            }
            case _ => logger.info(s"No report to insert for ${payload.name}")
          }
        } yield processedPayloads :+ payload.name
    }.map{processed =>
      logger.info(s"Finished processing ${processed.length} payloads. " +
        s"Note this number may differ to the number of raw reports in the collection, as we don't download reports with no rows in.")
      Future.unit
    }
  }

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

  def getReport(reportId: Int, name: String): Future[Option[Report]] = {
    implicit val rfmt = Report.apiFormat
    for {
      zip     <- xrayConnector.downloadReport(reportId, name)
      text     = unzipReport(zip)
      report   = text.map(t => Json.parse(t).as[Report])
    } yield report
  }

   def unzipReport(inputStream: InputStream): Option[String] = {
    val zip = new ZipInputStream(inputStream)
    Iterator.continually(zip.getNextEntry)
      .takeWhile(_ != null)
      .foldLeft(Option.empty[String])((found, entry) => {
        Some(scala.io.Source.fromInputStream(zip).mkString)
      })
  }

  def checkIfReportReady(reportRequestResponse: ReportRequestResponse, counter: Int): Future[Status] = {
    //Timeout after 15 secs
    if (counter < 15) {
      xrayConnector.checkStatus(reportRequestResponse.reportID).flatMap { rs => (rs.status, rs.rowCount) match {
        case ("completed", Some(rows)) if rows > 0 => Future.successful(XraySuccess)
        case ("completed", _)                      => Future.successful(XrayNoData)
        case _                                     => akka.pattern.after(FiniteDuration(1000, MILLISECONDS), system.scheduler) {
          checkIfReportReady(reportRequestResponse, counter + 1)
        }
      }}
    } else {
      Future.successful(XrayFailure)
    }
  }


}
