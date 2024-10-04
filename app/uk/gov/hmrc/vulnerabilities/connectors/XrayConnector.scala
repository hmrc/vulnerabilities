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

package uk.gov.hmrc.vulnerabilities.connectors

import org.apache.pekko.stream.Materializer
import org.apache.pekko.stream.scaladsl.{Source, StreamConverters}
import org.apache.pekko.util.ByteString
import play.api.{Configuration, Logging}
import play.api.libs.json.{Json, Reads, __}
import play.api.libs.ws.writeableOf_JsValue
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, StringContextOps, UpstreamErrorResponse}
import uk.gov.hmrc.http.client.{HttpClientV2, readEitherSource}
import uk.gov.hmrc.vulnerabilities.model.{ReportId, RawVulnerability, ReportResponse, ReportStatus, ServiceName, Version}

import java.io.InputStream
import java.time.{Clock, Instant}
import java.time.temporal.ChronoUnit
import javax.inject.{Inject, Singleton}
import scala.concurrent.duration.FiniteDuration
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class XrayConnector @Inject() (
  configuration: Configuration,
  httpClientV2 : HttpClientV2,
  clock        : Clock
)(implicit
  ec           : ExecutionContext,
  mat          : Materializer
) extends Logging{
  import HttpReads.Implicits._

  private val xrayBaseUrl         : String         = configuration.get[String]("xray.url")
  private val xrayToken           : String         = configuration.get[String]("xray.token")
  private val xrayUsername        : String         = configuration.get[String]("xray.username")
  private val xrayReportsRetention: FiniteDuration = configuration.get[FiniteDuration]("xray.reports.retention")

  private def toReportName(serviceName: ServiceName, version: Version): String =
    s"AppSec-report-${serviceName.asString}_${version.original.replaceAll("\\.", "_")}"

  // https://jfrog.com/help/r/xray-rest-apis/generate-vulnerabilities-report
  def generateReport(serviceName: ServiceName, version: Version)(implicit hc: HeaderCarrier): Future[ReportResponse] = {
    implicit val rfmt = ReportResponse.apiFormat
    httpClientV2
      .post(url"${xrayBaseUrl}/vulnerabilities")
      .setHeader(
        "Authorization" -> s"Bearer $xrayToken",
        "Content-Type"  -> "application/json"
      ).withBody(Json.parse(
        s"""{"name":"${toReportName(serviceName, version)}","resources":{"repositories":[{"name":"webstore-local"}]},"filters":{"impacted_artifact":"*/${serviceName.asString}_${version.original}*.tgz"}}"""
      ))
      .execute[ReportResponse]
  }

  // https://jfrog.com/help/r/xray-rest-apis/get-report-details-by-id
  def checkStatus(id: Int)(implicit hc: HeaderCarrier): Future[ReportStatus] = {
    implicit val fmt = ReportStatus.apiFormat
    httpClientV2
      .get(url"${xrayBaseUrl}/$id")
      .setHeader(
        "Authorization" -> s"Bearer $xrayToken",
        "Content-Type"  -> "application/json"
      )
      .execute[ReportStatus]
  }

  def downloadAndUnzipReport(reportId: Int, serviceName: ServiceName, version: Version)(implicit hc: HeaderCarrier): Future[Option[(Instant, Seq[RawVulnerability])]] = {
    implicit val readsRawVulnerability: Reads[RawVulnerability] = RawVulnerability.apiFormat
    for {
      zip    <- downloadReport(reportId, serviceName, version)
      result =  unzipReport(zip)
                  .map(Json.parse)
                  .map { json =>
                    val date = (json \ "generatedDate").asOpt[Instant].getOrElse(Instant.now())
                    val rows = (json \ "rows"         ).as[Seq[RawVulnerability]]
                    (date, rows)
                  }
    } yield result
  }

  private def unzipReport(inputStream: InputStream): Option[String] = {
    val zip = new java.util.zip.ZipInputStream(inputStream)
    try {
      Iterator
        .continually(zip.getNextEntry)
        .takeWhile(_ != null)
        .foldLeft(Option.empty[String])((found, entry) => Some(scala.io.Source.fromInputStream(zip).mkString))
    } finally {
      zip.close()
    }
  }

  // https://jfrog.com/help/r/xray-rest-apis/export
  private def downloadReport(reportId: Int, serviceName: ServiceName, version: Version)(implicit hc: HeaderCarrier): Future[InputStream] = {
    val fileName = toReportName(serviceName, version)
    val url = url"${xrayBaseUrl}/export/$reportId?file_name=${fileName}&format=json"
    httpClientV2
      .get(url)
      .setHeader(
        "Authorization" -> s"Bearer $xrayToken",
        "Content-Type"  -> "application/json"
      )
      .stream[Either[UpstreamErrorResponse, Source[ByteString, _]]]
      .flatMap {
        case Right(source) =>
          logger.info(s"Successfully downloaded the zipped report for $fileName with id $reportId from Xray")
          Future.successful(source.runWith(StreamConverters.asInputStream()))
        case Left(error) =>
          logger.error(s"Could not download zip for: $url", error)
          throw error
      }
  }

  // https://jfrog.com/help/r/xray-rest-apis/delete
  def deleteReportFromXray(reportId: Int)(implicit hc: HeaderCarrier): Future[Unit] =
    httpClientV2
      .delete(url"${xrayBaseUrl}/$reportId")
      .setHeader(
        "Authorization" -> s"Bearer $xrayToken",
        "Content-Type"  -> "application/json"
      ).execute[Unit](throwOnFailure(implicitly[HttpReads[Either[UpstreamErrorResponse, Unit]]]), implicitly[ExecutionContext])

  // https://jfrog.com/help/r/xray-rest-apis/get-reports-list
  def getStaleReportIds()(implicit hc: HeaderCarrier): Future[Seq[ReportId]] = {
    given Reads[Seq[ReportId]] =
      (__ \ "reports")
        .read(Reads.seq[ReportId](ReportId.reads))

    val cutOff = Instant.now(clock).minus(xrayReportsRetention.toMillis, ChronoUnit.MILLIS)
    httpClientV2
      .post(url"${xrayBaseUrl}?page_num=1&num_of_rows=100")
      .setHeader(
        "Authorization" -> s"Bearer $xrayToken",
        "Content-Type"  -> "application/json"
      ).withBody(Json.parse(
        s"""{"filters":{"author":"${xrayUsername}","start_time_range":{"start":"2023-06-01T00:00:00Z","end":"$cutOff"}}}"""
      ))
      .execute[Seq[ReportId]]
  }
}
