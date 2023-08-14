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

import akka.stream.Materializer
import akka.stream.scaladsl.{Source, StreamConverters}
import akka.util.ByteString
import play.api.Logging
import play.api.libs.json.{Json, Reads, __}
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, StringContextOps, UpstreamErrorResponse}
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.vulnerabilities.model.{ReportId, ReportResponse, ReportStatus, ServiceVersionDeployments}
import uk.gov.hmrc.vulnerabilities.config.XrayConfig

import java.io.InputStream
import java.time.{Clock, Instant}
import java.time.temporal.ChronoUnit
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class XrayConnector @Inject() (
  httpClientV2: HttpClientV2,
  config      : XrayConfig,
  clock       : Clock
)(implicit
  ec          : ExecutionContext,
  mat         : Materializer
) extends Logging{
  import HttpReads.Implicits._

  private val token = config.xrayToken

  def generateReport(svd: ServiceVersionDeployments)(implicit hc: HeaderCarrier): Future[ReportResponse] = {
    implicit val rfmt = ReportResponse.apiFormat

    val requestBody =
      s"""{"name":"AppSec-report-${svd.serviceName}_${svd.version}","resources":{"repositories":[{"name":"webstore-local"}]},"filters":{"impacted_artifact":"*/${svd.serviceName}_${svd.version}*"}}"""

    httpClientV2
      .post(url"${config.xrayBaseUrl}/vulnerabilities")
      .setHeader(
        "Authorization" -> s"Bearer $token",
        "Content-Type"  -> "application/json"
      ).withBody(Json.parse(requestBody))
      .execute[ReportResponse]
  }

  def checkStatus(id: Int)(implicit hc: HeaderCarrier): Future[ReportStatus] = {
    implicit val fmt = ReportStatus.apiFormat
    httpClientV2
      .get(url"${config.xrayBaseUrl}/$id")
      .setHeader(
        "Authorization" -> s"Bearer $token",
        "Content-Type"  -> "application/json"
      )
      .execute[ReportStatus]
  }

  def downloadReport(reportId: Int, svd: ServiceVersionDeployments)(implicit hc: HeaderCarrier): Future[InputStream] = {
    val fileName = s"AppSec-report-${svd.serviceName}_${svd.version}"
    val url = url"${config.xrayBaseUrl}/export/$reportId?file_name=${fileName}&format=json"
    httpClientV2
      .get(url)
      .setHeader(
        "Authorization" -> s"Bearer $token",
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

    def deleteReportFromXray(reportId: Int)(implicit hc: HeaderCarrier): Future[Unit] =
      httpClientV2
        .delete(url"${config.xrayBaseUrl}/$reportId")
        .setHeader(
          "Authorization" -> s"Bearer $token",
          "Content-Type"  -> "application/json"
        ).execute[Unit](throwOnFailure(implicitly[HttpReads[Either[UpstreamErrorResponse, Unit]]]), implicitly[ExecutionContext])

    def getStaleReportIds()(implicit hc: HeaderCarrier): Future[Seq[ReportId]] = {
      implicit val rir = {
        implicit val rir = ReportId.reads
        Reads.at[Seq[ReportId]](__ \ "reports")
      }
      val cutOff       = Instant.now(clock).minus(config.xrayReportsRetention.toMillis, ChronoUnit.MILLIS)
      val requestBody  = s"""{"filters":{"author":"${config.xrayUsername}","start_time_range":{"start":"2023-06-01T00:00:00Z","end":"$cutOff"}}}"""

      httpClientV2
        .post(url"${config.xrayBaseUrl}?page_num=1&num_of_rows=100")
        .setHeader(
          "Authorization" -> s"Bearer $token",
          "Content-Type"  -> "application/json"
        ).withBody(Json.parse(requestBody))
        .execute[Seq[ReportId]]
    }
}
