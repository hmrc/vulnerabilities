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

package uk.gov.hmrc.vulnerabilities.connectors

import akka.stream.Materializer
import akka.stream.scaladsl.{Source, StreamConverters}
import akka.util.ByteString
import com.google.common.io.BaseEncoding
import play.api.{Logger, Logging}
import play.api.libs.json.Json
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, HttpResponse, StringContextOps, UpstreamErrorResponse}
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.vulnerabilities.model.{Report, ReportDelete, ReportRequestPayload, ReportRequestResponse, ReportStatus, Status}
import uk.gov.hmrc.http.HttpReads.Implicits._
import uk.gov.hmrc.vulnerabilities.config.XrayConfig

import java.io.InputStream
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class XrayConnector @Inject() (
  httpClientV2: HttpClientV2,
  config: XrayConfig
)(implicit
  ec: ExecutionContext,
  materializer: Materializer)
extends Logging{

  private val token = config.xrayToken

  def generateReport(payload: ReportRequestPayload)(implicit hc: HeaderCarrier): Future[ReportRequestResponse] = {

    implicit val pfmt = ReportRequestPayload.apiFormat
    implicit val rfmt = ReportRequestResponse.apiFormat

    httpClientV2
      .post(url"${config.xrayBaseUrl}/vulnerabilities")
      .withProxy
      .setHeader(
        "Authorization" -> s"Bearer $token",
        "Content-Type"  -> "application/json"
      ).withBody(Json.toJson(payload))
      .execute[ReportRequestResponse]
  }

  def checkStatus(id: Int)(implicit hc: HeaderCarrier): Future[ReportStatus] = {
    implicit val fmt = ReportStatus.apiFormat
    httpClientV2
      .get(url"${config.xrayBaseUrl}/$id")
      .withProxy
      .setHeader(
        "Authorization" -> s"Bearer $token",
        "Content-Type"  -> "application/json"
      )
      .execute[ReportStatus]
  }

  def downloadReport(reportId: Int, filename: String)(implicit hc: HeaderCarrier): Future[InputStream] = {
    implicit val fmt = Report.apiFormat

    httpClientV2
      .get(url"${config.xrayBaseUrl}/export/$reportId?file_name=$filename&format=json")
      .withProxy
      .setHeader(
        "Authorization" -> s"Bearer $token",
        "Content-Type" -> "application/json"
      )
      .stream[Either[UpstreamErrorResponse, Source[ByteString, _]]]
      .flatMap {
        case Right(source) =>
          logger.info(s"Successfully downloaded the zipped report from Xray")
          Future.successful(source.runWith(StreamConverters.asInputStream()))
        case Left(error) =>
          logger.error(s"Could not download zip for: ${config.xrayBaseUrl}/export/$reportId?file_name=$filename&format=json", error)
          throw error
      }
  }


    def deleteReportFromXray(reportId: Int)(implicit hc: HeaderCarrier): Future[ReportDelete] = {
      implicit val rdf = ReportDelete.apiFormat

      httpClientV2
        .delete(url"${config.xrayBaseUrl}/$reportId")
        .withProxy
        .setHeader(
          "Authorization" -> s"Bearer $token",
          "Content-Type"  -> "application/json"
        ).execute[ReportDelete]
    }

}
