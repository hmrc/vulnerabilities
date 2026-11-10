/*
 * Copyright 2026 HM Revenue & Customs
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

package uk.gov.hmrc.vulnerabilities.v2.connector

import org.apache.pekko.stream.Materializer
import org.apache.pekko.stream.scaladsl.Source
import org.apache.pekko.util.ByteString
import play.api.Configuration
import play.api.libs.json.Json
import play.api.libs.ws.writeableOf_JsValue
import uk.gov.hmrc.http.{BadRequestException, HeaderCarrier, HttpReads, StringContextOps, UpstreamErrorResponse}
import uk.gov.hmrc.http.client.{HttpClientV2, readEitherSource}
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig
import uk.gov.hmrc.vulnerabilities.model.{ArtifactoryToken, ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.v2.model.xray.{XrayArtifactStatus, XrayReport}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

final class InvalidXrayResponse(message: String) extends UpstreamErrorResponse(message, 502, 502, Map.empty)

@Singleton
class XrayConnector @Inject() (
  servicesConfig: ServicesConfig,
  httpClientV2  : HttpClientV2,
  configuration : Configuration
)(using ExecutionContext, Materializer):

  private val baseUrl = servicesConfig.baseUrl("xray-v2")
  private val maxExportBytes =
    val configured = configuration.get[Long]("v2.xray.max-export-bytes")
    require(configured > 0 && configured < Int.MaxValue, "v2.xray.max-export-bytes must be between 1 and Int.MaxValue - 1")
    configured.toInt

  private def invalidResponse(message: String): UpstreamErrorResponse =
    InvalidXrayResponse(s"Invalid Xray v2 response: $message")

  private def upstreamFailure(status: Int): UpstreamErrorResponse =
    UpstreamErrorResponse(s"Xray v2 returned HTTP $status", status)

  private given reportRequestReads: HttpReads[XrayReport.ReportRequest] = (_, _, response) =>
    response.status match
      case 200 =>
        val result = XrayResponseDecoder.parseJson[XrayReport.ReportRequest](response.body.getBytes(java.nio.charset.StandardCharsets.UTF_8))
        if result.reportId <= 0 || result.status.isBlank then
          throw invalidResponse("invalid report ID or status")
        result
      case status => throw upstreamFailure(status)

  private given reportStatusReads: HttpReads[XrayReport.ReportStatus] = (_, _, response) =>
    response.status match
      case 200 =>
        val result = XrayResponseDecoder.parseJson[XrayReport.ReportStatus](response.body.getBytes(java.nio.charset.StandardCharsets.UTF_8))
        if result.status.isBlank || result.numberOfRows < 0 || result.totalArtefacts < 0 then
          throw invalidResponse("invalid report status or counts")
        result
      case status => throw upstreamFailure(status)

  private given deleteReads: HttpReads[Unit] = (_, _, response) =>
    response.status match
      case 200 | 204 => ()
      case status    => throw upstreamFailure(status)

  private given artifactStatusReads: HttpReads[XrayArtifactStatus] = (_, _, response) =>
    response.status match
      case 200 => XrayResponseDecoder.parseJson[XrayArtifactStatus](response.body.getBytes(java.nio.charset.StandardCharsets.UTF_8))
      case status => throw upstreamFailure(status)

  private def validateId(id: Int): Unit =
    if id <= 0 then throw new BadRequestException("Xray report ID must be positive")

  private def toReportName(serviceName: ServiceName, version: Version): String =
    if serviceName.asString.isBlank || version.original.isBlank then
      throw new BadRequestException("Service name and version must not be blank")
    s"AppSec-v2-report-${serviceName.asString}_${version.original.replace('.', '_')}"

  private def artefactName(path: String): String =
    val basename = path.substring(path.lastIndexOf('/') + 1)
    if basename.isBlank || basename == "." || basename == ".." || path.exists(c => c == '*' || c == '?') then
      throw new BadRequestException("Xray artefact path must have an exact, nonempty basename without wildcards")
    basename

  def generateReport(serviceName: ServiceName, version: Version, path: String)(token: ArtifactoryToken)(using HeaderCarrier): Future[XrayReport.ReportRequest] =
    val name = toReportName(serviceName, version)
    val basename = artefactName(path)
    httpClientV2
      .post(url"$baseUrl/xray/api/v1/reports/vulnerabilities")
      .setHeader(
        "Authorization" -> s"Bearer ${token.accessToken.decryptedValue}",
        "Content-Type"  -> "application/json"
      )
      .withBody(Json.obj(
        "name"      -> name,
        "resources" -> Json.obj("repositories" -> Json.arr(Json.obj("name" -> "webstore-local"))),
        "filters"   -> Json.obj("impacted_artifact" -> s"*/$basename")
      ))
      .execute[XrayReport.ReportRequest]

  def checkStatus(id: Int)(token: ArtifactoryToken)(using HeaderCarrier): Future[XrayReport.ReportStatus] =
    validateId(id)
    httpClientV2
      .get(url"$baseUrl/xray/api/v1/reports/$id")
      .setHeader("Authorization" -> s"Bearer ${token.accessToken.decryptedValue}")
      .execute[XrayReport.ReportStatus]

  // TODO: BDOG-3994: HMRC JFrog contract verification required.
  // Documented endpoint: POST /xray/api/v1/artifact/status.
  def checkArtifactStatus(repo: String, path: String)(token: ArtifactoryToken)(using HeaderCarrier): Future[XrayArtifactStatus] =
    if repo.isBlank || path.isBlank then
      throw new BadRequestException("Xray repository and repository-relative path must not be blank")
    httpClientV2
      .post(url"$baseUrl/xray/api/v1/artifact/status")
      .setHeader("Authorization" -> s"Bearer ${token.accessToken.decryptedValue}", "Content-Type" -> "application/json")
      .withBody(Json.obj("repo" -> repo, "path" -> path))
      .execute[XrayArtifactStatus]

  def downloadAndUnzipReport(reportId: Int, serviceName: ServiceName, version: Version)(token: ArtifactoryToken)(using HeaderCarrier): Future[XrayReport] =
    validateId(reportId)
    val name = toReportName(serviceName, version)
    httpClientV2
      .get(url"$baseUrl/xray/api/v1/reports/export/$reportId?file_name=$name&format=json")
      .setHeader("Authorization" -> s"Bearer ${token.accessToken.decryptedValue}")
      .stream[Either[UpstreamErrorResponse, Source[ByteString, _]]]
      .flatMap:
        case Left(error) => Future.failed(upstreamFailure(error.statusCode))
        case Right(source) =>
          source.runFold(ByteString.empty) { (accumulated, chunk) =>
            if chunk.length.toLong + accumulated.length > maxExportBytes then
              throw invalidResponse("compressed export exceeds size limit")
            accumulated ++ chunk
          }.map(bytes => XrayResponseDecoder.unzipReport(bytes, maxExportBytes))

  def deleteReportFromXray(reportId: Int)(token: ArtifactoryToken)(using HeaderCarrier): Future[Unit] =
    validateId(reportId)
    httpClientV2
      .delete(url"$baseUrl/xray/api/v1/reports/$reportId")
      .setHeader("Authorization" -> s"Bearer ${token.accessToken.decryptedValue}")
      .execute[Unit]
