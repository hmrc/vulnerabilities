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

package uk.gov.hmrc.vulnerabilities

import com.github.tomakehurst.wiremock.client.WireMock.*
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets.UTF_8
import java.time.Instant
import java.util.zip.{ZipEntry, ZipOutputStream}
import org.apache.pekko.actor.ActorSystem
import org.apache.pekko.stream.{Materializer, SystemMaterializer}
import org.scalatest.BeforeAndAfterEach
import org.scalatest.concurrent.{IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.Configuration
import play.api.libs.json.Json
import uk.gov.hmrc.crypto.Sensitive.SensitiveString
import uk.gov.hmrc.http.{BadRequestException, HeaderCarrier, RequestId, UpstreamErrorResponse}
import uk.gov.hmrc.http.test.{HttpClientV2Support, WireMockSupport}
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig
import uk.gov.hmrc.vulnerabilities.connector.XrayConnectorV2
import uk.gov.hmrc.vulnerabilities.model.{ArtifactoryToken, ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.model.v2.xray.XrayReport
import scala.concurrent.Await
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.duration.*
import scala.util.Using

class XrayConnectorV2ISpec
  extends AnyWordSpec
    with Matchers
    with ScalaFutures
    with IntegrationPatience
    with HttpClientV2Support
    with WireMockSupport
    with BeforeAndAfterEach:

  private given HeaderCarrier = HeaderCarrier(requestId = Some(RequestId("v2-xray-contract-check")))
  private val actorSystem = ActorSystem("xray-v2-connector-spec")
  private given Materializer = SystemMaterializer(actorSystem).materializer
  private val service = ServiceName("service1")
  private val version = Version("5.4.0")
  private val reportName = "AppSec-v2-report-service1_5_4_0"
  private val token = ArtifactoryToken(SensitiveString("dummy-v2-access-token"), SensitiveString("unused"))
  private val generated = Instant.parse("2026-09-11T10:00:00Z")

  private def connector(maxBytes: Int = 33554432): XrayConnectorV2 =
    val config = Configuration.from(Map(
      "microservice.services.xray-v2.protocol" -> "http",
      "microservice.services.xray-v2.host" -> "localhost",
      "microservice.services.xray-v2.port" -> wireMockPort,
      "v2.xray.max-export-bytes" -> maxBytes
    ))
    XrayConnectorV2(ServicesConfig(config), httpClientV2, config)

  override def beforeEach(): Unit =
    super.beforeEach()
    wireMockServer.resetAll()

  override def afterAll(): Unit =
    try super.afterAll()
    finally Await.result(actorSystem.terminate(), 10.seconds)

  private val row = Json.obj(
    "cves" -> Json.arr(
      Json.obj("cve" -> "CVE-2026-0001", "cvss_v3_score" -> 8.1),
      Json.obj("cve" -> "CVE-2026-0002")
    ),
    "summary" -> "Synthetic Xray finding",
    "severity" -> "High",
    "vulnerable_component" -> "gav://uk.gov.hmrc:example-lib:2.4.0",
    "component_physical_path" -> "lib/example-lib-2.4.0.jar",
    "impacted_artifact" -> "service1_5.4.0_0.5.2.tgz",
    "impact_path" -> Json.arr("service1", "example-lib"),
    "path" -> "webstore-local/service1/service1_5.4.0_0.5.2.tgz",
    "fixed_versions" -> Json.arr("2.4.1"),
    "published" -> "2026-09-01T10:00:00Z",
    "artifact_scan_time" -> "2026-09-11T10:00:00Z",
    "issue_id" -> "XRAY-EXAMPLE-0001",
    "package_type" -> "maven",
    "project_keys" -> Json.arr()
  )

  private def zip(entries: (String, String)*): Array[Byte] =
    val output = ByteArrayOutputStream()
    Using.resource(ZipOutputStream(output)): stream =>
      entries.foreach: (name, body) =>
        stream.putNextEntry(ZipEntry(name))
        stream.write(body.getBytes(UTF_8))
        stream.closeEntry()
    output.toByteArray

  private def stubExport(bytes: Array[Byte]): Unit =
    stubFor(get(urlPathEqualTo("/xray/api/v1/reports/export/1234"))
      .withQueryParam("file_name", equalTo(reportName))
      .withQueryParam("format", equalTo("json"))
      .willReturn(aResponse().withHeader("Content-Type", "application/zip").withBody(bytes)))

  private def download(client: XrayConnectorV2 = connector()) =
    client.downloadAndUnzipReport(1234, service, version)(token)

  private def assertBadExport(bytes: Array[Byte]): Unit =
    stubExport(bytes)
    val error = download().failed.futureValue
    assertUpstreamError(error, 502)

  private def assertUpstreamError(error: Throwable, status: Int): Unit =
    error match
      case upstream: UpstreamErrorResponse => upstream.statusCode shouldBe status
      case other => fail(s"Expected UpstreamErrorResponse with status $status", other)

  "XrayConnectorV2" should:
    "decode documented artefact status with exact repository-relative path and caller token, not coverage" in:
      stubFor(post(urlEqualTo("/xray/api/v1/artifact/status"))
        .willReturn(okJson("""{"overall":{"status":"DONE","time":"2026-09-11T10:00:00Z"},"details":{"sca":{"status":"DONE"}}}""")))
      val result = connector().checkArtifactStatus("webstore-local", "service1/service1.tgz")(token).futureValue
      result.overall.status shouldBe "DONE"
      result.overall.time shouldBe Some(generated)
      result.details.flatMap(_.sca).map(_.time) shouldBe Some(None)
      wireMockServer.verify(1, postRequestedFor(urlEqualTo("/xray/api/v1/artifact/status"))
        .withHeader("Authorization", equalTo("Bearer dummy-v2-access-token"))
        .withRequestBody(equalToJson("""{"repo":"webstore-local","path":"service1/service1.tgz"}""")))

    Seq("PENDING", "SCANNING", "DONE", "PARTIAL", "FAILED", "NOT_SUPPORTED", "NOT_SCANNED", "UNRECOGNISED").foreach: status =>
      s"preserve artefact scan status $status as wire data without inventing success" in:
        stubFor(post(urlEqualTo("/xray/api/v1/artifact/status"))
          .willReturn(okJson(s"""{"overall":{"status":"$status"},"details":{"sca":{"status":"$status"}}}""")))
        val result = connector().checkArtifactStatus("webstore-local", "service1/a.tgz")(token).futureValue
        result.overall.status shouldBe status
        result.overall.time shouldBe None
        result.details.flatMap(_.sca).map(_.status) shouldBe Some(status)

    Seq("""{"overall":{"status":"DONE"}}""", """{"overall":{"status":"DONE"},"details":{}}""").foreach: body =>
      s"retain missing optional SCA details without treating them as completion: $body" in:
        stubFor(post(urlEqualTo("/xray/api/v1/artifact/status")).willReturn(okJson(body)))
        connector().checkArtifactStatus("repo", "path")(token).futureValue.details.flatMap(_.sca) shouldBe None

    Seq("not JSON", "{}", """{"overall":{}}""", """{"overall":{"status":""}}""",
      """{"overall":{"status":12}}""", """{"overall":{"status":"DONE","time":"invalid"}}""",
      """{"overall":{"status":"DONE"},"details":{"sca":{}}}""").zipWithIndex.foreach { (body, index) =>
      s"reject malformed documented artefact status $index" in:
        stubFor(post(urlEqualTo("/xray/api/v1/artifact/status")).willReturn(okJson(body)))
        connector().checkArtifactStatus("repo", "path")(token).failed.futureValue shouldBe
          a[uk.gov.hmrc.vulnerabilities.connector.InvalidXrayResponseV2]
    }

    Seq(401, 403, 404, 429, 500).foreach: status =>
      s"preserve artefact-status HTTP $status without retrying" in:
        stubFor(post(urlEqualTo("/xray/api/v1/artifact/status")).willReturn(aResponse().withStatus(status)))
        assertUpstreamError(connector().checkArtifactStatus("repo", "path")(token).failed.futureValue, status)
        wireMockServer.verify(1, postRequestedFor(urlEqualTo("/xray/api/v1/artifact/status")))

    Seq("" -> "path", " " -> "path", "repo" -> "", "repo" -> "\t").foreach: (repo, path) =>
      s"reject blank artefact-status input ${repo.length}/${path.length} before HTTP" in:
        intercept[BadRequestException](connector().checkArtifactStatus(repo, path)(token))
        wireMockServer.getAllServeEvents shouldBe empty

    "generate the isolated V2 report with exact artefact filtering and caller credentials" in:
      stubFor(post(urlEqualTo("/xray/api/v1/reports/vulnerabilities"))
        .willReturn(okJson("""{"report_id":1234,"status":"pending"}""")))

      connector().generateReport(service, version, "some/path/service1_5.4.0_0.5.2.tgz")(token).futureValue shouldBe
        XrayReport.ReportRequest(1234, "pending")

      wireMockServer.verify(1, postRequestedFor(urlEqualTo("/xray/api/v1/reports/vulnerabilities"))
        .withHeader("Authorization", equalTo("Bearer dummy-v2-access-token"))
        .withHeader("Content-Type", containing("application/json"))
        .withHeader("X-Request-ID", equalTo("v2-xray-contract-check"))
        .withRequestBody(equalToJson(Json.stringify(Json.obj(
          "name" -> reportName,
          "resources" -> Json.obj("repositories" -> Json.arr(Json.obj("name" -> "webstore-local"))),
          "filters" -> Json.obj("impacted_artifact" -> "*/service1_5.4.0_0.5.2.tgz")
        )))))

    "escape filename characters structurally instead of interpolating raw JSON" in:
      stubFor(post(urlEqualTo("/xray/api/v1/reports/vulnerabilities"))
        .willReturn(okJson("""{"report_id":1234,"status":"pending"}""")))
      connector().generateReport(service, version, "path/a\"quoted.tgz")(token).futureValue
      wireMockServer.verify(postRequestedFor(urlEqualTo("/xray/api/v1/reports/vulnerabilities"))
        .withRequestBody(matchingJsonPath("$.filters.impacted_artifact", equalTo("*/a\"quoted.tgz"))))

    "expose each report status without retrying or treating pending as completion" in:
      stubFor(get(urlEqualTo("/xray/api/v1/reports/1234"))
        .willReturn(okJson("""{"status":"pending","number_of_rows":0,"total_artifacts":0}""")))
      connector().checkStatus(1234)(token).futureValue shouldBe XrayReport.ReportStatus("pending", 0, 0)
      wireMockServer.verify(1, getRequestedFor(urlEqualTo("/xray/api/v1/reports/1234"))
        .withHeader("Authorization", equalTo("Bearer dummy-v2-access-token")))

    "download and parse the real legacy-format ZIP fixture into independent V2 types" in:
      val bytes = Using.resource(getClass.getResourceAsStream("/xray_report_v1_x-no_descriptions.zip"))(_.readAllBytes())
      stubExport(bytes)
      val report = download().futureValue
      report.generatedDate shouldBe None
      report.rows should have size 11
      val jackson = report.rows.find(_.issueId == "XRAY-522015").getOrElse(fail("Missing expected Xray issue"))
      jackson.cves.flatMap(_.cveId) should contain("CVE-2023-35116")
      jackson.cvss3MaxScore shouldBe Some(4.7)
      report.rows.foreach: finding =>
        finding.description shouldBe None
        finding.references shouldBe empty
      wireMockServer.verify(1, getRequestedFor(urlPathEqualTo("/xray/api/v1/reports/export/1234"))
        .withQueryParam("file_name", equalTo(reportName))
        .withQueryParam("format", equalTo("json"))
        .withHeader("Authorization", equalTo("Bearer dummy-v2-access-token")))

    "preserve the upstream timestamp, multiple CVEs and absent optional enrichment" in:
      stubExport(zip("report.json" -> Json.stringify(Json.obj("generatedDate" -> generated, "rows" -> Json.arr(row)))))
      val report = download().futureValue
      report.generatedDate shouldBe Some(generated)
      report.rows.head.cves.flatMap(_.cveId) shouldBe Seq("CVE-2026-0001", "CVE-2026-0002")
      report.rows.head.cvss3MaxScore shouldBe None
      report.rows.head.description shouldBe None
      report.rows.head.references shouldBe empty
      report.rows.head.fixedVersions shouldBe Seq("2.4.1")

    "accept an explicitly empty rows array, without inventing a generation timestamp" in:
      stubExport(zip("report.json" -> """{"rows":[]}"""))
      download().futureValue shouldBe XrayReport(None, Seq.empty)

    "skip directory entries while accepting exactly one report document" in:
      stubExport(zip("folder/" -> "", "folder/report.json" -> """{"rows":[]}"""))
      download().futureValue.rows shouldBe empty

    "reject a non-ZIP response rather than returning a successful empty report" in:
      assertBadExport("not a ZIP archive".getBytes(UTF_8))

    "reject an empty ZIP archive" in:
      assertBadExport(zip())

    "reject an archive containing only directories" in:
      assertBadExport(zip("folder/" -> ""))

    "reject ambiguous archives with multiple report files" in:
      assertBadExport(zip("first.json" -> """{"rows":[]}""", "second.json" -> """{"rows":[]}"""))

    "reject malformed JSON" in:
      assertBadExport(zip("report.json" -> """{"rows":"""))

    "reject missing rows rather than substituting an empty result" in:
      assertBadExport(zip("report.json" -> "{}"))

    "reject a malformed finding rather than silently dropping it" in:
      assertBadExport(zip("report.json" -> """{"rows":[{"issue_id":"XRAY-INCOMPLETE"}]}"""))

    "reject an invalid supplied generation timestamp" in:
      assertBadExport(zip("report.json" -> """{"generatedDate":"invalid","rows":[]}"""))

    "bound the compressed download size" in:
      stubExport(zip("report.json" -> """{"rows":[]}"""))
      val error = download(connector(8)).failed.futureValue
      error shouldBe a[UpstreamErrorResponse]
      error.getMessage.toLowerCase should include("limit")

    "accept an export exactly at the compressed size limit" in:
      val bytes = zip("report.json" -> """{"rows":[]}""")
      stubExport(bytes)
      download(connector(bytes.length)).futureValue.rows shouldBe empty

    "bound the expanded report size even for highly compressible data" in:
      val bytes = zip("report.json" -> Json.stringify(Json.obj("padding" -> ("a" * 4096), "rows" -> Json.arr())))
      bytes.length should be < 512
      stubExport(bytes)
      val error = download(connector(512)).failed.futureValue
      error shouldBe a[UpstreamErrorResponse]
      error.getMessage.toLowerCase should include("limit")

    "accept a report exactly at the expanded size limit" in:
      val text = Json.stringify(Json.obj("padding" -> ("a" * 512), "rows" -> Json.arr()))
      val bytes = zip("report.json" -> text)
      val expandedBytes = text.getBytes(UTF_8).length
      bytes.length should be < expandedBytes
      stubExport(bytes)
      download(connector(expandedBytes)).futureValue.rows shouldBe empty

    "count directory payloads toward the expanded size bound" in:
      val bytes = zip("folder/" -> ("a" * 4096), "report.json" -> """{"rows":[]}""")
      bytes.length should be < 512
      stubExport(bytes)
      val error = download(connector(512)).failed.futureValue
      error shouldBe a[UpstreamErrorResponse]
      error.getMessage.toLowerCase should include("limit")

    Seq(401, 404, 429, 500).foreach: status =>
      s"preserve HTTP $status from report generation without retrying" in:
        stubFor(post(urlEqualTo("/xray/api/v1/reports/vulnerabilities"))
          .willReturn(aResponse().withStatus(status)))
        val error = connector().generateReport(service, version, "path/service1.tgz")(token).failed.futureValue
        assertUpstreamError(error, status)
        wireMockServer.verify(1, postRequestedFor(urlEqualTo("/xray/api/v1/reports/vulnerabilities")))

      s"preserve HTTP $status from status checks" in:
        stubFor(get(urlEqualTo("/xray/api/v1/reports/1234")).willReturn(aResponse().withStatus(status)))
        val error = connector().checkStatus(1234)(token).failed.futureValue
        assertUpstreamError(error, status)

      s"preserve HTTP $status from export instead of attempting to parse the error body as ZIP" in:
        stubFor(get(urlPathEqualTo("/xray/api/v1/reports/export/1234"))
          .willReturn(aResponse().withStatus(status).withBody("upstream error, not a ZIP")))
        val error = download().failed.futureValue
        assertUpstreamError(error, status)

      s"preserve HTTP $status from deletion" in:
        stubFor(delete(urlEqualTo("/xray/api/v1/reports/1234")).willReturn(aResponse().withStatus(status)))
        val error = connector().deleteReportFromXray(1234)(token).failed.futureValue
        assertUpstreamError(error, status)

    Seq(200, 204).foreach: status =>
      s"accept HTTP $status when deleting an explicitly supplied report ID" in:
        stubFor(delete(urlEqualTo("/xray/api/v1/reports/1234")).willReturn(aResponse().withStatus(status)))
        connector().deleteReportFromXray(1234)(token).futureValue shouldBe ()
        wireMockServer.verify(1, deleteRequestedFor(urlEqualTo("/xray/api/v1/reports/1234"))
          .withHeader("Authorization", equalTo("Bearer dummy-v2-access-token")))

    Seq("", "path/", "path/*service.tgz", "path/service?.tgz", ".", "..").foreach: path =>
      s"reject invalid artefact path '$path' before sending a generation request" in:
        val error = scala.util.Try(connector().generateReport(service, version, path)(token))
          .fold(identity, _.failed.futureValue)
        error shouldBe a[BadRequestException]
        wireMockServer.verify(0, postRequestedFor(urlEqualTo("/xray/api/v1/reports/vulnerabilities")))

    "reject nonpositive report IDs before sending status, export or deletion requests" in:
      val client = connector()
      Seq(
        () => client.checkStatus(0)(token),
        () => client.downloadAndUnzipReport(-1, service, version)(token),
        () => client.deleteReportFromXray(0)(token)
      ).foreach: call =>
        scala.util.Try(call()).fold(identity, _.failed.futureValue) shouldBe a[BadRequestException]
      wireMockServer.getAllServeEvents shouldBe empty

    "reject malformed report-generation responses" in:
      stubFor(post(urlEqualTo("/xray/api/v1/reports/vulnerabilities"))
        .willReturn(okJson("""{"report_id":0,"status":"pending"}""")))
      connector().generateReport(service, version, "path/service1.tgz")(token).failed.futureValue shouldBe a[UpstreamErrorResponse]

    "reject malformed upstream JSON without echoing its contents" in:
      stubFor(post(urlEqualTo("/xray/api/v1/reports/vulnerabilities"))
        .willReturn(okJson("DO_NOT_ECHO_UPSTREAM_BODY")))
      val error = connector().generateReport(service, version, "path/service1.tgz")(token).failed.futureValue
      assertUpstreamError(error, 502)
      error.getMessage should not include "DO_NOT_ECHO_UPSTREAM_BODY"

    "reject invalid report-status counts" in:
      stubFor(get(urlEqualTo("/xray/api/v1/reports/1234"))
        .willReturn(okJson("""{"status":"completed","number_of_rows":-1,"total_artifacts":1}""")))
      connector().checkStatus(1234)(token).failed.futureValue shouldBe a[UpstreamErrorResponse]
