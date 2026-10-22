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

package uk.gov.hmrc.vulnerabilities.support

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.*
import com.github.tomakehurst.wiremock.stubbing.Scenario.STARTED
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets.UTF_8
import java.time.Instant
import java.util.concurrent.atomic.AtomicInteger
import java.util.zip.{ZipEntry, ZipOutputStream}
import play.api.libs.json.*
import play.api.routing.Router.Routes
import play.api.routing.SimpleRouter
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.ScanContextV2
import scala.util.Using

final class V2IngestionManualRouter extends SimpleRouter:
  override def routes: Routes = PartialFunction.empty

class XrayWireMockFixturesV2(server: WireMockServer, coverage: ControlledArtifactCoverageVerifierV2):
  private val next = AtomicInteger(1234)
  val generated: Instant = Instant.parse("2026-10-21T12:00:00Z")

  def row(artefact: String): JsObject = Json.obj(
    "cves" -> Json.arr(Json.obj("cve" -> "CVE-2026-0001", "cvss_v3_score" -> 8.1)),
    "summary" -> "Synthetic finding", "severity" -> "High",
    "vulnerable_component" -> "gav://uk.gov.hmrc:example-lib:2.4.0",
    "component_physical_path" -> "lib/example-lib.jar", "impacted_artifact" -> artefact.split("/").last,
    "impact_path" -> Json.arr(), "path" -> artefact, "fixed_versions" -> Json.arr("2.4.1"),
    "published" -> generated, "artifact_scan_time" -> generated, "issue_id" -> "XRAY-SYNTHETIC",
    "package_type" -> "maven", "project_keys" -> Json.arr())

  private def zip(text: String): Array[Byte] =
    val bytes = ByteArrayOutputStream()
    Using.resource(ZipOutputStream(bytes)): output =>
      output.putNextEntry(ZipEntry("report.json"))
      output.write(text.getBytes(UTF_8))
      output.closeEntry()
    bytes.toByteArray

  def stub(context: ScanContextV2, artefact: String, rows: Seq[JsObject], mode: String = "populated"): Int =
    val id = next.getAndIncrement()
    server.stubFor(post(urlEqualTo("/xray/api/v1/reports/vulnerabilities")).atPriority(10)
      .willReturn(aResponse().withStatus(400)))
    server.stubFor(post(urlEqualTo("/xray/api/v1/reports/vulnerabilities")).atPriority(1)
      .withHeader("Authorization", equalTo("Bearer dummy-v2-access-token"))
      .withRequestBody(matchingJsonPath("$.resources.repositories[0].name", equalTo("webstore-local")))
      .withRequestBody(matchingJsonPath("$.filters.impacted_artifact", equalTo("*/" + artefact.split("/").last)))
      .willReturn(okJson(s"""{"report_id":$id,"status":"pending"}""")))
    val terminal = if mode == "failed" then "failed" else if mode == "unknown" then "unrecognised" else "completed"
    val count = if mode == "zero-artefacts" then 0 else 1
    val scenario = s"report-$id"
    server.stubFor(get(urlEqualTo(s"/xray/api/v1/reports/$id")).inScenario(scenario).whenScenarioStateIs(STARTED)
      .willReturn(okJson("""{"status":"pending","number_of_rows":0,"total_artifacts":0}""")).willSetStateTo("ready"))
    server.stubFor(get(urlEqualTo(s"/xray/api/v1/reports/$id")).inScenario(scenario).whenScenarioStateIs("ready")
      .willReturn(okJson(Json.stringify(Json.obj("status" -> terminal, "number_of_rows" -> rows.size, "total_artifacts" -> count)))))
    if mode != "missing-coverage" then
      coverage.register(id, ControlledReportEvidenceV2(context,
        if mode == "wrong-coverage" then "webstore-local/other.tgz" else artefact, rows.size, count))
    val scope = artefact.split("/", 2)
    server.stubFor(post(urlEqualTo("/xray/api/v1/artifact/status"))
      .withRequestBody(equalToJson(Json.stringify(Json.obj("repo" -> scope(0), "path" -> scope(1)))))
      .willReturn(okJson("""{"overall":{"status":"DONE"},"details":{"sca":{"status":"DONE"}}}""")))
    val document = Json.stringify(Json.obj("generatedDate" -> generated, "rows" -> rows))
    val bytes = if mode == "malformed-zip" then "not a ZIP".getBytes(UTF_8)
      else zip(if mode == "malformed-json" then "not JSON" else document)
    server.stubFor(get(urlPathEqualTo(s"/xray/api/v1/reports/export/$id")).inScenario(scenario).whenScenarioStateIs("ready")
      .willReturn(aResponse().withHeader("Content-Type", "application/zip").withBody(bytes)))
    val deletion = delete(urlEqualTo(s"/xray/api/v1/reports/$id")).inScenario(scenario).whenScenarioStateIs("ready")
      .willReturn(aResponse().withStatus(if mode == "cleanup-failed" then 503 else 204))
    server.stubFor(if mode == "cleanup-failed" then deletion else deletion.willSetStateTo("deleted"))
    server.stubFor(get(urlEqualTo(s"/xray/api/v1/reports/$id")).inScenario(scenario).whenScenarioStateIs("deleted")
      .willReturn(aResponse().withStatus(404)))
    server.stubFor(get(urlPathEqualTo(s"/xray/api/v1/reports/export/$id")).inScenario(scenario).whenScenarioStateIs("deleted")
      .willReturn(aResponse().withStatus(404)))
    id
