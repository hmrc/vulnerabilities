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

package uk.gov.hmrc.vulnerabilities.v2.service

import java.time.Instant
import org.scalatest.EitherValues
import org.scalatest.concurrent.{ScalaFutures, IntegrationPatience}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.libs.json.Json
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.v2.model.deployment.*
import uk.gov.hmrc.vulnerabilities.v2.model.ingestion.*
import uk.gov.hmrc.vulnerabilities.v2.model.ingestion.IngestionFailure.*
import uk.gov.hmrc.vulnerabilities.v2.model.xray.{XrayArtifactStatus, XrayReport}
import uk.gov.hmrc.vulnerabilities.v2.support.*
import scala.util.Using

class IngestionProvidersSpec extends AnyWordSpec with Matchers with EitherValues with ScalaFutures with IntegrationPatience:
  private val context = ScanContext(ServiceName("example-service"), Version("1.8.0"))
  private val path = "webstore-local/example-service/example-service_1.8.0_0.5.2.tgz"
  private val report = Using.resource(getClass.getResourceAsStream("/xray-v2/maven-multiple-cves.json"))(s =>
    Json.parse(s.readAllBytes()).as[XrayReport])
  private val findings = XrayFindingMapper.map(report, context).value
  private val status = XrayArtifactStatus(XrayArtifactStatus.Status("DONE", Some(Instant.parse("2026-10-21T12:00:00Z"))),
    Some(XrayArtifactStatus.Details(Some(XrayArtifactStatus.Status("DONE", None)))))
  private val input = ArtifactCoverageInput(IngestScan("controlled-run", context, path, WorkflowInitialisation.UsePolicy),
    1234, XrayReport.ReportStatus("completed", 1, 1), report, status)

  "Production coverage verifier" should:
    Seq("DONE", "PENDING", "SCANNING", "FAILED", "PARTIAL", "NOT_SUPPORTED", "NOT_SCANNED", "UNKNOWN").foreach: value =>
      s"reject $value without approved freshness and report/revision correlation, including apparent DONE/DONE" in:
        JfrogArtifactCoverageVerifier().verify(input.copy(
          artifactStatus = status.copy(overall = status.overall.copy(status = value)))).left.value shouldBe a[CoverageUnverified]

    "reject missing SCA details and zero-row reports without independent proof" in:
      val verifier = JfrogArtifactCoverageVerifier()
      verifier.verify(input.copy(artifactStatus = status.copy(details = None))).left.value shouldBe a[CoverageUnverified]
      verifier.verify(input.copy(report = XrayReport(None, Seq.empty),
        reportStatus = XrayReport.ReportStatus("completed", 0, 1))).left.value shouldBe a[CoverageUnverified]

  "Controlled test coverage verifier" should:
    "verify one raw row containing two CVEs and a genuinely verified empty report" in:
      val verifier = ControlledArtifactCoverageVerifier()
      verifier.register(1234, ControlledReportEvidence(context, path, 1))
      verifier.verify(input).value shouldBe ScanCompletion(true, true)
      findings.findings should have size 2
      verifier.register(1235, ControlledReportEvidence(context, path, 0))
      verifier.verify(input.copy(reportId = 1235, report = XrayReport(None, Seq.empty),
        reportStatus = XrayReport.ReportStatus("completed", 0, 1))).isRight shouldBe true

    Seq(
      "wrong report ID" -> input.copy(reportId = 999),
      "wrong artefact" -> input.copy(request = input.request.copy(expectedArtefact = "webstore-local/other.tgz")),
      "wrong application" -> input.copy(request = input.request.copy(context = context.copy(appVersion = Version("other")))),
      "pending report" -> input.copy(reportStatus = XrayReport.ReportStatus("pending", 1, 1)),
      "failed report" -> input.copy(reportStatus = XrayReport.ReportStatus("failed", 1, 1)),
      "zero artefacts" -> input.copy(reportStatus = XrayReport.ReportStatus("completed", 1, 0)),
      "wrong raw count" -> input.copy(reportStatus = XrayReport.ReportStatus("completed", 2, 1)),
      "missing SCA" -> input.copy(artifactStatus = status.copy(details = None)),
      "wrong export path" -> input.copy(report = report.copy(rows = report.rows.map(_.copy(path = "other"))))
    ).foreach { (name, invalid) =>
      s"reject $name rather than dropping uncertain findings" in:
        val verifier = ControlledArtifactCoverageVerifier()
        verifier.register(1234, ControlledReportEvidence(context, path, 1))
        verifier.verify(invalid).left.value shouldBe a[CoverageRejected]
    }

  "Workflow policy boundary" should:
    "return typed production unavailability without inventing values" in:
      val ctx = InitialWorkflowContext(context, findings.findings.head, Instant.parse("2026-10-21T12:00:00Z"))
      UnavailableInitialWorkflowPolicy().initialValues(ctx).left.value shouldBe
        ScanPublicationError.WorkflowPolicyUnavailable("CVE-2026-0001")
      val temporary = TemporaryInitialWorkflowPolicy()
      temporary.initialValues(ctx).value shouldBe
        InitialWorkflowValues(Priority.monitor, OccurrenceState.actionable,
          DeploymentSla(None, breached = false, nearBreach = false), synthetic = true)
      temporary.initialValues(ctx) shouldBe temporary.initialValues(ctx)

  "Dependency evidence boundary" should:
    "distinguish unavailable source from explicit known empty and known nonempty fixture values" in:
      UnavailableDependencyEvidenceService().importedBy(findings).futureValue.left.value shouldBe a[DependencyEvidenceUnavailable]
      val fixture = FixtureDependencyEvidenceService()
      fixture.importedBy(findings).futureValue.left.value shouldBe a[DependencyEvidenceUnavailable]
      fixture.values += "CVE-2026-0002" -> Seq(ImportedDependency("parent", "library", "1"))
      val actual = fixture.importedBy(findings).futureValue.value
      actual("CVE-2026-0001") shouldBe empty
      actual("CVE-2026-0002") should have size 1

    "require no invented evidence for zero findings" in:
      UnavailableDependencyEvidenceService().importedBy(findings.copy(findings = Seq.empty)).futureValue.value shouldBe Map.empty
