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

package uk.gov.hmrc.vulnerabilities.service.v2

import java.time.Instant
import java.util.zip.ZipInputStream
import org.scalatest.{EitherValues, OptionValues}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.libs.json.Json
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.*
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.XrayFindingMappingErrorV2.*
import uk.gov.hmrc.vulnerabilities.model.v2.xray.XrayReport
import scala.util.Using

class XrayFindingMapperV2Spec extends AnyWordSpec with Matchers with EitherValues with OptionValues:
  private val generated = Instant.parse("2026-09-11T10:00:00Z")
  private val context = ScanContextV2(ServiceName("example-service"), Version("1.8.0"))
  private val cve = XrayReport.CVE(Some("CVE-2026-0001"), Some(8.1), Some("source-vector"))
  private val row = XrayReport.Vulnerability(
    cves = Seq(cve),
    cvss3MaxScore = Some(9.8),
    summary = "Synthetic development finding from the local Xray stub",
    severity = "High",
    severitySource = None,
    vulnerableComponent = "gav://uk.gov.hmrc:example-lib:2.4.0",
    componentPhysicalPath = "lib/example-lib-2.4.0.jar",
    impactedArtefact = "example-service_1.8.0_0.5.2.tgz",
    impactPath = Seq("example-service", "example-lib"),
    path = "webstore-local/example-service/example-service_1.8.0_0.5.2.tgz",
    fixedVersions = Seq("2.4.1"),
    published = Instant.parse("2026-09-01T10:00:00Z"),
    artefactScanTime = generated,
    issueId = "XRAY-EXAMPLE-0001",
    packageType = "maven",
    provider = Some("synthetic-provider"),
    description = Some("Scanner description, not platform guidance"),
    references = Seq("https://example.invalid/advisory"),
    projectKeys = Seq("not-an-hmrc-team")
  )

  private def map(rows: XrayReport.Vulnerability*) =
    XrayFindingMapperV2.map(XrayReport(Some(generated), rows.toSeq), context)

  private def conflict(rows: XrayReport.Vulnerability*): ConflictingFindings =
    map(rows*).left.value match
      case Seq(error: ConflictingFindings) => error
      case errors => fail(s"Expected one typed conflict, got $errors")

  private def zipFixture(): XrayReport =
    Using.resource(ZipInputStream(getClass.getResourceAsStream("/xray_report_v1_x-no_descriptions.zip"))): zip =>
      zip.getNextEntry should not be null
      Json.parse(zip.readAllBytes()).as[XrayReport]

  "XrayFindingMapperV2" should:
    "map one CVE with separate application, installed dependency and fixed dependency versions" in:
      val result = map(row).value
      result.context shouldBe context
      result.generatedDate shouldBe Some(generated)
      result.findings should have size 1
      val finding = result.findings.head
      finding.vulnerabilityId shouldBe "CVE-2026-0001"
      finding.summary shouldBe row.summary
      finding.cvss shouldBe Some(8.1)
      finding.component shouldBe MavenComponentV2("uk.gov.hmrc", "example-lib", "2.4.0")
      finding.component.identity shouldBe "gav://uk.gov.hmrc:example-lib"
      finding.fixedVersions shouldBe Seq("2.4.1")
      finding.references shouldBe row.references
      finding.sources shouldBe Seq(XrayFindingSourceV2(
        row.issueId, cve.cveV3Vector, row.cvss3MaxScore, row.severity, row.severitySource,
        row.componentPhysicalPath, row.impactedArtefact, row.impactPath, row.path,
        row.published, row.artefactScanTime, row.provider, row.description, row.projectKeys
      ))

    "preserve Scala artefact suffixes and installed-version text exactly" in:
      val finding = map(row.copy(vulnerableComponent = "gav://uk.gov.hmrc:example-lib_2.13:2.4.0-RC1+build.7")).value.findings.head
      finding.component.identity shouldBe "gav://uk.gov.hmrc:example-lib_2.13"
      finding.component.installedVersion shouldBe "2.4.0-RC1+build.7"

    "accept Maven package types case-insensitively" in:
      Seq("maven", "Maven", "MAVEN", "mAvEn").foreach: packageType =>
        map(row.copy(packageType = packageType)).value.findings.head.component shouldBe
          MavenComponentV2("uk.gov.hmrc", "example-lib", "2.4.0")

    "retain fixed-version strings and ranges without interpretation" in:
      val fixes = Seq("[2.4.1,3.0)", "(,1.3.16]", " 2.4.1 ", "2.4.1", "2.4.1")
      map(row.copy(fixedVersions = fixes)).value.findings.head.fixedVersions shouldBe fixes

    "accept empty fix evidence without inventing workflow state" in:
      map(row.copy(fixedVersions = Seq.empty)).value.findings.head.fixedVersions shouldBe empty

    "keep fixed versions associated with the right CVE and component" in:
      val second = row.copy(cves = Seq(cve.copy(cveId = Some("CVE-2026-0002"))),
        vulnerableComponent = "gav://other.group:other-lib:3.1", fixedVersions = Seq("3.2"))
      val findings = map(row, second).value.findings
      findings.map(f => (f.vulnerabilityId, f.component.identity, f.fixedVersions)) shouldBe Seq(
        ("CVE-2026-0001", "gav://uk.gov.hmrc:example-lib", Seq("2.4.1")),
        ("CVE-2026-0002", "gav://other.group:other-lib", Seq("3.2"))
      )

    "preserve absent CVSS instead of using zero or the row maximum" in:
      val finding = map(row.copy(cves = Seq(cve.copy(cveV3Score = None)))).value.findings.head
      finding.cvss shouldBe None
      finding.sources.head.rowMaxCvss shouldBe Some(9.8)

    "expand multiple CVEs in row order with each CVE's own score and vector" in:
      val second = XrayReport.CVE(Some("CVE-2026-0002"), Some(6.5), Some("second-vector"))
      val third = XrayReport.CVE(Some("CVE-2026-0003"), None, None)
      val findings = map(row.copy(cves = Seq(cve, second, third))).value.findings
      findings.map(_.vulnerabilityId) shouldBe Seq("CVE-2026-0001", "CVE-2026-0002", "CVE-2026-0003")
      findings.map(_.cvss) shouldBe Seq(Some(8.1), Some(6.5), None)
      findings.map(_.sources.head.cvssVector) shouldBe Seq(Some("source-vector"), Some("second-vector"), None)
      findings.foreach: finding =>
        finding.component.identity shouldBe "gav://uk.gov.hmrc:example-lib"
        finding.fixedVersions shouldBe row.fixedVersions
        finding.summary shouldBe row.summary
        finding.sources.head.issueId shouldBe row.issueId

    "reject an empty CVE list rather than adopting the Xray issue identifier" in:
      map(row.copy(cves = Seq.empty)).left.value shouldBe Seq(UnsupportedCve(1, row.issueId, None, None))

    Seq(None, Some(""), Some(" "), Some("XRAY-1234"), Some("CVE-1234"), Some("cve-2026-0001"),
      Some(" CVE-2026-0001"), Some("CVE-2026-001"), Some("CVE-2026-0001\n")).foreach { id =>
      s"reject unsupported CVE identifier $id" in:
        map(row.copy(cves = Seq(cve.copy(cveId = id)))).left.value shouldBe
          Seq(UnsupportedCve(1, row.issueId, Some(1), id))
    }

    "reject a row containing a valid CVE alongside an unusable CVE" in:
      map(row.copy(cves = Seq(cve, cve.copy(cveId = None)))).left.value shouldBe
        Seq(UnsupportedCve(1, row.issueId, Some(2), None))

    "collapse identical repeated rows without duplicate findings or source evidence" in:
      map(row, row).value shouldBe map(row).value

    "collapse a repeated identical CVE within one row" in:
      map(row.copy(cves = Seq(cve, cve))).value shouldBe map(row).value

    "retain distinct issue, path and reference evidence when combining representable findings" in:
      val second = row.copy(issueId = "XRAY-EXAMPLE-0002", componentPhysicalPath = "another/lib.jar",
        impactPath = Seq("example-service", "another-importer", "example-lib"),
        references = Seq("https://example.invalid/second-advisory", row.references.head))
      val result = map(row, second).value
      result.findings should have size 1
      result.findings.head.sources.map(_.issueId) shouldBe Seq(row.issueId, second.issueId)
      result.findings.head.sources.map(_.componentPhysicalPath) shouldBe Seq(row.componentPhysicalPath, second.componentPhysicalPath)
      result.findings.head.sources.map(_.impactPath) shouldBe Seq(row.impactPath, second.impactPath)
      result.findings.head.references shouldBe Seq(row.references.head, second.references.head)

    "reject one CVE affecting two different components, even with identical fixes" in:
      val second = row.copy(vulnerableComponent = "gav://other.group:other-lib:2.4.0")
      val error = conflict(row, second)
      error.vulnerabilityId shouldBe cve.cveId.value
      error.rows shouldBe Seq(1, 2)
      error.fields shouldBe Seq(ConflictingFindingFieldV2.component)
      error.evidence.map(_.component.identity) shouldBe Seq("gav://uk.gov.hmrc:example-lib", "gav://other.group:other-lib")

    "report distinct component and fix information rather than selecting a component" in:
      val error = conflict(row, row.copy(vulnerableComponent = "gav://other.group:other-lib:2.4.0", fixedVersions = Seq("3.2")))
      error.fields shouldBe Seq(ConflictingFindingFieldV2.component, ConflictingFindingFieldV2.fixedVersions)
      error.evidence.map(_.fixedVersions) shouldBe Seq(Seq("2.4.1"), Seq("3.2"))

    "reject two installed versions of one CVE/component within a deployment" in:
      conflict(row, row.copy(vulnerableComponent = "gav://uk.gov.hmrc:example-lib:2.3.0")).fields shouldBe
        Seq(ConflictingFindingFieldV2.installedVersion)

    "reject conflicting fix evidence for the same CVE/component" in:
      conflict(row, row.copy(fixedVersions = Seq("2.5.0"))).fields shouldBe Seq(ConflictingFindingFieldV2.fixedVersions)
      conflict(row, row.copy(fixedVersions = Seq.empty)).fields shouldBe Seq(ConflictingFindingFieldV2.fixedVersions)

    "ignore fix order for conflict detection while preserving source strings and first-seen order" in:
      val fixes = Seq("2.4.1", "[3.2,4.0)")
      map(row.copy(fixedVersions = fixes), row.copy(fixedVersions = fixes.reverse))
        .value.findings.head.fixedVersions shouldBe fixes

    "reject conflicting summaries without choosing an authoritative one" in:
      conflict(row, row.copy(summary = "Different scanner summary")).fields shouldBe Seq(ConflictingFindingFieldV2.summary)

    "reject conflicting per-CVE scores including absent versus supplied scores" in:
      Seq(Some(6.5), None).foreach: score =>
        conflict(row, row.copy(cves = Seq(cve.copy(cveV3Score = score)))).fields shouldBe
          Seq(ConflictingFindingFieldV2.cvss)

    "reject conflicting scores for a repeated CVE within one row" in:
      conflict(row.copy(cves = Seq(cve, cve.copy(cveV3Score = Some(6.5))))).rows shouldBe Seq(1)

    "map a structurally valid report with zero rows to an empty finding set" in:
      map().value shouldBe ScannerFindingsV2(context, Some(generated), Seq.empty)

    "preserve an absent generation timestamp for populated and empty reports" in:
      XrayFindingMapperV2.map(XrayReport(None, Seq(row)), context).value.generatedDate shouldBe None
      XrayFindingMapperV2.map(XrayReport(None, Seq.empty), context).value shouldBe
        ScannerFindingsV2(context, None, Seq.empty)

    Seq("npm", "docker", "", " maven ").foreach: packageType =>
      s"reject unsupported package type '$packageType'" in:
        map(row.copy(packageType = packageType)).left.value shouldBe
          Seq(UnsupportedPackageType(1, row.issueId, packageType))

    Seq("pkg:maven/uk.gov.hmrc/example-lib@2.4.0", "npm://example-lib:2.4.0", "GAV://g:a:1", "g:a:1").foreach: coordinates =>
      s"reject unsupported coordinate scheme '$coordinates'" in:
        map(row.copy(vulnerableComponent = coordinates)).left.value shouldBe
          Seq(UnsupportedCoordinateScheme(1, row.issueId, coordinates))

    Seq("gav://", "gav://g:a", "gav://:a:1", "gav://g::1", "gav://g:a:", "gav://g:a:1:extra",
      "gav://g/a:a:1", "gav://g:a/b:1", "gav://g:a:1/extra", "gav://g:a:1?query",
      "gav://g:a:1#fragment", "gav:// g:a:1", "gav://g:a :1", "gav://g:a:1\n",
      "gav://g:\ta:1", "gav://g:a:1\u00a0").foreach { coordinates =>
      s"reject malformed coordinates ${coordinates.toList}" in:
        map(row.copy(vulnerableComponent = coordinates)).left.value shouldBe
          Seq(MalformedComponentCoordinates(1, row.issueId, coordinates))
    }

    Seq(-0.1, 10.1, Double.NaN, Double.PositiveInfinity, Double.NegativeInfinity).foreach: score =>
      s"reject invalid per-CVE CVSS $score" in:
        map(row.copy(cves = Seq(cve.copy(cveV3Score = Some(score))))).left.value match
          case Seq(InvalidCvss(1, row.issueId, Some("CVE-2026-0001"), actual)) =>
            java.lang.Double.compare(actual, score) shouldBe 0
          case errors => fail(s"Expected invalid CVSS, got $errors")

    "accept CVSS boundary values zero and ten without treating zero as absence" in:
      Seq(0.0, 10.0).foreach: score =>
        map(row.copy(cves = Seq(cve.copy(cveV3Score = Some(score))))).value.findings.head.cvss shouldBe Some(score)

    "validate the entire report and return every invalid row instead of partial findings" in:
      val invalidCve = row.copy(cves = Seq(cve.copy(cveId = None)))
      val invalidComponent = row.copy(vulnerableComponent = "gav://broken")
      map(row, invalidCve, invalidComponent).left.value shouldBe Seq(
        UnsupportedCve(2, row.issueId, Some(1), None),
        MalformedComponentCoordinates(3, row.issueId, "gav://broken")
      )

    "detect report-wide conflicts even when another row is invalid" in:
      val errors = map(row, row.copy(cves = Seq.empty),
        row.copy(vulnerableComponent = "gav://other.group:other-lib:2.4.0")).left.value
      errors should have size 2
      errors.head shouldBe UnsupportedCve(2, row.issueId, None, None)
      errors(1) match
        case error: ConflictingFindings => error.rows shouldBe Seq(1, 3)
        case other => fail(s"Expected component conflict, got $other")

    "reject blank explicit context even for an empty report" in:
      val invalid = ScanContextV2(ServiceName(" "), Version(""))
      XrayFindingMapperV2.map(XrayReport(None, Seq.empty), invalid).left.value shouldBe
        Seq(InvalidContext("serviceName", " "), InvalidContext("appVersion", ""))

    "use exact supplied context, not service or application versions inferred from row paths" in:
      val supplied = ScanContextV2(ServiceName("different-service"), Version("development"))
      val result = XrayFindingMapperV2.map(XrayReport(None, Seq(row)), supplied).value
      result.context shouldBe supplied
      result.findings.head.component.installedVersion shouldBe "2.4.0"

    "reject the existing ZIP's Xray-only identifier rather than silently mapping the remainder" in:
      val report = zipFixture()
      report.rows should have size 11
      XrayFindingMapperV2.map(report, context).left.value shouldBe
        Seq(UnsupportedCve(8, "XRAY-947687", Some(1), Some("XRAY-947687")))

    "map the existing ZIP's repeated CVE evidence without losing distinct physical paths" in:
      val report = zipFixture()
      val selected = report.rows.filter(_.issueId == "XRAY-710140")
      selected should have size 2
      val result = XrayFindingMapperV2.map(report.copy(rows = selected), context).value
      result.findings should have size 1
      result.findings.head.vulnerabilityId shouldBe "CVE-2025-48924"
      result.findings.head.fixedVersions shouldBe Seq("3.18.0")
      result.findings.head.sources.map(_.componentPhysicalPath).toSet shouldBe selected.map(_.componentPhysicalPath).toSet
