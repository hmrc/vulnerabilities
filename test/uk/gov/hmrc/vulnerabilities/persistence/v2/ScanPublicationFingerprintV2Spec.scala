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

package uk.gov.hmrc.vulnerabilities.persistence.v2

import org.scalatest.EitherValues
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.libs.json.Json
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.*
import uk.gov.hmrc.vulnerabilities.model.v2.xray.XrayReport
import uk.gov.hmrc.vulnerabilities.service.v2.XrayFindingMapperV2
import uk.gov.hmrc.vulnerabilities.support.HistoricalPublicationV1
import scala.collection.immutable.ListMap
import scala.util.Using

class ScanPublicationFingerprintV2Spec extends AnyWordSpec with Matchers with EitherValues:
  private val report = Using.resource(getClass.getResourceAsStream("/xray-v2/maven-multiple-cves.json"))(s =>
    Json.parse(s.readAllBytes()).as[XrayReport])
  private val findings = XrayFindingMapperV2.map(report, ScanContextV2(ServiceName("example-service"), Version("1.8.0"))).value
  private val input = PublishScanV2("historical-format-regression", findings, ScanCompletionV2(true, true),
    ListMap("CVE-2026-0001" -> Seq.empty, "CVE-2026-0002" -> Seq(ImportedDependencyV2("parent", "library", "1"))),
    WorkflowInitialisationV2.UsePolicy)

  "Publication fingerprint codecs" should:
    "match the frozen previous implementation, without enabling its old creation option" in:
      val original = HistoricalPublicationV1.fingerprint(input)
      original shouldBe "23dc615031227d59cdd30a7e59c50bbd3c1aaf2b23714e17cbb835a53dcbb407"
      ScanPublicationFingerprintV2.legacy(input) shouldBe original

    "be deterministic across finding order, map iteration and repeated calls" in:
      val reordered = input.copy(findings = findings.copy(findings = findings.findings.reverse),
        importedBy = ListMap.from(input.importedBy.toSeq.reverse))
      ScanPublicationFingerprintV2.current(reordered) shouldBe ScanPublicationFingerprintV2.current(input)
      ScanPublicationFingerprintV2.current(input) shouldBe ScanPublicationFingerprintV2.current(input)
      ScanPublicationFingerprintV2.legacy(reordered) shouldBe HistoricalPublicationV1.fingerprint(input)

    "distinguish explicit empty, omitted dependency evidence and initialisation intent" in:
      val digest = ScanPublicationFingerprintV2.current(input)
      ScanPublicationFingerprintV2.current(input.copy(importedBy = Map.empty)) should not be digest
      ScanPublicationFingerprintV2.current(input.copy(workflowInitialisation = WorkflowInitialisationV2.ExistingOnly)) should not be digest
      ScanPublicationFingerprintV2.current(input.copy(findings = findings.copy(
        findings = findings.findings.map(_.copy(summary = "Changed"))))) should not be digest

    "use a different explicitly versioned format for new publications" in:
      ScanPublicationFingerprintV2.currentVersion shouldBe 2
      ScanPublicationFingerprintV2.current(input) should fullyMatch regex "[0-9a-f]{64}"
      ScanPublicationFingerprintV2.current(input) should not be ScanPublicationFingerprintV2.legacy(input)
