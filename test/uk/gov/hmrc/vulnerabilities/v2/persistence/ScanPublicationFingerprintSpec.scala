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

package uk.gov.hmrc.vulnerabilities.v2.persistence

import org.scalatest.EitherValues
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.libs.json.Json
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.v2.model.ingestion.*
import uk.gov.hmrc.vulnerabilities.v2.model.xray.XrayReport
import uk.gov.hmrc.vulnerabilities.v2.service.XrayFindingMapper
import uk.gov.hmrc.vulnerabilities.support.HistoricalPublicationV1
import scala.collection.immutable.ListMap
import scala.util.Using

class ScanPublicationFingerprintSpec extends AnyWordSpec with Matchers with EitherValues:
  private val report = Using.resource(getClass.getResourceAsStream("/xray-v2/maven-multiple-cves.json"))(s =>
    Json.parse(s.readAllBytes()).as[XrayReport])
  private val findings = XrayFindingMapper.map(report, ScanContext(ServiceName("example-service"), Version("1.8.0"))).value
  private val input = PublishScan("historical-format-regression", findings, ScanCompletion(true, true),
    ListMap("CVE-2026-0001" -> Seq.empty, "CVE-2026-0002" -> Seq(ImportedDependency("parent", "library", "1"))),
    WorkflowInitialisation.UsePolicy)

  "Publication fingerprint codecs" should:
    "match the frozen previous implementation, without enabling its old creation option" in:
      val original = HistoricalPublicationV1.fingerprint(input)
      original shouldBe "23dc615031227d59cdd30a7e59c50bbd3c1aaf2b23714e17cbb835a53dcbb407"
      ScanPublicationFingerprint.legacy(input) shouldBe original

    "be deterministic across finding order, map iteration and repeated calls" in:
      val reordered = input.copy(findings = findings.copy(findings = findings.findings.reverse),
        importedBy = ListMap.from(input.importedBy.toSeq.reverse))
      ScanPublicationFingerprint.current(reordered) shouldBe ScanPublicationFingerprint.current(input)
      ScanPublicationFingerprint.current(input) shouldBe ScanPublicationFingerprint.current(input)
      ScanPublicationFingerprint.legacy(reordered) shouldBe HistoricalPublicationV1.fingerprint(input)

    "distinguish explicit empty, omitted dependency evidence and initialisation intent" in:
      val digest = ScanPublicationFingerprint.current(input)
      ScanPublicationFingerprint.current(input.copy(importedBy = Map.empty)) should not be digest
      ScanPublicationFingerprint.current(input.copy(workflowInitialisation = WorkflowInitialisation.ExistingOnly)) should not be digest
      ScanPublicationFingerprint.current(input.copy(findings = findings.copy(
        findings = findings.findings.map(_.copy(summary = "Changed"))))) should not be digest

    "use a different explicitly versioned format for new publications" in:
      ScanPublicationFingerprint.currentVersion shouldBe 2
      ScanPublicationFingerprint.current(input) should fullyMatch regex "[0-9a-f]{64}"
      ScanPublicationFingerprint.current(input) should not be ScanPublicationFingerprint.legacy(input)

    "detect changes to component-specific imported-by evidence" in: 
      val key = findings.findings.head.observationKey 
      val first = input.copy( 
        importedBy = Map(
          key -> Seq(
            ImportedDependency("parent", "library-a", "1.0")
          )
        )
      )
      val second = first.copy(
        importedBy = Map(
          key -> Seq(
            ImportedDependency("parent", "library-b", "2.0")
          )
        )
      )
      ScanPublicationFingerprint.current(first) should not be 
        ScanPublicationFingerprint.current(second)

