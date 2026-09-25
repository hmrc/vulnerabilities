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

package uk.gov.hmrc.vulnerabilities.service.mock

import uk.gov.hmrc.vulnerabilities.model.v2.{KEV, Vulnerability}

class FakeDB {

  private def exampleVulnerability(
    vulnId: String,
    summary: String,
    kev: KEV,
    epss: Option[Double],
    epssPercentile: Option[Double]
  ): Vulnerability =
    Vulnerability(
      vulnId = vulnId,
      summary = summary,
      kev = kev,
      epssProbability = epss,
      epssPercentile = epss,
      references = List.empty,
      cvssScore = None,
      vulnComponent = "some-component",
      fixedVersion = None,
      guidance = List("some-guidance")
      )

  val exampleRows: Map[String, Vulnerability] = {
    val vulnList = List(
      exampleVulnerability("CVE-2024-0001", s"Example summary for ${"CVE-2024-0001"}", KEV.NOT_INCLUDED, Some(0.23), Some(0.45)),
      exampleVulnerability("CVE-2024-0002", s"Example summary for ${"CVE-2024-0002"}", KEV.NOT_INCLUDED, Some(0.45), Some(0.60)),
      exampleVulnerability("CVE-2024-0003", s"Example summary for ${"CVE-2024-0003"}", KEV.NOT_INCLUDED, Some(0.84), Some(0.95)),
      exampleVulnerability("CVE-2024-0004", s"Example summary for ${"CVE-2024-0004"}", KEV.NOT_INCLUDED, Some(0.79), Some(0.02)),
      exampleVulnerability("CVE-2024-0005", s"Example summary for ${"CVE-2024-0005"}", KEV.NOT_INCLUDED, Some(0.66), Some(0.80))
    )

    vulnList.map(v => v.vulnId -> v).toMap
  }


}
