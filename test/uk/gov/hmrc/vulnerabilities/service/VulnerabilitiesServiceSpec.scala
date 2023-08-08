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

package uk.gov.hmrc.vulnerabilities.service

import org.mockito.MockitoSugar.mock
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import uk.gov.hmrc.vulnerabilities.data.UnrefinedVulnerabilitySummariesData
import uk.gov.hmrc.vulnerabilities.model.CurationStatus.{ActionRequired, InvestigationOngoing, NoActionRequired, Uncurated}
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitySummariesRepository
import uk.gov.hmrc.vulnerabilities.utils.Assessment

import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global

class VulnerabilitiesServiceSpec extends AnyWordSpec with Matchers {

  "vulnerabilitiesService" when {
    "VulnerabilitiesService.totalCountsPerService" should {
      "sum the number of vulnerabilities for each curation status and return TotalVulnerabilityCount objects" in new Setup {

        val totalVulnerabilityCounts = Seq(
          TotalVulnerabilityCount("service-one", actionRequired = 40, noActionRequired = 20, investigationOngoing = 4, uncurated = 0),
          TotalVulnerabilityCount("service-two", actionRequired = 40, noActionRequired = 20, investigationOngoing = 0, uncurated = 0),
        )

        vulnerabilitiesService.totalCountsPerService(vulnerabilityCounts) shouldBe totalVulnerabilityCounts
      }
    }
  }

  trait Setup {

    val vulnerabilitySummariesRepository: VulnerabilitySummariesRepository = mock[VulnerabilitySummariesRepository]
    val vulnerabilitiesService = new VulnerabilitiesService(vulnerabilitySummariesRepository)

    val vulnerabilityCounts = Seq(
      VulnerabilityCount("service-one", "production",   ActionRequired, 10),
      VulnerabilityCount("service-one", "staging",      ActionRequired, 10),
      VulnerabilityCount("service-one", "qa",           ActionRequired, 10),
      VulnerabilityCount("service-one", "externalTest", ActionRequired, 10),

      VulnerabilityCount("service-two", "production",   ActionRequired, 10),
      VulnerabilityCount("service-two", "staging",      ActionRequired, 10),
      VulnerabilityCount("service-two", "qa",           ActionRequired, 10),
      VulnerabilityCount("service-two", "externalTest", ActionRequired, 10),

      VulnerabilityCount("service-one", "production",   NoActionRequired, 5),
      VulnerabilityCount("service-one", "staging",      NoActionRequired, 5),
      VulnerabilityCount("service-one", "qa",           NoActionRequired, 5),
      VulnerabilityCount("service-one", "externalTest", NoActionRequired, 5),

      VulnerabilityCount("service-two", "production",   NoActionRequired, 5),
      VulnerabilityCount("service-two", "staging",      NoActionRequired, 5),
      VulnerabilityCount("service-two", "qa",           NoActionRequired, 5),
      VulnerabilityCount("service-two", "externalTest", NoActionRequired, 5),

      VulnerabilityCount("service-one", "production",   InvestigationOngoing, 1),
      VulnerabilityCount("service-one", "staging",      InvestigationOngoing, 1),
      VulnerabilityCount("service-one", "qa",           InvestigationOngoing, 1),
      VulnerabilityCount("service-one", "externalTest", InvestigationOngoing, 1),

      VulnerabilityCount("service-two", "production",   InvestigationOngoing, 0),
      VulnerabilityCount("service-two", "staging",      InvestigationOngoing, 0),
      VulnerabilityCount("service-two", "qa",           InvestigationOngoing, 0),
      VulnerabilityCount("service-two", "externalTest", InvestigationOngoing, 0),
    )
  }
}
