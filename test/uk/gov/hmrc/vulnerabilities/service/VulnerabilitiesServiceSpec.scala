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

package uk.gov.hmrc.vulnerabilities.service

import org.mockito.MockitoSugar.mock
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import uk.gov.hmrc.vulnerabilities.data.UnrefinedVulnerabilitySummariesData
import uk.gov.hmrc.vulnerabilities.model.CurationStatus.{ActionRequired, NoActionRequired, Uncurated}
import uk.gov.hmrc.vulnerabilities.model.{CurationStatus, Deployment, DistinctVulnerability, ServiceVersionDeployments, VulnerabilityOccurrence, VulnerabilitySummary, VulnerableComponent, WhatsRunningWhere}
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitySummariesRepository
import uk.gov.hmrc.vulnerabilities.utils.Assessment

import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global

class VulnerabilitiesServiceSpec extends AnyWordSpec with Matchers {

  "vulnerabilitiesService" when {
    "converting to vulnerability summary" should {
      //Note: No need to test for edge case of UnrefinedVulnerabilitySummary not being in the list of SVDs, as
      //the only reports that get downloaded from XRAY are those that are in the svd list to start with.

      "Transform each unrefinedVulnerabilitySummary into a VulnerabilitySummary, using the data from releasesAPI and T&R" in new Setup {
        val result = vulnerabilitiesService.convertToVulnerabilitySummary(Seq(unrefined1, unrefined2), reposWithTeams, svds)
        val expectedResult = Seq(vuln1, vuln2)

        result.length shouldBe 2
        result shouldBe expectedResult

      }

      "Set teams to an empty Seq() if the service does not exist in reposWithTeams" in new Setup {
        val res = vulnerabilitiesService.convertToVulnerabilitySummary(Seq(unrefined3), reposWithTeams, svds)
        val expectedResult = Seq(vuln3)

        res.length shouldBe 1
        res shouldBe expectedResult
      }
    }

    "addingInvestigationsToSummaries" should {
      "Add expected curationStatus, Assessment and Ticket" in new Setup {
        val res = vulnerabilitiesService.addInvestigationsToSummaries(Seq(vuln1, vuln2), investigations)

        res.length shouldBe 2

        res.head.distinctVulnerability.curationStatus shouldBe Some(ActionRequired)
        res.head.distinctVulnerability.id shouldBe "CVE-2021-99999"
        res.head.distinctVulnerability.assessment shouldBe Some("Should fix")
        res.head.distinctVulnerability.ticket shouldBe Some("Ticket1")

        res.last.distinctVulnerability.curationStatus shouldBe Some(NoActionRequired)
        res.last.distinctVulnerability.id shouldBe "CVE-2022-12345"
        res.last.distinctVulnerability.assessment shouldBe Some("Don't fix")
        res.last.distinctVulnerability.ticket shouldBe Some("Ticket2")

      }

      "Default curationStatus to Uncurated if the id does not exist in the Assessments collections" in new Setup {
        val res = vulnerabilitiesService.addInvestigationsToSummaries(Seq(vuln3), investigations)

        res.length shouldBe 1

        res.head.distinctVulnerability.curationStatus shouldBe Some(Uncurated)
        res.head.distinctVulnerability.id shouldBe "XRAY-000004"
        res.head.distinctVulnerability.assessment shouldBe None
        res.head.distinctVulnerability.ticket shouldBe None
      }
    }


  }
  trait Setup {

    val unrefined1 = UnrefinedVulnerabilitySummariesData.unrefined1
    val unrefined2 = UnrefinedVulnerabilitySummariesData.unrefined2
    val unrefined3 = UnrefinedVulnerabilitySummariesData.unrefined3

    val reposWithTeams: Map[String, Seq[String]] = Map(
      "service3" -> Seq("Team1", "TeamA"),
      "service1" -> Seq("Team4", "TeamF"),
      "service2" -> Seq("TeamB")
    )

    val svds: Seq[ServiceVersionDeployments] = Seq(
      ServiceVersionDeployments(serviceName = "service1", version = "1.0.4", environments = Seq("qa", "production")),
      ServiceVersionDeployments(serviceName = "service2", version = "2.0.4", environments = Seq("qa")),
      ServiceVersionDeployments(serviceName = "service3", version = "3.0.4", environments = Seq("qa", "staging", "production")),
      ServiceVersionDeployments(serviceName = "service4", version = "4.0.4", environments = Seq("staging", "production"))
    )

    val investigations: Map[String, Assessment] = Map(
      "CVE-2021-99999" -> Assessment(id = "CVE-2021-99999", assessment = "Should fix", curationStatus = ActionRequired, lastReviewed = UnrefinedVulnerabilitySummariesData.now, ticket = "Ticket1"),
      "CVE-2022-12345" -> Assessment(id = "CVE-2022-12345", assessment = "Don't fix", curationStatus = NoActionRequired, lastReviewed = UnrefinedVulnerabilitySummariesData.now, ticket = "Ticket2")
    )

    val vulnerabilitySummariesRepository: VulnerabilitySummariesRepository = mock[VulnerabilitySummariesRepository]
    val vulnerabilitiesService = new VulnerabilitiesService(vulnerabilitySummariesRepository)

    val vuln1 = VulnerabilitySummary(
      DistinctVulnerability(
        vulnerableComponentName = "gav://com.testxml.test.core:test-bind",
        vulnerableComponentVersion = "1.6.8",
        vulnerableComponents = Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind", "1.6.8")),
        id = "CVE-2021-99999",
        score = Some(7.0),
        description = "This is an exploit",
        fixedVersions = Some(Seq("1.6.9")),
        references = Seq("foo.com", "bar.net"),
        publishedDate = UnrefinedVulnerabilitySummariesData.now.minus(14, ChronoUnit.DAYS),
        assessment = None,
        curationStatus = None,
        ticket = None
      ),
      occurrences = Seq(
        VulnerabilityOccurrence(service = "service3", serviceVersion = "3.0.4", componentPathInSlug = "service3-3.0.4/some/physical/path",
          teams = Seq("Team1", "TeamA"), envs = Seq("qa", "staging", "production"), vulnerableComponentName = "gav://com.testxml.test.core:test-bind", vulnerableComponentVersion = "1.6.8"
        )
      ),
      teams = Seq("Team1", "TeamA"),
      generatedDate = Some(UnrefinedVulnerabilitySummariesData.now)
      )

    val vuln2 = VulnerabilitySummary(
      DistinctVulnerability(
        vulnerableComponentName = "gav://com.testxml.test.core:test-bind",
        vulnerableComponentVersion = "1.5.9",
        vulnerableComponents = Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind", "1.5.9")),
        id = "CVE-2022-12345",
        score = Some(8.0),
        description = "This is an exploit",
        fixedVersions = Some(Seq("1.6.0")),
        references = Seq("foo.com", "bar.net"),
        publishedDate = UnrefinedVulnerabilitySummariesData.now.minus(14, ChronoUnit.DAYS),
        assessment = None,
        curationStatus = None,
        ticket = None
      ),
      occurrences = Seq(
        VulnerabilityOccurrence(service = "service1", serviceVersion = "1.0.4", componentPathInSlug = "service1-1.0.4/some/physical/path",
          teams = Seq("Team4", "TeamF"), envs = Seq("qa", "production"), vulnerableComponentName = "gav://com.testxml.test.core:test-bind", vulnerableComponentVersion = "1.5.9"
        ),
        VulnerabilityOccurrence(service = "service3", serviceVersion = "3.0.4", componentPathInSlug = "service3-3.0.4/some/physical/path",
          teams = Seq("Team1", "TeamA"), envs = Seq("qa", "staging", "production"), vulnerableComponentName = "gav://com.testxml.test.core:test-bind", vulnerableComponentVersion = "1.5.9"
        )
      ),
      teams = Seq("Team1", "Team4", "TeamA", "TeamF"),
      generatedDate = Some(UnrefinedVulnerabilitySummariesData.now)
    )

    val vuln3 = VulnerabilitySummary(
      DistinctVulnerability(
        vulnerableComponentName = "gav://com.testxml.test.core:test-bind",
        vulnerableComponentVersion = "1.8.0",
        vulnerableComponents = Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind", "1.8.0")),
        id = "XRAY-000004",
        score = None,
        description = "This is an exploit",
        fixedVersions = Some(Seq("1.8.1")),
        references = Seq("foo.com", "bar.net"),
        publishedDate = UnrefinedVulnerabilitySummariesData.now.minus(14, ChronoUnit.DAYS),
        assessment = None,
        curationStatus = None,
        ticket = None
      ),
      occurrences = Seq(
        VulnerabilityOccurrence(service = "service4", serviceVersion = "4.0.4", componentPathInSlug = "service4-4.0.4/some/physical/path",
          teams = Seq.empty, envs = Seq("staging", "production"), vulnerableComponentName = "gav://com.testxml.test.core:test-bind", vulnerableComponentVersion = "1.8.0"
        ),
      ),
      teams = Seq.empty,
      generatedDate = Some(UnrefinedVulnerabilitySummariesData.now)
    )

  }
}
