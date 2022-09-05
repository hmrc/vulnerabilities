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

import org.mockito.MockitoSugar
import org.scalatest.concurrent.ScalaFutures.convertScalaFuture
import org.scalatest.matchers.must.Matchers
import org.scalatest.matchers.should.Matchers.convertToAnyShouldWrapper
import org.scalatest.wordspec.AnyWordSpecLike
import uk.gov.hmrc.vulnerabilities.model.{DistinctVulnerability, Vulnerability, VulnerabilityCountSummary}
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitiesRepository

import java.time.Instant
import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

class VulnerabilitiesServiceSpec
  extends AnyWordSpecLike
    with Matchers
    with MockitoSugar {

  private val now = Instant.now().truncatedTo(ChronoUnit.MILLIS)
  private val vulnerabilitiesRepository = mock[VulnerabilitiesRepository]
  private val vulnerabilitiesService = new VulnerabilitiesService(
    vulnerabilitiesRepository
  )

  private val vulnerability1 =
    Vulnerability(
      service = "service1",
      serviceVersion = "1",
      vulnerableComponentName = "component1",
      vulnerableComponentVersion = "1.0",
      componentPathInSlug = "",
      id = "CVE-TEST-1",
      score = Some(1.0),
      description = "desc1",
      requiresAction = Some(true),
      assessment = Some(""),
      lastReviewed = Some(now),
      teams = Some(Seq("team1", "team2")),
      references = Seq("test", "test"),
      publishedDate = now,
      scannedDate = now
    )

  private val vulnerability1again =
    Vulnerability(
      service = "service4",
      serviceVersion = "1",
      vulnerableComponentName = "component1",
      vulnerableComponentVersion = "1.0",
      componentPathInSlug = "",
      id = "CVE-TEST-1",
      score = Some(1.0),
      description = "desc1",
      requiresAction = Some(true),
      assessment = Some(""),
      lastReviewed = Some(now),
      teams = Some(Seq("team7", "team8", "team1")),
      references = Seq("test", "test"),
      publishedDate = now,
      scannedDate = now
    )

  private val vulnerability2 =
    Vulnerability(
      service = "service2",
      serviceVersion = "2",
      vulnerableComponentName = "component2",
      vulnerableComponentVersion = "2.0",
      componentPathInSlug = "",
      id = "CVE-TEST-2",
      score = Some(2.0),
      description = "desc2",
      requiresAction = Some(true),
      assessment = Some(""),
      lastReviewed = Some(now),
      teams = Some(Seq("team1", "team2")),
      references = Seq("test", "test"),
      publishedDate = now,
      scannedDate = now
    )

  private val vulnerability3 =
    Vulnerability(
      service = "service3",
      serviceVersion = "3",
      vulnerableComponentName = "component3",
      vulnerableComponentVersion = "3.0",
      componentPathInSlug = "",
      id = "XRAY-TEST-1",
      score = None,
      description = "desc3",
      requiresAction = Some(false),
      assessment = Some(""),
      lastReviewed = Some(now),
      teams = Some(Seq("team1")),
      references = Seq("test", "test"),
      publishedDate = now,
      scannedDate = now
    )

  "distinctVulnerabilitiesSummary" must {

    "find all distinct Vulnerabilities, along with the services and teams that are vulnerable" in {
     val res1 = VulnerabilityCountSummary(
            distinctVulnerability = DistinctVulnerability(vulnerableComponentName = "component1", vulnerableComponentVersion = "1.0", id = "CVE-TEST-1", score = Some(1.0), description = "desc1", references = Seq("test", "test"), publishedDate = now, requiresAction = Some(true), assessment =  Some(""), lastReviewed = Some(now)),
            services = Seq("service1", "service4"),
            teams = Seq("team1", "team2", "team7", "team8")
          )
     val res2 =  VulnerabilityCountSummary(
            distinctVulnerability = DistinctVulnerability(vulnerableComponentName = "component2", vulnerableComponentVersion = "2.0", id = "CVE-TEST-2", score = Some(2.0), description = "desc2", references = Seq("test", "test"), publishedDate = now, requiresAction = Some(true), assessment = Some(""), lastReviewed = Some(now)),
            services = Seq("service2"),
            teams = Seq("team1", "team2")
          )
     val res3 = VulnerabilityCountSummary(
            distinctVulnerability = DistinctVulnerability(vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0", id = "XRAY-TEST-1", score = None, description = "desc3", references = Seq("test", "test"), publishedDate = now, requiresAction = Some(false), assessment = Some(""), lastReviewed = Some(now)),
            services = Seq("service3"),
            teams = Seq("team1")
          )
     val expectedResults = Seq(res1, res2, res3)

      when(vulnerabilitiesRepository.search()).thenReturn(Future.successful(
        Seq(vulnerability1, vulnerability1again, vulnerability2, vulnerability3)
      ))

      val results = vulnerabilitiesService.distinctVulnerabilitiesSummary(None, None).futureValue
      results.length shouldBe 3
      results should contain theSameElementsInOrderAs expectedResults
    }

    "find distinct vulnerabilities, filtered by id" in {
      val res1 = VulnerabilityCountSummary(
        distinctVulnerability = DistinctVulnerability(vulnerableComponentName = "component1", vulnerableComponentVersion = "1.0", id = "CVE-TEST-1", score = Some(1.0), description = "desc1", references = Seq("test", "test"), publishedDate = now, requiresAction = Some(true), assessment =  Some(""), lastReviewed = Some(now)),
        services = Seq("service1", "service4"),
        teams = Seq("team1", "team2", "team7", "team8")
      )
      val res2 =  VulnerabilityCountSummary(
        distinctVulnerability = DistinctVulnerability(vulnerableComponentName = "component2", vulnerableComponentVersion = "2.0", id = "CVE-TEST-2", score = Some(2.0), description = "desc2", references = Seq("test", "test"), publishedDate = now, requiresAction = Some(true), assessment = Some(""), lastReviewed = Some(now)),
        services = Seq("service2"),
        teams = Seq("team1", "team2")
      )

      val expectedResults = Seq(res1, res2)
      when(vulnerabilitiesRepository.search(id = Some("cve"))).thenReturn(Future.successful(
        Seq(vulnerability1, vulnerability1again, vulnerability2)
      ))

      val results = vulnerabilitiesService.distinctVulnerabilitiesSummary(vulnerability = Some("cve"), None).futureValue
      results.length shouldBe 2
      results should contain theSameElementsInOrderAs expectedResults
    }

  }
}