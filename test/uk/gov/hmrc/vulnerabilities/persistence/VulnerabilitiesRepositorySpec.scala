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

package uk.gov.hmrc.vulnerabilities.persistence

import org.scalatest.concurrent.IntegrationPatience
import org.scalatest.matchers.must.Matchers
import org.scalatest.wordspec.AnyWordSpecLike
import uk.gov.hmrc.mongo.test.{CleanMongoCollectionSupport, PlayMongoRepositorySupport}
import uk.gov.hmrc.vulnerabilities.model.{DistinctVulnerability, Vulnerability, VulnerabilityOccurrence, VulnerabilitySummary}

import java.time.Instant
import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global

class VulnerabilitiesRepositorySpec
  extends AnyWordSpecLike
    with Matchers
    with PlayMongoRepositorySupport[Vulnerability]
    with CleanMongoCollectionSupport
    with IntegrationPatience {

  override protected def repository = new VulnerabilitiesRepository(mongoComponent)

  private val now = Instant.now().truncatedTo(ChronoUnit.MILLIS)

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
      requiresAction = Some(false),
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

  private val vulnerability3RepeatedService =
    Vulnerability(
      service = "service3",
      serviceVersion = "3.1",
      vulnerableComponentName = "component3",
      vulnerableComponentVersion = "3.0",
      componentPathInSlug = "x",
      id = "XRAY-TEST-1",
      score = None,
      description = "desc3",
      requiresAction = Some(true),
      assessment = Some(""),
      lastReviewed = Some(now),
      teams = Some(Seq("team1")),
      references = Seq("test", "test"),
      publishedDate = now,
      scannedDate = now
    )

  private val vulnerability3NoTeams =
    Vulnerability(
      service = "service98",
      serviceVersion = "3",
      vulnerableComponentName = "component3",
      vulnerableComponentVersion = "3.0",
      componentPathInSlug = "x",
      id = "XRAY-TEST-1",
      score = None,
      description = "desc3",
      requiresAction = Some(false),
      assessment = Some(""),
      lastReviewed = Some(now),
      teams = None,
      references = Seq("test", "test"),
      publishedDate = now,
      scannedDate = now
    )

  "search" must {

    "find all vulnerabilities" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search().futureValue
      results must contain allOf(vulnerability1, vulnerability2, vulnerability3)
    }

    "find all vulnerabilities by team name" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search(team = Some("team2")).futureValue
      results must contain only (vulnerability1, vulnerability2)
    }

    "find all vulnerabilities for a service" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search(service = Some("service1")).futureValue
      results must contain only (vulnerability1)
    }

    "find all vulnerabilities by id" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search(id = Some("CVE-TEST-1")).futureValue
      results must contain only (vulnerability1)
    }

    "find all vulnerabilities by description" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search(description = Some("desc")).futureValue
      results must contain allOf(vulnerability1, vulnerability2, vulnerability3)
    }
  }

  "distinctVulnerabilitySummary" must {

    val expectedDistinctVulnerabilities = Seq(
      DistinctVulnerability(
        vulnerableComponentName = "component1", vulnerableComponentVersion = "1.0", id = "CVE-TEST-1",
        score = Some(1.0), description = "desc1", references = Seq("test", "test"), publishedDate = now
      ),
      DistinctVulnerability(
        vulnerableComponentName = "component2", vulnerableComponentVersion = "2.0", id = "CVE-TEST-2",
        score = Some(2.0), description = "desc2", references = Seq("test", "test"), publishedDate = now
      ),
      DistinctVulnerability(
        vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0", id = "XRAY-TEST-1",
        score = None, description = "desc3", references = Seq("test", "test"), publishedDate = now
      )
    )

    val expectedOccurrences = Seq(
      VulnerabilityOccurrence(service = "service1", serviceVersion = "1", assessment = Some(""), requiresAction = Some(true)),
      VulnerabilityOccurrence(service = "service2", serviceVersion = "2", assessment = Some(""), requiresAction = Some(false)),
      VulnerabilityOccurrence(service = "service3", serviceVersion = "3", assessment = Some(""), requiresAction = Some(false)),
      VulnerabilityOccurrence(service = "service3", serviceVersion = "3.1", assessment = Some(""), requiresAction = Some(true)),
      VulnerabilityOccurrence(service = "service98", serviceVersion = "3", assessment = Some(""), requiresAction = Some(false))
    )

    "find all distinct CVEs, with a count of distinct services & a list of distinct teams" in {

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(0)), Seq("team1", "team2"))
      val expected2 = VulnerabilitySummary(expectedDistinctVulnerabilities(1), Seq(expectedOccurrences(1)), Seq("team1", "team2"))
      val expected3 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(2), expectedOccurrences(3), expectedOccurrences(4)), Seq("team1"))

      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3, vulnerability3NoTeams, vulnerability3RepeatedService)).toFuture().futureValue
      val results = repository.distinctVulnerabilitiesSummary(None, None, None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length mustBe 3
      resultsSorted must contain theSameElementsAs Seq(expected1, expected2, expected3)
    }

    "filter by id" in {

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(2), expectedOccurrences(3), expectedOccurrences(4)), Seq("team1"))

      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3, vulnerability3NoTeams, vulnerability3RepeatedService)).toFuture().futureValue
      val results = repository.distinctVulnerabilitiesSummary(id = Some("XRAY"), None, None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length mustBe 1
      resultsSorted mustBe Seq(expected1)
    }

    "filter by requiresAction" in {
      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(0)), Seq("team1", "team2"))
      val expected2 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(3)), Seq("team1"))

      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3, vulnerability3NoTeams, vulnerability3RepeatedService)).toFuture().futureValue
      val results = repository.distinctVulnerabilitiesSummary(None, requiresAction = Some(true), None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length mustBe 2
      resultsSorted must contain theSameElementsAs Seq(expected1, expected2)
    }

    "filter by service name" in {
      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(0)), Seq("team1", "team2"))

      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3, vulnerability3NoTeams, vulnerability3RepeatedService)).toFuture().futureValue
      val results = repository.distinctVulnerabilitiesSummary(None, None, service = Some("ice1"), None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length mustBe 1
      resultsSorted must contain theSameElementsAs Seq(expected1)
    }

    "filter by team" in {
      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(0)), Seq("team1", "team2"))
      val expected2 = VulnerabilitySummary(expectedDistinctVulnerabilities(1), Seq(expectedOccurrences(1)), Seq("team1", "team2"))

      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3, vulnerability3NoTeams, vulnerability3RepeatedService)).toFuture().futureValue
      val results = repository.distinctVulnerabilitiesSummary(None, None, None, team = Some("team2")).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length mustBe 2
      resultsSorted must contain theSameElementsAs Seq(expected1, expected2)
    }

    "filter by all four parameters" in {
      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(2)), Seq("team1"))

      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3, vulnerability3NoTeams, vulnerability3RepeatedService)).toFuture().futureValue
      val results1 = repository.distinctVulnerabilitiesSummary(id = Some("XRAY"), requiresAction = Some(false), service = Some("3"), team = Some("team2")).futureValue
      val results2 = repository.distinctVulnerabilitiesSummary(id = Some("XRAY"), requiresAction = Some(false), service = Some("3"), team = Some("team1")).futureValue

      val results1Sorted = results1.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))
      val results2Sorted = results2.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      results1.length mustBe 0
      results2.length mustBe 1
      results2 must contain theSameElementsAs Seq(expected1)

    }
  }
}
