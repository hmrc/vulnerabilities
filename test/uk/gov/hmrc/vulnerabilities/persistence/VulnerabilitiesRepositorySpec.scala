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
import uk.gov.hmrc.vulnerabilities.model.{CurationStatus, DistinctVulnerability, VulnerabilityOccurrence, VulnerabilitySummary, VulnerableComponent}

import java.time.Instant
import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global

class VulnerabilitiesRepositorySpec
  extends AnyWordSpecLike
    with Matchers
    with PlayMongoRepositorySupport[VulnerabilitySummary]
    with CleanMongoCollectionSupport
    with IntegrationPatience {

  override protected def repository = new VulnerabilitySummariesRepository(mongoComponent)

  private val now = Instant.now().truncatedTo(ChronoUnit.MILLIS)
  private val oneMinAgo = now.minus(1, ChronoUnit.MINUTES)
  private val fourDaysAgo = now.minus(4, ChronoUnit.DAYS)

  "distinctVulnerabilitySummary" must {

    //Building blocks for VulnerabilitySummary expected results
    val expectedDistinctVulnerabilities = Seq(
      DistinctVulnerability(
        vulnerableComponentName = "component1", vulnerableComponentVersion = "1.0",
        vulnerableComponents = Seq(VulnerableComponent("component1", "1.0"), VulnerableComponent("component1.1", "0.8")), id = "CVE-TEST-1",
        score = Some(1.0), description = "desc1", references = Seq("test", "test"), publishedDate = now, assessment = Some(""),
        curationStatus = Some(CurationStatus.ActionRequired), ticket = Some("BDOG-1"),
        fixedVersions = None
      ),
      DistinctVulnerability(
        vulnerableComponentName = "component2", vulnerableComponentVersion = "2.0",
        vulnerableComponents = Seq(VulnerableComponent("component2", "2.0")), id = "CVE-TEST-2",
        score = Some(1.0), description = "desc2", references = Seq("test", "test"), publishedDate = now, assessment = Some(""),
        curationStatus = Some(CurationStatus.NoActionRequired), ticket = Some("BDOG-2"),
        fixedVersions = Some(Seq("1", "2"))
      ),
      DistinctVulnerability(
        vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0",
        vulnerableComponents = Seq(VulnerableComponent("component3", "3.0")), id = "XRAY-TEST-1",
        score = Some(2.0), description = "desc3", references = Seq("test", "test"), publishedDate = now, assessment = Some(""),
        curationStatus = Some(CurationStatus.ActionRequired), ticket = Some("BDOG-3"),
        fixedVersions = None
      )
    )

    //Building blocks for VulnerabilitySummary expected results
    val expectedOccurrences = Seq(
      VulnerabilityOccurrence(service = "service1"  , serviceVersion = "1"   , componentPathInSlug = "a",        teams = Seq("team1"),          envs = Seq("development"), vulnerableComponentName = "component1", vulnerableComponentVersion = "1.0"),
      VulnerabilityOccurrence(service = "service2"  , serviceVersion = "2"   , componentPathInSlug = "b",        teams = Seq("team1"),          envs = Seq("staging"), vulnerableComponentName = "component2", vulnerableComponentVersion = "2.0"),
      VulnerabilityOccurrence(service = "service3"  , serviceVersion = "3"   , componentPathInSlug = "c",        teams = Seq(),                 envs = Seq("development"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
      VulnerabilityOccurrence(service = "service3"  , serviceVersion = "3.1" , componentPathInSlug = "d",        teams = Seq(),                 envs = Seq("production"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
      VulnerabilityOccurrence(service = "service33" , serviceVersion = "3"   , componentPathInSlug = "e",        teams = Seq("team1"),          envs = Seq("staging", "production"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
      VulnerabilityOccurrence(service = "service6"  , serviceVersion = "2.55", componentPathInSlug = "apache:x", teams = Seq("team2"),          envs = Seq("staging", "production"), vulnerableComponentName = "component1.1", vulnerableComponentVersion = "0.8"),
      VulnerabilityOccurrence(service = "helloWorld", serviceVersion = "2.51", componentPathInSlug = "apache:y", teams = Seq("team1", "team2"), envs = Seq("qa"), vulnerableComponentName = "component2", vulnerableComponentVersion = "2.0")
    )

    "default sort by descending score and ascending id" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(0), expectedOccurrences(5)), Seq("team1", "team2"), oneMinAgo)
      val expected2 = VulnerabilitySummary(expectedDistinctVulnerabilities(1), Seq(expectedOccurrences(6), expectedOccurrences(1)), Seq("team1", "team2"), now)
      val expected3 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(2), expectedOccurrences(3), expectedOccurrences(4)), Seq("team1"), fourDaysAgo)

      val results = repository.distinctVulnerabilitiesSummary(None, None, None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length mustBe 3
      resultsSorted mustBe Seq(expected3, expected1, expected2)
    }

    "filter by id" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue


      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(2), expectedOccurrences(3), expectedOccurrences(4)), Seq("team1"), fourDaysAgo)

      val results = repository.distinctVulnerabilitiesSummary(id = Some("XRAY"), None, None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))


      resultsSorted.length mustBe 1
      resultsSorted mustBe Seq(expected1)
    }

    "filter by curationStatus" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(0), expectedOccurrences(5)), Seq("team1", "team2"), oneMinAgo)
      val expected2 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(2), expectedOccurrences(3), expectedOccurrences(4)), Seq("team1"), fourDaysAgo)

      val results = repository.distinctVulnerabilitiesSummary(None, curationStatus = Some(CurationStatus.ActionRequired.asString), None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length mustBe 2
      resultsSorted must contain theSameElementsAs Seq(expected1, expected2)
    }

    "filter by service name" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(0)), Seq("team1", "team2"), generatedDate = oneMinAgo)

      val results = repository.distinctVulnerabilitiesSummary(None, None, service = Some("ice1"), None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length mustBe 1
      resultsSorted must contain theSameElementsAs Seq(expected1)
    }

    "filter by team" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(5)), Seq("team1", "team2"), oneMinAgo)
      val expected2 = VulnerabilitySummary(expectedDistinctVulnerabilities(1), Seq(expectedOccurrences(6)), Seq("team1", "team2"), now)

      val results = repository.distinctVulnerabilitiesSummary(None, None, None, team = Some("team2")).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length mustBe 2
      resultsSorted mustBe Seq(expected1, expected2)
    }

    "filter by all four parameters" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(4)), Seq("team1"), fourDaysAgo)

      val results1 = repository.distinctVulnerabilitiesSummary(id = Some("XRAY"), curationStatus = Some(CurationStatus.ActionRequired.asString), service = Some("3"), team = Some("team2")).futureValue
      val results2 = repository.distinctVulnerabilitiesSummary(id = Some("XRAY"), curationStatus = Some(CurationStatus.ActionRequired.asString), service = Some("3"), team = Some("team1")).futureValue

      val results1Sorted = results1.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))
      val results2Sorted = results2.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      results1Sorted.length mustBe 0
      results2Sorted.length mustBe 1
      results2Sorted mustBe Seq(expected1)
    }

    "return only unique teams" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val results = repository.distinctVulnerabilitiesSummary(id = Some("XRAY"), None, None, None).futureValue

      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length mustBe 1
      resultsSorted.head.teams.length mustBe 1
    }

    "Do an exact match on service when searchTerm is quoted" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(2), expectedOccurrences(3)), Seq("team1"), fourDaysAgo)
      val results = repository.distinctVulnerabilitiesSummary(None, None, Some("\"service3\""), None).futureValue

      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length mustBe 1
      resultsSorted must contain theSameElementsAs Seq(expected1)
      resultsSorted.head.occurrences.length mustBe 2 //Shouldn't pick up 'Service33'

    }
  }

  "getMostRecent" must {
    "Return the dateTime Instant of the most recently generated document" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val result = repository.getMostRecent.futureValue

      result mustBe now
    }

    "Return a default Instant that is 8 days old, if there are no documents in the collection" in {

      val result = repository.getMostRecent.futureValue

      result mustBe < (now.minus(7, ChronoUnit.DAYS))
      result mustBe > (now.minus(9, ChronoUnit.DAYS))
    }
  }

  "deleteOldAndInsertNewSummaries" must {
    "delete the existing summary, and add a new summary to the collection" in new Setup {

      val intermediateRes = for {
        _   <- repository.collection.insertOne(vulnerabilitySummary1).toFuture()
        res <- repository.collection.find().toFuture()
      } yield res

      intermediateRes.futureValue.length mustBe 1

      val finalRes = for {
        _   <- repository.deleteOldAndInsertNewSummaries(Seq(vulnerabilitySummary2, vulnerabilitySummary3))
        res <- repository.collection.find().toFuture()
      } yield res

      finalRes.futureValue.length mustBe 2
      finalRes.futureValue.map(res => res.distinctVulnerability.id).sorted mustBe Seq("CVE-TEST-2", "XRAY-TEST-1")
    }
  }

  trait Setup {
    //Three vals below populate the test Mongo collection in each test case.
    lazy val vulnerabilitySummary1 =
      VulnerabilitySummary(
        distinctVulnerability = DistinctVulnerability(
          vulnerableComponentName = "component1",
          vulnerableComponentVersion = "1.0",
          vulnerableComponents = Seq(
            VulnerableComponent("component1", "1.0"),
            VulnerableComponent("component1.1", "0.8")
          ),
          id = "CVE-TEST-1",
          score = Some(1.0),
          description = "desc1",
          fixedVersions = None,
          references = Seq("test", "test"),
          publishedDate = now,
          assessment = Some(""),
          curationStatus = Some(CurationStatus.ActionRequired),
          ticket = Some("BDOG-1")
        ),
        occurrences = Seq(
          VulnerabilityOccurrence(service = "service1", serviceVersion = "1", componentPathInSlug = "a", teams = Seq("team1"), envs = Seq("development"), vulnerableComponentName = "component1", vulnerableComponentVersion = "1.0"),
          VulnerabilityOccurrence(service = "service6", serviceVersion = "2.55", componentPathInSlug = "apache:x", teams = Seq("team2"), envs = Seq("staging", "production"), vulnerableComponentName = "component1.1", vulnerableComponentVersion = "0.8")
        ),
        teams = Seq("team1", "team2"),
        generatedDate = oneMinAgo
      )

    lazy val vulnerabilitySummary2 =
      VulnerabilitySummary(
        distinctVulnerability = DistinctVulnerability(
          vulnerableComponentName = "component2",
          vulnerableComponentVersion = "2.0",
          vulnerableComponents = Seq(
            VulnerableComponent("component2", "2.0"),
          ),
          id = "CVE-TEST-2",
          score = Some(1.0),
          description = "desc2",
          fixedVersions = Some(Seq("1", "2")),
          references = Seq("test", "test"),
          publishedDate = now,
          assessment = Some(""),
          curationStatus = Some(CurationStatus.NoActionRequired),
          ticket = Some("BDOG-2")
        ),
        occurrences = Seq(
          VulnerabilityOccurrence(service = "service2", serviceVersion = "2", componentPathInSlug = "b", teams = Seq("team1"), envs = Seq("staging"), vulnerableComponentName = "component2", vulnerableComponentVersion = "2.0"),
          VulnerabilityOccurrence(service = "helloWorld", serviceVersion = "2.51", componentPathInSlug = "apache:y", teams = Seq("team1", "team2"), envs = Seq("qa"), vulnerableComponentName = "component2", vulnerableComponentVersion = "2.0")
        ),
        teams = Seq("team1", "team2"),
        generatedDate = now
      )

    lazy val vulnerabilitySummary3 = VulnerabilitySummary(
      distinctVulnerability = DistinctVulnerability(
        vulnerableComponentName = "component3",
        vulnerableComponentVersion = "3.0",
        vulnerableComponents = Seq(
          VulnerableComponent("component3", "3.0")
        ),
        id = "XRAY-TEST-1",
        score = Some(2.0),
        description = "desc3",
        fixedVersions = None,
        references = Seq("test", "test"),
        publishedDate = now,
        assessment = Some(""),
        curationStatus = Some(CurationStatus.ActionRequired),
        ticket = Some("BDOG-3")
      ),
      occurrences = Seq(
        VulnerabilityOccurrence(service = "service3",serviceVersion = "3", componentPathInSlug = "c", teams = Seq(), envs = Seq("development"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
        VulnerabilityOccurrence(service = "service3",serviceVersion = "3.1",componentPathInSlug = "d", teams = Seq(), envs =Seq("production"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
        VulnerabilityOccurrence(service = "service33",serviceVersion = "3",componentPathInSlug = "e",teams = Seq("team1"), envs =Seq("staging", "production"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
      ),
      teams = Seq("team1"),
      generatedDate = fourDaysAgo
    )

  }


}
