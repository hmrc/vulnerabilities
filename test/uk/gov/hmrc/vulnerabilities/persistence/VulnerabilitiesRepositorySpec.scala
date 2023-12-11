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

package uk.gov.hmrc.vulnerabilities.persistence

import org.scalatest.concurrent.IntegrationPatience
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpecLike
import org.scalatestplus.play.guice.GuiceOneServerPerSuite
import uk.gov.hmrc.mongo.test.DefaultPlayMongoRepositorySupport
import uk.gov.hmrc.vulnerabilities.config.AppConfig
import uk.gov.hmrc.vulnerabilities.model.{CurationStatus, DistinctVulnerability, Environment, ServiceVersionDeployments, VulnerabilityCount, VulnerabilityOccurrence, VulnerabilitySummary, VulnerableComponent}

import java.time.Instant
import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global

class VulnerabilitiesRepositorySpec
  extends AnyWordSpecLike
    with Matchers
    with DefaultPlayMongoRepositorySupport[VulnerabilitySummary]
    with IntegrationPatience
    with GuiceOneServerPerSuite {

  private val appConfig = app.injector.instanceOf[AppConfig]

  override lazy val repository = new VulnerabilitySummariesRepository(mongoComponent, appConfig)

  private val now = Instant.now().truncatedTo(ChronoUnit.MILLIS)
  private val oneMinAgo = now.minus(1, ChronoUnit.MINUTES)
  private val fourDaysAgo = now.minus(4, ChronoUnit.DAYS)

  "distinctVulnerabilitySummary" should {

    //Building blocks for VulnerabilitySummary expected results
    val expectedDistinctVulnerabilities = Seq(
      DistinctVulnerability(
        vulnerableComponentName    = "component1",
        vulnerableComponentVersion = "1.0",
        vulnerableComponents       = Seq(VulnerableComponent("component1", "1.0"), VulnerableComponent("component1.1", "0.8")),
        id                         = "CVE-TEST-1",
        score                      = Some(1.0),
        description                = "desc1",
        references                 = Seq("test", "test"),
        publishedDate              = now,
        firstDetected              = Some(now),
        assessment                 = Some(""),
        curationStatus             = Some(CurationStatus.ActionRequired), ticket = Some("BDOG-1"),
        fixedVersions              = None
      ),
      DistinctVulnerability(
        vulnerableComponentName    = "component2",
        vulnerableComponentVersion = "2.0",
        vulnerableComponents       = Seq(VulnerableComponent("component2", "2.0")),
        id                         = "CVE-TEST-2",
        score                      = Some(1.0),
        description                = "desc2",
        references                 = Seq("test", "test"),
        publishedDate              = now,
        firstDetected              = Some(now),
        assessment                 = Some(""),
        curationStatus             = Some(CurationStatus.NoActionRequired),
        ticket                     = Some("BDOG-2"),
        fixedVersions              = Some(Seq("1", "2"))
      ),
      DistinctVulnerability(
        vulnerableComponentName    = "component3",
        vulnerableComponentVersion = "3.0",
        vulnerableComponents       = Seq(VulnerableComponent("component3", "3.0")),
        id                         = "XRAY-TEST-1",
        score                      = Some(2.0),
        description                = "desc3",
        references                 = Seq("test", "test"),
        publishedDate              = now,
        firstDetected              = Some(now),
        assessment                 = Some(""),
        curationStatus             = Some(CurationStatus.ActionRequired),
        ticket                     = Some("BDOG-3"),
        fixedVersions              = None
      ),
      DistinctVulnerability(
        vulnerableComponentName = "component7",
        vulnerableComponentVersion = "7.0",
        vulnerableComponents = Seq(VulnerableComponent("component7", "7.0")),
        id = "XRAY-TEST-7",
        score = Some(2.0),
        description = "desc7",
        references = Seq("test", "test"),
        publishedDate = now,
        firstDetected = Some(now),
        assessment = Some(""),
        curationStatus = Some(CurationStatus.ActionRequired),
        ticket = Some("BDOG-7"),
        fixedVersions = None
      )
    )

    //Building blocks for VulnerabilitySummary expected results
    val expectedOccurrences = Seq(
      VulnerabilityOccurrence(service = "service1"  , serviceVersion = "1"    , componentPathInSlug = "a",        teams = Seq("team1"),          envs = Seq("development")          , vulnerableComponentName = "component1"  , vulnerableComponentVersion = "1.0"),
      VulnerabilityOccurrence(service = "service2"  , serviceVersion = "2"    , componentPathInSlug = "b",        teams = Seq("team1"),          envs = Seq("staging")              , vulnerableComponentName = "component2"  , vulnerableComponentVersion = "2.0"),
      VulnerabilityOccurrence(service = "service3"  , serviceVersion = "3"    , componentPathInSlug = "c",        teams = Seq(),                 envs = Seq("development")          , vulnerableComponentName = "component3"  , vulnerableComponentVersion = "3.0"),
      VulnerabilityOccurrence(service = "service3"  , serviceVersion = "3.1"  , componentPathInSlug = "d",        teams = Seq(),                 envs = Seq("production")           , vulnerableComponentName = "component3"  , vulnerableComponentVersion = "3.0"),
      VulnerabilityOccurrence(service = "service33" , serviceVersion = "3"    , componentPathInSlug = "e",        teams = Seq("team1"),          envs = Seq("staging", "production"), vulnerableComponentName = "component3"  , vulnerableComponentVersion = "3.0"),
      VulnerabilityOccurrence(service = "service6"  , serviceVersion = "2.55" , componentPathInSlug = "apache:x", teams = Seq("team2"),          envs = Seq("staging", "production"), vulnerableComponentName = "component1.1", vulnerableComponentVersion = "0.8"),
      VulnerabilityOccurrence(service = "helloWorld", serviceVersion = "2.51" , componentPathInSlug = "apache:y", teams = Seq("team1", "team2"), envs = Seq("qa")                   , vulnerableComponentName = "component2"  , vulnerableComponentVersion = "2.0")
    )


    "default sort by descending score and ascending id" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(0), expectedOccurrences(5)), Seq("team1", "team2"), oneMinAgo)
      val expected2 = VulnerabilitySummary(expectedDistinctVulnerabilities(1), Seq(expectedOccurrences(6), expectedOccurrences(1)), Seq("team1", "team2"), now)
      val expected3 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(2), expectedOccurrences(3), expectedOccurrences(4)), Seq("team1"), fourDaysAgo)

      val results = repository.distinctVulnerabilitiesSummary(None, None, None, None, None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length shouldBe 3
      resultsSorted shouldBe Seq(expected3, expected1, expected2)
    }

    "filter by exclusion regex and disregard vulnerability if occurrences are not defined" in new Setup {

      repository.collection.insertMany(Seq(vulnerabilityWithValidAndExludedOccurrence, vulnerabilityWithExludedOccurrenceOnly1)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(3), Seq(expectedOccurrences(2)), Seq("team1"), oneMinAgo)

      val results = repository.distinctVulnerabilitiesSummary(None, None, None, None, None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length shouldBe 1
      resultsSorted.head shouldBe expected1
      resultsSorted.head.occurrences.length shouldBe 1
    }

    "filter by exclusion regex and return empty list if no occurrence is valid" in new Setup {

      repository.collection.insertMany(Seq(vulnerabilityWithExludedOccurrenceOnly1, vulnerabilityWithExludedOccurrenceOnly2)).toFuture().futureValue

      val results = repository.distinctVulnerabilitiesSummary(None, None, None, None, None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length shouldBe 0
    }


    "filter by id" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue


      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(2), expectedOccurrences(3), expectedOccurrences(4)), Seq("team1"), fourDaysAgo)

      val results = repository.distinctVulnerabilitiesSummary(id = Some("XRAY"), None, None, None, None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))


      resultsSorted.length shouldBe 1
      resultsSorted shouldBe Seq(expected1)
    }

    "filter by curationStatus" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(0), expectedOccurrences(5)), Seq("team1", "team2"), oneMinAgo)
      val expected2 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(2), expectedOccurrences(3), expectedOccurrences(4)), Seq("team1"), fourDaysAgo)

      val results = repository.distinctVulnerabilitiesSummary(None, curationStatus = Some(CurationStatus.ActionRequired.asString), None, None, None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length shouldBe 2
      resultsSorted should contain theSameElementsAs Seq(expected1, expected2)
    }

    "filter by service name" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(0)), Seq("team1", "team2"), generatedDate = oneMinAgo)

      val results = repository.distinctVulnerabilitiesSummary(None, None, service = Some("ice1"), None, None, None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length shouldBe 1
      resultsSorted should contain theSameElementsAs Seq(expected1)
    }

    "filter by team" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(5)), Seq("team1", "team2"), oneMinAgo)
      val expected2 = VulnerabilitySummary(expectedDistinctVulnerabilities(1), Seq(expectedOccurrences(6)), Seq("team1", "team2"), now)

      val results = repository.distinctVulnerabilitiesSummary(None, None, None, None, team = Some("team2"), None).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length shouldBe 2
      resultsSorted shouldBe Seq(expected1, expected2)
    }

    "filter by component" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(0), Seq(expectedOccurrences(0), expectedOccurrences(5)), Seq("team1", "team2"), oneMinAgo)

      val results = repository.distinctVulnerabilitiesSummary(None, None, None, None, None, Some("ent1")).futureValue
      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length shouldBe 1
      resultsSorted shouldBe Seq(expected1)
    }

    "filter by all five parameters" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(4)), Seq("team1"), fourDaysAgo)

      val results1 = repository.distinctVulnerabilitiesSummary(id = Some("XRAY"), curationStatus = Some(CurationStatus.ActionRequired.asString), service = Some("3"), version = None, team = Some("team2"), component = Some("3")).futureValue
      val results2 = repository.distinctVulnerabilitiesSummary(id = Some("XRAY"), curationStatus = Some(CurationStatus.ActionRequired.asString), service = Some("3"), version = None, team = Some("team1"), component = Some("3")).futureValue

      val results1Sorted = results1.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))
      val results2Sorted = results2.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      results1Sorted.length shouldBe 0
      results2Sorted.length shouldBe 1
      results2Sorted shouldBe Seq(expected1)
    }

    "return only unique teams" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val results = repository.distinctVulnerabilitiesSummary(id = Some("XRAY"), None, None, None, None, None).futureValue

      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length shouldBe 1
      resultsSorted.head.teams.length shouldBe 1
    }

    "Do an exact match on service when searchTerm is quoted" in new Setup {
      repository.collection.insertMany(Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)).toFuture().futureValue

      val expected1 = VulnerabilitySummary(expectedDistinctVulnerabilities(2), Seq(expectedOccurrences(2), expectedOccurrences(3)), Seq("team1"), fourDaysAgo)
      val results = repository.distinctVulnerabilitiesSummary(None, None, Some("\"service3\""), None, None, None).futureValue

      val resultsSorted = results.map(res => res.copy(teams = res.teams.sorted, occurrences = res.occurrences.sortBy(_.service)))

      resultsSorted.length shouldBe 1
      resultsSorted should contain theSameElementsAs Seq(expected1)
      resultsSorted.head.occurrences.length shouldBe 2 //Shouldn't pick up 'Service33'
    }

    "return an empty list when given service and team filters that each match seperate occurrences, but don't both match the same occurrence" in new Setup {
      repository.collection.insertMany(
        Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3)
      ).toFuture().futureValue

      val res = repository.distinctVulnerabilitiesSummary(id = None, curationStatus = None, service = Some("service2"), version = None, team = Some("team2"), component = None).futureValue
      res shouldBe empty
    }
  }

  "vulnerabilitiesCount" should {

    "return counts for a service" in new Setup {
      val expected = Seq(
        VulnerabilityCount("service3", Environment.Development.asString, CurationStatus.ActionRequired  , 2),
        VulnerabilityCount("service3", Environment.Development.asString, CurationStatus.NoActionRequired, 1),
        VulnerabilityCount("service3", Environment.Production.asString , CurationStatus.ActionRequired  , 2),
        VulnerabilityCount("service3", Environment.Production.asString , CurationStatus.NoActionRequired, 1)
      )

      repository.collection.insertMany(
        Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3, vulnerabilitySummary4, vulnerabilitySummary5)
      ).toFuture().futureValue

      val result = repository.vulnerabilitiesCount(service = Some("\"service3\""), None, None)
      result.futureValue should contain theSameElementsAs expected
    }

    "return counts for all services owned by a team" in new Setup {
      val expected = Seq(
        VulnerabilityCount("service6"  , Environment.Staging.asString   , CurationStatus.ActionRequired  , 1),
        VulnerabilityCount("service6"  , Environment.Production.asString, CurationStatus.ActionRequired  , 1),
        VulnerabilityCount("helloWorld", Environment.QA.asString        , CurationStatus.NoActionRequired, 1)
      )

      repository.collection.insertMany(
        Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3, vulnerabilitySummary4, vulnerabilitySummary5)
      ).toFuture().futureValue

      val result = repository.vulnerabilitiesCount(None, team = Some("team2"), None)
      result.futureValue should contain theSameElementsAs expected
    }

    "return counts for an environment" in new Setup {
      val expected = Seq(
        VulnerabilityCount("helloWorld", Environment.QA.asString, CurationStatus.NoActionRequired, 1),
        VulnerabilityCount("service6"  , Environment.QA.asString, CurationStatus.NoActionRequired, 1),
        VulnerabilityCount("service6"  , Environment.QA.asString, CurationStatus.ActionRequired  , 1)
      )

      repository.collection.insertMany(
        Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3, vulnerabilitySummary4, vulnerabilitySummary5)
      ).toFuture().futureValue

      val result = repository.vulnerabilitiesCount(None, None, environment = Some(Environment.QA))
      result.futureValue should contain theSameElementsAs expected
    }

    "return counts with all filters applied" in new Setup {
      val expected =  Seq(
        VulnerabilityCount("service6", Environment.Production.asString, CurationStatus.ActionRequired  , 1),
        VulnerabilityCount("service6", Environment.Production.asString, CurationStatus.NoActionRequired, 1)
      )

      repository.collection.insertMany(
        Seq(vulnerabilitySummary1, vulnerabilitySummary2, vulnerabilitySummary3, vulnerabilitySummary4, vulnerabilitySummary5)
      ).toFuture().futureValue

      val result = repository.vulnerabilitiesCount(service = Some("\"service6\""), team = Some("team1"), environment = Some(Environment.Production))
      result.futureValue should contain theSameElementsAs expected
    }
  }

  "deleteOldAndInsertNewSummaries" should {
    "delete the existing summary, and add a new summary to the collection" in new Setup {

      val intermediateRes = for {
        _   <- repository.collection.insertOne(vulnerabilitySummary1).toFuture()
        res <- repository.collection.find().toFuture()
      } yield res

      intermediateRes.futureValue.length shouldBe 1

      val finalRes = for {
        _   <- repository.deleteOldAndInsertNewSummaries(Seq(vulnerabilitySummary2, vulnerabilitySummary3), Seq())
        res <- repository.collection.find().toFuture()
      } yield res

      finalRes.futureValue.length shouldBe 2
      finalRes.futureValue.map(res => res.distinctVulnerability.id).sorted shouldBe Seq("CVE-TEST-2", "XRAY-TEST-1")
    }
  }

  "filterOutEnvironmentsNoLongerDeployedTo" should {
    "no deployments should delete all" in new Setup {
      val currentSummaries: Seq[VulnerabilitySummary] = Seq(vulnerabilitySummary1, vulnerabilitySummary2)
      repository.filterOutEnvironmentsNoLongerDeployedTo(currentSummaries, Seq()).length shouldBe 0
    }
    "matches deployments should delete nothing" in new Setup {
      private val currentSummaries = Seq(vulnerabilitySummary1, vulnerabilitySummary2)
      private val svds = Seq(
        ServiceVersionDeployments("service1", "1", Seq("development")),
        ServiceVersionDeployments("service6", "2.55", Seq("staging", "production")),
        ServiceVersionDeployments("service2", "2", Seq("staging")),
        ServiceVersionDeployments("helloWorld", "2.51", Seq("qa")))
      repository.filterOutEnvironmentsNoLongerDeployedTo(currentSummaries, svds) shouldBe Seq(vulnerabilitySummary1, vulnerabilitySummary2)
    }
    "remove one environment only" in new Setup {
      private val currentSummaries = Seq(vulnerabilitySummary1)
      private val currentEnvs = currentSummaries.flatMap(v => v.occurrences.map(o => o.envs)).flatten.toSet
      private val svds = Seq(
        ServiceVersionDeployments("service1", "1", Seq("development")),
        ServiceVersionDeployments("service6", "2.55", Seq("staging")))
      private val result = repository.filterOutEnvironmentsNoLongerDeployedTo(currentSummaries, svds)
      private val remainingEnvs = result.flatMap(v => v.occurrences.map(o => o.envs)).flatten.toSet
      currentEnvs shouldBe Set("development", "staging", "production")
      remainingEnvs shouldBe Set("development", "staging")
    }
    "remove on summary only" in new Setup {
      private val currentSummaries = Seq(vulnerabilitySummary1, vulnerabilitySummary2)
      private val svds = Seq(
        ServiceVersionDeployments("service1", "1", Seq("development")),
        ServiceVersionDeployments("service6", "2.55", Seq("staging", "production")))
      repository.filterOutEnvironmentsNoLongerDeployedTo(currentSummaries, svds) shouldBe Seq(vulnerabilitySummary1)
    }
  }

  "ensureOldVulnerabilitiesStillIncluded" should {
    "not change of no current" in new Setup {
      repository.ensureOldVulnerabilitiesStillIncluded(Seq(), Seq(vulnerabilitySummary1, vulnerabilitySummary2)) shouldBe Seq(vulnerabilitySummary1, vulnerabilitySummary2)
    }
    "not change of current and new identical" in new Setup {
      private val currentSummaries = Seq(vulnerabilitySummary1, vulnerabilitySummary2)
      repository.ensureOldVulnerabilitiesStillIncluded(currentSummaries, Seq(vulnerabilitySummary1, vulnerabilitySummary2)) shouldBe Seq(vulnerabilitySummary1, vulnerabilitySummary2)
    }
    "add vulnerability if not in new" in new Setup {
      private val currentSummaries = Seq(vulnerabilitySummary1, vulnerabilitySummary2)
      repository.ensureOldVulnerabilitiesStillIncluded(currentSummaries, Seq(vulnerabilitySummary2)) shouldBe Seq(vulnerabilitySummary1, vulnerabilitySummary2)
    }
    "not change if old is missing environment" in new Setup {
      private val summary1WithoutStaging = vulnerabilitySummary1.copy(occurrences = vulnerabilitySummary1.occurrences.map(occ => occ.copy(envs = occ.envs.filterNot(_ === "production"))))
      private val currentSummaries = Seq(summary1WithoutStaging, vulnerabilitySummary2)
      repository.ensureOldVulnerabilitiesStillIncluded(currentSummaries, Seq(vulnerabilitySummary1, vulnerabilitySummary2)) shouldBe Seq(vulnerabilitySummary1, vulnerabilitySummary2)
    }
    "add env change if new is missing environment" in new Setup {
      private val summary1WithoutStaging = vulnerabilitySummary1.copy(occurrences = vulnerabilitySummary1.occurrences.map(occ => occ.copy(envs = occ.envs.filterNot(_ === "production"))))
      private val currentSummaries = Seq(vulnerabilitySummary1)
      repository.ensureOldVulnerabilitiesStillIncluded(currentSummaries, Seq(summary1WithoutStaging)) shouldBe Seq(vulnerabilitySummary1)
    }
  }

  trait Setup {
    //Three vals below populate the test Mongo collection in each test case.
    lazy val vulnerabilitySummary1 =
      VulnerabilitySummary(
        distinctVulnerability = DistinctVulnerability(
          vulnerableComponentName    = "component1",
          vulnerableComponentVersion = "1.0",
          vulnerableComponents       = Seq(
                                         VulnerableComponent("component1", "1.0"),
                                         VulnerableComponent("component1.1", "0.8")
                                       ),
          id                         = "CVE-TEST-1",
          score                      = Some(1.0),
          description                = "desc1",
          fixedVersions              = None,
          references                 = Seq("test", "test"),
          publishedDate              = now,
          firstDetected              = Some(now),
          assessment                 = Some(""),
          curationStatus             = Some(CurationStatus.ActionRequired),
          ticket                     = Some("BDOG-1")
        ),
        occurrences   = Seq(
          VulnerabilityOccurrence(service = "service1", serviceVersion = "1", componentPathInSlug = "a", teams = Seq("team1"), envs = Seq("development"), vulnerableComponentName = "component1", vulnerableComponentVersion = "1.0"),
          VulnerabilityOccurrence(service = "service6", serviceVersion = "2.55", componentPathInSlug = "apache:x", teams = Seq("team2"), envs = Seq("staging", "production"), vulnerableComponentName = "component1.1", vulnerableComponentVersion = "0.8")
        ),
        teams         = Seq("team1", "team2"),
        generatedDate = oneMinAgo
      )

    lazy val vulnerabilitySummary2 =
      VulnerabilitySummary(
        distinctVulnerability = DistinctVulnerability(
          vulnerableComponentName    = "component2",
          vulnerableComponentVersion = "2.0",
          vulnerableComponents       = Seq(
                                         VulnerableComponent("component2", "2.0"),
                                       ),
          id                         = "CVE-TEST-2",
          score                      = Some(1.0),
          description                = "desc2",
          fixedVersions              = Some(Seq("1", "2")),
          references                 = Seq("test", "test"),
          publishedDate              = now,
          firstDetected              = Some(now),
          assessment                 = Some(""),
          curationStatus             = Some(CurationStatus.NoActionRequired),
          ticket                     = Some("BDOG-2")
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
        vulnerableComponentName    = "component3",
        vulnerableComponentVersion = "3.0",
        vulnerableComponents       = Seq(
                                       VulnerableComponent("component3", "3.0")
                                     ),
        id                         = "XRAY-TEST-1",
        score                      = Some(2.0),
        description                = "desc3",
        fixedVersions              = None,
        references                 = Seq("test", "test"),
        publishedDate              = now,
        firstDetected              = Some(now),
        assessment                 = Some(""),
        curationStatus             = Some(CurationStatus.ActionRequired),
        ticket                     = Some("BDOG-3")
      ),
      occurrences = Seq(
        VulnerabilityOccurrence(service = "service3",serviceVersion = "3", componentPathInSlug = "c", teams = Seq(), envs = Seq("development"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
        VulnerabilityOccurrence(service = "service3",serviceVersion = "3.1",componentPathInSlug = "d", teams = Seq(), envs =Seq("production"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
        VulnerabilityOccurrence(service = "service33",serviceVersion = "3",componentPathInSlug = "e",teams = Seq("team1"), envs =Seq("staging", "production"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
      ),
      teams         = Seq("team1"),
      generatedDate = fourDaysAgo
    )

    lazy val vulnerabilitySummary4 = VulnerabilitySummary(
      distinctVulnerability = DistinctVulnerability(
        vulnerableComponentName    = "component3",
        vulnerableComponentVersion = "3.0",
        vulnerableComponents       = Seq(
                                       VulnerableComponent("component3", "3.0")
                                     ),
        id                         = "XRAY-TEST-2",
        score                      = Some(2.0),
        description                = "desc3",
        fixedVersions              = None,
        references                 = Seq("test", "test"),
        publishedDate              = now,
        firstDetected              = Some(now),
        assessment                 = Some(""),
        curationStatus             = Some(CurationStatus.ActionRequired),
        ticket                     = Some("BDOG-3")
      ),
      occurrences = Seq(
        VulnerabilityOccurrence(service = "service3",serviceVersion = "3", componentPathInSlug = "c", teams = Seq(), envs = Seq("production", "development"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
        VulnerabilityOccurrence(service = "service1",serviceVersion = "3.1",componentPathInSlug = "d", teams = Seq(), envs = Seq("production"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
        VulnerabilityOccurrence(service = "service6",serviceVersion = "3",componentPathInSlug = "e",teams = Seq("team1"), envs = Seq("staging", "production", "qa"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
      ),
      teams         = Seq("team1"),
      generatedDate = fourDaysAgo
    )

    lazy val vulnerabilitySummary5 = VulnerabilitySummary(
      distinctVulnerability = DistinctVulnerability(
        vulnerableComponentName    = "component3",
        vulnerableComponentVersion = "3.0",
        vulnerableComponents       = Seq(
                                       VulnerableComponent("component3", "3.0")
                                     ),
        id                         = "XRAY-TEST-3",
        score                      = Some(2.0),
        description                = "desc3",
        fixedVersions              = None,
        references                 = Seq("test", "test"),
        publishedDate              = now,
        firstDetected              = Some(now),
        assessment                 = Some(""),
        curationStatus             = Some(CurationStatus.NoActionRequired),
        ticket                     = Some("BDOG-3")
      ),
      occurrences = Seq(
        VulnerabilityOccurrence(service = "service3",serviceVersion = "3", componentPathInSlug = "c", teams = Seq(), envs = Seq("production", "development"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
        VulnerabilityOccurrence(service = "service1",serviceVersion = "3.1",componentPathInSlug = "d", teams = Seq(), envs = Seq("production"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
        VulnerabilityOccurrence(service = "service6",serviceVersion = "3",componentPathInSlug = "e",teams = Seq("team1"), envs = Seq("staging", "production", "qa"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
      ),
      teams         = Seq("team1"),
      generatedDate = oneMinAgo
    )

    lazy val vulnerabilityWithValidAndExludedOccurrence = VulnerabilitySummary(
      distinctVulnerability = DistinctVulnerability(
        vulnerableComponentName = "component7",
        vulnerableComponentVersion = "7.0",
        vulnerableComponents = Seq(
          VulnerableComponent("component7", "7.0")
        ),
        id = "XRAY-TEST-7",
        score = Some(2.0),
        description = "desc7",
        fixedVersions = None,
        references = Seq("test", "test"),
        publishedDate = now,
        firstDetected = Some(now),
        assessment = Some(""),
        curationStatus = Some(CurationStatus.ActionRequired),
        ticket = Some("BDOG-7")
      ),
      occurrences = Seq(
        VulnerabilityOccurrence(service = "service3", serviceVersion = "3", componentPathInSlug = "c", teams = Seq(), envs = Seq("development"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0"),
        VulnerabilityOccurrence(service = "service6", serviceVersion = "3.1", componentPathInSlug = "test-1.51.0/lib/net.sf.ehcache.ehcache-2.10.9.2.jar/rest-management-private-classpath/META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.xml", teams = Seq(), envs = Seq("production"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0")
      ),
      teams = Seq("team1"),
      generatedDate = oneMinAgo
    )

    lazy val vulnerabilityWithExludedOccurrenceOnly1 = VulnerabilitySummary(
      distinctVulnerability = DistinctVulnerability(
        vulnerableComponentName = "component7",
        vulnerableComponentVersion = "7.0",
        vulnerableComponents = Seq(
          VulnerableComponent("component7", "7.0")
        ),
        id = "XRAY-TEST-7",
        score = Some(2.0),
        description = "desc7",
        fixedVersions = None,
        references = Seq("test", "test"),
        publishedDate = now,
        firstDetected = Some(now),
        assessment = Some(""),
        curationStatus = Some(CurationStatus.ActionRequired),
        ticket = Some("BDOG-7")
      ),
      occurrences = Seq(
        VulnerabilityOccurrence(service = "service6", serviceVersion = "3.1", componentPathInSlug = "test-1.51.0/lib/net.sf.ehcache.ehcache-2.10.9.2.jar/rest-management-private-classpath/META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.xml", teams = Seq(), envs = Seq("production"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0")
      ),
      teams = Seq("team1"),
      generatedDate = oneMinAgo
    )

    lazy val vulnerabilityWithExludedOccurrenceOnly2 = VulnerabilitySummary(
      distinctVulnerability = DistinctVulnerability(
        vulnerableComponentName = "component8",
        vulnerableComponentVersion = "8.0",
        vulnerableComponents = Seq(
          VulnerableComponent("component8", "8.0")
        ),
        id = "XRAY-TEST-8",
        score = Some(2.0),
        description = "desc8",
        fixedVersions = None,
        references = Seq("test", "test"),
        publishedDate = now,
        firstDetected = Some(now),
        assessment = Some(""),
        curationStatus = Some(CurationStatus.ActionRequired),
        ticket = Some("BDOG-8")
      ),
      occurrences = Seq(
        VulnerabilityOccurrence(service = "service6", serviceVersion = "3.1", componentPathInSlug = "test-1.51.0/lib/net.sf.ehcache.ehcache-2.10.9.2.jar/rest-management-private-classpath/META-INF/maven/com.fasterxml.jackson.core/jackson-databind/pom.xml", teams = Seq(), envs = Seq("production"), vulnerableComponentName = "component3", vulnerableComponentVersion = "3.0")
      ),
      teams = Seq("team1"),
      generatedDate = oneMinAgo
    )
  }
}
