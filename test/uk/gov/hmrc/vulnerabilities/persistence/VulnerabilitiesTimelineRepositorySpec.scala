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

import org.mongodb.scala.ObservableFuture
import org.scalatest.concurrent.IntegrationPatience
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import uk.gov.hmrc.mongo.test.DefaultPlayMongoRepositorySupport

import uk.gov.hmrc.vulnerabilities.model.{ServiceName, TeamName, TimelineEvent, VulnerabilitiesTimelineCount}
import uk.gov.hmrc.vulnerabilities.model.CurationStatus.{ActionRequired, InvestigationOngoing, NoActionRequired, Uncurated}

import scala.concurrent.ExecutionContext.Implicits.global
import java.time.Instant

class VulnerabilitiesTimelineRepositorySpec
  extends AnyWordSpec
     with Matchers
     with DefaultPlayMongoRepositorySupport[TimelineEvent]
     with IntegrationPatience:

  override val repository: VulnerabilitiesTimelineRepository = VulnerabilitiesTimelineRepository(mongoComponent)

  private val team1 = TeamName("team1")
  private val team2 = TeamName("team2")
  private val team3 = TeamName("team3")

  "replaceOrInsert" should:
    val te1 = TimelineEvent(id = "CVE-1", service = "service1", weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), teams = Seq(team1, team2), curationStatus = ActionRequired)
    val te2 = TimelineEvent(id = "CVE-2", service = "service2", weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), teams = Seq(team1, team2), curationStatus = ActionRequired)
    val te3 = TimelineEvent(id = "CVE-3", service = "service3", weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), teams = Seq(team1, team2), curationStatus = ActionRequired)
    val te4 = TimelineEvent(id = "CVE-3", service = "service3", weekBeginning = Instant.parse("2022-12-19T00:00:00.000Z"), teams = Seq(team1, team2), curationStatus = ActionRequired)

    "insert all documents when no duplicates are found" in:
      repository.collection.insertMany(Seq(te1, te2, te3, te4)).toFuture().futureValue

      val te5 = TimelineEvent("CVE-3", "service3", Instant.parse("2022-12-26T00:00:00.000Z"), Seq(team1, team2), ActionRequired) //weekBeginning differs
      val te6 = TimelineEvent("CVE-4", "service3", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired) //id differs
      val te7 = TimelineEvent("CVE-3", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired) //service differs

      repository.replaceOrInsert(Seq(te5, te6, te7)).futureValue

      findAll().futureValue.length shouldBe 7
      findAll().futureValue should contain theSameElementsAs Seq(te1, te2, te3, te4, te5, te6, te7)

    "replace documents when duplicates are found, and insert the rest" in:
      repository.collection.insertMany(Seq(te1, te2, te3, te4)).toFuture().futureValue

      val te5 = TimelineEvent("CVE-3", "service3", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), NoActionRequired) //duplicate
      val te6 = TimelineEvent("CVE-3", "service3", Instant.parse("2022-12-12T00:00:00.000Z"), Seq(team1, team2), InvestigationOngoing) //duplicate
      val te7 = TimelineEvent("CVE-3", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired) //service differs

      repository.replaceOrInsert(Seq(te5, te6, te7)).futureValue

      findAll().futureValue.length shouldBe 5
      //sv3 and sv4 are replaced by their duplicates, which have different CurationStatus values.
      findAll().futureValue should contain theSameElementsAs Seq(te1, te2, te5, te6, te7)

    "throw an illegal argument exception when passed an empty Sequence" in:
      repository.collection.insertMany(Seq(te1, te2, te3, te4)).toFuture().futureValue

      assertThrows[IllegalArgumentException]:
        repository.replaceOrInsert(Seq()).futureValue

    "getTimelineCountsForService" should:
      val te1 = TimelineEvent(id = "CVE-1", service = "service1", weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), teams = Seq(team1            , team2            ), curationStatus = ActionRequired)
      val te2 = TimelineEvent(id = "CVE-2", service = "service2", weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), teams = Seq(team3            , TeamName("team4")), curationStatus = NoActionRequired)
      val te3 = TimelineEvent(id = "CVE-2", service = "service3", weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), teams = Seq(TeamName("team5"), TeamName("team6")), curationStatus = InvestigationOngoing)
      val te4 = TimelineEvent(id = "CVE-4", service = "service3", weekBeginning = Instant.parse("2022-12-19T00:00:00.000Z"), teams = Seq(TeamName("team6"), TeamName("team8")), curationStatus = Uncurated)

      "include timeline events equal to the from and to dates" in:
        val te5 = TimelineEvent("CVE-3", "service3", Instant.parse("2022-12-26T00:00:00.000Z"), Seq(team1, team2), ActionRequired)

        repository.collection.insertMany(Seq(te1, te2, te3, te4, te5)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = None, vulnerability = None, curationStatus = None, from = Instant.parse("2022-12-12T00:00:00.000Z"), to = Instant.parse("2022-12-26T00:00:00.000Z")).futureValue
        res.length shouldBe 3
        res should contain theSameElementsAs Seq(
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), count = 3),
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-19T00:00:00.000Z"), count = 1),
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-26T00:00:00.000Z"), count = 1)
        )

      "exclude timeline events before the 'from' date" in:
        val te5 = TimelineEvent("CVE-3", "service3", Instant.parse("2022-12-11T00:00:00.000Z"), Seq(team1, team2), ActionRequired)

        repository.collection.insertMany(Seq(te1, te2, te3, te4, te5)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = None, vulnerability = None, curationStatus = None, from = Instant.parse("2022-12-12T00:00:00.000Z"), to = Instant.parse("2022-12-19T00:00:00.000Z")).futureValue
        res.length shouldBe 2
        res should contain theSameElementsAs Seq(
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), count = 3),
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-19T00:00:00.000Z"), count = 1)
        )

      "exclude timeline events after the 'to' date" in:
        val te5 = TimelineEvent("CVE-3", "service3", Instant.parse("2022-12-20T00:00:00.000Z"), Seq(team1, team2), ActionRequired)

        repository.collection.insertMany(Seq(te1, te2, te3, te4, te5)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = None, vulnerability = None, curationStatus = None, from = Instant.parse("2022-12-12T00:00:00.000Z"), to = Instant.parse("2022-12-19T00:00:00.000Z")).futureValue
        res.length shouldBe 2
        res should contain theSameElementsAs Seq(
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), count = 3),
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-19T00:00:00.000Z"), count = 1)
        )

      "return VulnerabilityTimelineCounts for all data within the time range, when no service, team, vulnerability or CurationStatus filters are passed in" in:
        repository.collection.insertMany(Seq(te1, te2, te3, te4)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = None, vulnerability = None, curationStatus = None, from = Instant.parse("2022-12-12T00:00:00.000Z"), to = Instant.parse("2022-12-12T00:00:00.000Z")).futureValue
        res.length shouldBe 1
        res should contain theSameElementsAs Seq(
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), count = 3),
        )

      "filters by service, and is case insensitive" in:
        repository.collection.insertMany(Seq(te1, te2, te3, te4)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = Some(ServiceName("seRViCe1")), team = None, vulnerability = None, curationStatus = None, from = Instant.parse("2022-12-12T00:00:00.000Z"), to = Instant.parse("2022-12-19T00:00:00.000Z")).futureValue
        res.length shouldBe 1
        res should contain theSameElementsAs Seq(
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), count = 1),
        )

      "Do an exact match on service when searchTerm is quoted" in:
        val te5 = TimelineEvent("CVE-3", "service11", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired)

        repository.collection.insertMany(Seq(te1, te2, te3, te4, te5)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = Some(ServiceName("\"service1\"")), team = None, vulnerability = None, curationStatus = None, from = Instant.parse("2022-12-12T00:00:00.000Z"), to = Instant.parse("2022-12-19T00:00:00.000Z")).futureValue
        res.length shouldBe 1
        res should contain theSameElementsAs Seq(
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), count = 1),
        )

      "Do a substring match on service when searchTerm is NOT quoted" in:
        val te5 = TimelineEvent("CVE-3", "service11", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired)

        repository.collection.insertMany(Seq(te1, te2, te3, te4, te5)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = Some(ServiceName("service1")), team = None, vulnerability = None, curationStatus = None, from = Instant.parse("2022-12-12T00:00:00.000Z"), to = Instant.parse("2022-12-19T00:00:00.000Z")).futureValue
        res.length shouldBe 2
        res should contain theSameElementsAs Seq(
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), count = 1),
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-19T00:00:00.000Z"), count = 1),
        )

      "filters by team" in:
        repository.collection.insertMany(Seq(te1, te2, te3, te4)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = Some(TeamName("team6")), vulnerability = None, curationStatus = None, from = Instant.parse("2022-12-12T00:00:00.000Z"), to = Instant.parse("2022-12-19T00:00:00.000Z")).futureValue
        res.length shouldBe 2
        res should contain theSameElementsAs Seq(
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), count = 1),
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-19T00:00:00.000Z"), count = 1),
        )

      "filters by vulnerability" in:
        repository.collection.insertMany(Seq(te1, te2, te3, te4)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = None, vulnerability = Some("CVE-2"), curationStatus = None, from = Instant.parse("2022-12-12T00:00:00.000Z"), to = Instant.parse("2022-12-19T00:00:00.000Z")).futureValue
        res.length shouldBe 1
        res should contain theSameElementsAs Seq(
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), count = 2),
        )

      "filters by service, team AND vulnerability" in:
        val te5 = TimelineEvent("CVE-3", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team3), ActionRequired)
        val te6 = TimelineEvent("CVE-4", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired)
        val te7 = TimelineEvent("CVE-4", "service5", Instant.parse("2022-12-26T00:00:00.000Z"), Seq(team1, team3), NoActionRequired)
        val te8 = TimelineEvent("CVE-7", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), Uncurated)
        val te9 = TimelineEvent("CVE-4", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team3), NoActionRequired)

        repository.collection.insertMany(Seq(te5, te6, te7, te8, te9)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = Some(ServiceName("service5")), team = Some(team3), vulnerability = Some("CVE-4"), curationStatus = None, from = Instant.parse("2022-12-19T00:00:00.000Z"), to = Instant.parse("2022-12-26T00:00:00.000Z")).futureValue
        res.length shouldBe 2
        res should contain theSameElementsAs Seq(
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-19T00:00:00.000Z"), count = 1),
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-26T00:00:00.000Z"), count = 1),
        )

      "Groups timeline counts by weekBeginning" in:
        val te5 = TimelineEvent("CVE-4", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired)
        val te6 = TimelineEvent("CVE-5", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired)
        val te7 = TimelineEvent("CVE-5", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), NoActionRequired)
        val te8 = TimelineEvent("CVE-7", "service4", Instant.parse("2022-12-26T00:00:00.000Z"), Seq(team1, team2), Uncurated)
        val te9 = TimelineEvent("CVE-8", "service4", Instant.parse("2022-12-26T00:00:00.000Z"), Seq(team1, team2), InvestigationOngoing)

        repository.collection.insertMany(Seq(te5, te6, te7, te8, te9)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = None, vulnerability = None, curationStatus = None, from = Instant.parse("2022-12-19T00:00:00.000Z"), to = Instant.parse("2022-12-26T00:00:00.000Z")).futureValue
        res.length shouldBe 2
        res should contain theSameElementsAs Seq(
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-19T00:00:00.000Z"), count = 3),
          VulnerabilitiesTimelineCount(weekBeginning = Instant.parse("2022-12-26T00:00:00.000Z"), count = 2)
        )

      "Correctly calculates the number of InvestigationOngoing curation Statuses in a given time period" in:
        val te5 = TimelineEvent("CVE-4", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), InvestigationOngoing)
        val te6 = TimelineEvent("CVE-5", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), InvestigationOngoing)
        val te7 = TimelineEvent("CVE-6", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), InvestigationOngoing)
        val te8 = TimelineEvent("CVE-7", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired)

        repository.collection.insertMany(Seq(te5, te6, te7, te8)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = None, vulnerability = None, curationStatus = Some(InvestigationOngoing), from = Instant.parse("2022-12-19T00:00:00.000Z"), to = Instant.parse("2022-12-26T00:00:00.000Z")).futureValue
        res.length shouldBe 1
        res.head.count shouldBe 3

      "Correctly calculates the number of ActionRequired curation Statuses in a given time period" in:
        val te5 = TimelineEvent("CVE-4", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired)
        val te6 = TimelineEvent("CVE-5", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired)
        val te7 = TimelineEvent("CVE-6", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired)
        val te8 = TimelineEvent("CVE-7", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), InvestigationOngoing)

        repository.collection.insertMany(Seq(te5, te6, te7, te8)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = None, vulnerability = None, curationStatus = Some(ActionRequired), from = Instant.parse("2022-12-19T00:00:00.000Z"), to = Instant.parse("2022-12-26T00:00:00.000Z")).futureValue
        res.length shouldBe 1
        res.head.count shouldBe 3

      "Correctly calculates the number of NoActionRequired curation Statuses in a given time period" in:
        val te5 = TimelineEvent("CVE-4", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), NoActionRequired)
        val te6 = TimelineEvent("CVE-5", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), NoActionRequired)
        val te7 = TimelineEvent("CVE-6", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), NoActionRequired)
        val te8 = TimelineEvent("CVE-7", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired)

        repository.collection.insertMany(Seq(te5, te6, te7, te8)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = None, vulnerability = None, curationStatus = Some(NoActionRequired), from = Instant.parse("2022-12-19T00:00:00.000Z"), to = Instant.parse("2022-12-26T00:00:00.000Z")).futureValue
        res.length shouldBe 1
        res.head.count shouldBe 3

      "Correctly calculates the number of Uncurated curation Statuses in a given time period" in:
        val te5 = TimelineEvent("CVE-4", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), Uncurated)
        val te6 = TimelineEvent("CVE-5", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), Uncurated)
        val te7 = TimelineEvent("CVE-6", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), Uncurated)
        val te8 = TimelineEvent("CVE-7", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), NoActionRequired)

        repository.collection.insertMany(Seq(te5, te6, te7, te8)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = None, vulnerability = None, curationStatus = Some(Uncurated), from = Instant.parse("2022-12-19T00:00:00.000Z"), to = Instant.parse("2022-12-26T00:00:00.000Z")).futureValue
        res.length shouldBe 1
        res.head.count shouldBe 3

      "Correctly calculates the total vulnerabilities in a given time period" in:
        val te5 = TimelineEvent("CVE-4", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), Uncurated)
        val te6 = TimelineEvent("CVE-5", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), InvestigationOngoing)
        val te7 = TimelineEvent("CVE-6", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), ActionRequired)
        val te8 = TimelineEvent("CVE-7", "service5", Instant.parse("2022-12-19T00:00:00.000Z"), Seq(team1, team2), NoActionRequired)

        repository.collection.insertMany(Seq(te5, te6, te7, te8)).toFuture().futureValue

        val res = repository.getTimelineCounts(serviceName = None, team = None, vulnerability = None, curationStatus = None, from = Instant.parse("2022-12-19T00:00:00.000Z"), to = Instant.parse("2022-12-26T00:00:00.000Z")).futureValue
        res.length shouldBe 1
        res.head.count shouldBe 4
