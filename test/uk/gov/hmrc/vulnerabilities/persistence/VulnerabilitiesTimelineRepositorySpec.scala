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
import org.scalatest.matchers.must.Matchers
import org.scalatest.wordspec.{AnyWordSpec, AnyWordSpecLike}
import uk.gov.hmrc.mongo.test.{CleanMongoCollectionSupport, PlayMongoRepositorySupport}
import uk.gov.hmrc.vulnerabilities.model.CurationStatus.{ActionRequired, InvestigationOngoing, NoActionRequired}
import uk.gov.hmrc.vulnerabilities.model.ServiceVulnerability

import scala.concurrent.ExecutionContext.Implicits.global
import java.time.Instant


class VulnerabilitiesTimelineRepositorySpec extends AnyWordSpecLike
with Matchers
with PlayMongoRepositorySupport[ServiceVulnerability]
with CleanMongoCollectionSupport
with IntegrationPatience  {

  override protected def repository = new VulnerabilitiesTimelineRepository(mongoComponent)

  val sv1 = ServiceVulnerability(id = "CVE-1", service = "service1", weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), teams = Seq("team1", "team2"), curationStatus = ActionRequired)
  val sv2 = ServiceVulnerability(id = "CVE-2", service = "service2", weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), teams = Seq("team1", "team2"), curationStatus = ActionRequired)
  val sv3 = ServiceVulnerability(id = "CVE-3", service = "service3", weekBeginning = Instant.parse("2022-12-12T00:00:00.000Z"), teams = Seq("team1", "team2"), curationStatus = ActionRequired)
  val sv4 = ServiceVulnerability(id = "CVE-3", service = "service3", weekBeginning = Instant.parse("2022-12-19T00:00:00.000Z"), teams = Seq("team1", "team2"), curationStatus = ActionRequired)


  "replaceOrInsert" should {
    "insert all documents when no duplicates are found" in {
      repository.collection.insertMany(Seq(sv1, sv2, sv3, sv4)).toFuture().futureValue

     val sv5 = ServiceVulnerability("CVE-3", "service3", Instant.parse("2022-12-26T00:00:00.000Z"), Seq("team1", "team2"), ActionRequired) //weekBeginning differs
     val sv6 = ServiceVulnerability("CVE-4", "service3", Instant.parse("2022-12-19T00:00:00.000Z"), Seq("team1", "team2"), ActionRequired) //id differs
     val sv7 = ServiceVulnerability("CVE-3", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq("team1", "team2"), ActionRequired) //service differs

      repository.replaceOrInsert(Seq(sv5, sv6, sv7)).futureValue

      findAll().futureValue.length mustBe 7
      findAll().futureValue must contain theSameElementsAs Seq(sv1, sv2, sv3, sv4, sv5, sv6, sv7)
    }

    "replace documents when duplicates are found, and insert the rest" in {
      repository.collection.insertMany(Seq(sv1, sv2, sv3, sv4)).toFuture().futureValue

      val sv5 = ServiceVulnerability("CVE-3", "service3", Instant.parse("2022-12-19T00:00:00.000Z"), Seq("team1", "team2"), NoActionRequired)     //duplicate
      val sv6 = ServiceVulnerability("CVE-3", "service3", Instant.parse("2022-12-12T00:00:00.000Z"), Seq("team1", "team2"), InvestigationOngoing) //duplicate
      val sv7 = ServiceVulnerability("CVE-3", "service4", Instant.parse("2022-12-19T00:00:00.000Z"), Seq("team1", "team2"), ActionRequired) //service differs

      repository.replaceOrInsert(Seq(sv5, sv6, sv7)).futureValue

          findAll().futureValue.length mustBe 5
          //sv3 and sv4 are replaced by their duplicates, which have different CurationStatus values.
          findAll().futureValue must contain theSameElementsAs Seq(sv1, sv2, sv5, sv6, sv7)
    }

    "throw an illegal argument exception when passed an empty Sequence" in {
      repository.collection.insertMany(Seq(sv1, sv2, sv3, sv4)).toFuture().futureValue

      assertThrows[IllegalArgumentException] {
        repository.replaceOrInsert(Seq()).futureValue
      }
    }


  }
}
