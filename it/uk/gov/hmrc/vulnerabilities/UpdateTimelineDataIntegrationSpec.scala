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

package uk.gov.hmrc.vulnerabilities

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.client.WireMock.{aResponse, stubFor, urlPathMatching}
import org.scalatest.concurrent.{Eventually, IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.play.guice.GuiceOneServerPerSuite
import play.api.Application
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.ws.WSClient
import uk.gov.hmrc.http.test.WireMockSupport
import uk.gov.hmrc.mongo.test.MongoSupport
import uk.gov.hmrc.vulnerabilities.model.{CurationStatus, ServiceVulnerability}
import uk.gov.hmrc.vulnerabilities.persistence.{AssessmentsRepository, RawReportsRepository, VulnerabilitiesTimelineRepository}

class UpdateTimelineDataIntegrationSpec
  extends AnyWordSpec
     with Matchers
     with ScalaFutures
     with IntegrationPatience
     with Eventually
     with GuiceOneServerPerSuite
     with WireMockSupport
     with MongoSupport {

  override def fakeApplication(): Application =
    GuiceApplicationBuilder()
      .configure(Map(
        "microservice.services.teams-and-repositories.port" -> wireMockPort,
        "application.router"                                -> "testOnlyDoNotUseInAppConf.Routes",
        "timeline.scheduler.enabled"                        -> "true",
        "mongodb.uri"                                       -> mongoUri
      ))
      .build()

  private val wsClient = app.injector.instanceOf[WSClient]

  val rawReportsCollection            = app.injector.instanceOf[RawReportsRepository]
  val assessmentsCollection           = app.injector.instanceOf[AssessmentsRepository]
  val vulnerabilityTimelineCollection = app.injector.instanceOf[VulnerabilitiesTimelineRepository]

  "vulnerabilitiesTimelineService" should {
    "Transform rawReports to serviceVulnerabilities, add the correct curationStatus and teams data, and insert the records into the vulnerabilitiesTimeline collection" in {

      //1. Pre-fill the rawReports and Assessments collections
      UpdateTimelineData.rawReports.map(r => rawReportsCollection.insertReport(r, r.rows.head.path))
      assessmentsCollection.insertAssessments(UpdateTimelineData.assessments)

      //2. Set T&R stub response
      stubFor(WireMock.get(urlPathMatching("/api/repository_teams"))
        .willReturn(aResponse().withStatus(200).withBody(UpdateTimelineStubResponses.teamsAndRepos))
      )

      //3. Provide implicit val for our expected result
      implicit val fmt = ServiceVulnerability.mongoFormat

      // It takes time for the scheduler to autostart, and run through full process.
      eventually {
        //5. Get result from collection.
        val res = vulnerabilityTimelineCollection.collection.find().toFuture().futureValue

        //TEST
        //Should not include report 1, as generatedDate is not within specified cut-off
        //Report 4 is a duplicate so should only appear once

        res.length shouldBe 3
        res should contain theSameElementsAs(Seq(
          ServiceVulnerability(id = "CVE-2021-99999", service = "service3", weekBeginning = UpdateTimelineData.nowTruncated, teams = Seq("Team3")           , curationStatus = CurationStatus.Uncurated),
          ServiceVulnerability(id = "CVE-2022-12345", service = "service3", weekBeginning = UpdateTimelineData.nowTruncated, teams = Seq("Team3")           , curationStatus = CurationStatus.NoActionRequired),
          ServiceVulnerability(id = "XRAY-000004"   , service = "service4", weekBeginning = UpdateTimelineData.nowTruncated, teams = Seq("Team4", "Team4.4"), curationStatus = CurationStatus.ActionRequired),
        ))
      }
    }
  }
}
