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

import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.client.WireMock._
import org.scalatest.concurrent.{Eventually, IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.play.guice.GuiceOneServerPerSuite
import play.api.Application
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.ws.WSClient
import uk.gov.hmrc.http.test.WireMockSupport
import uk.gov.hmrc.mongo.test.CleanMongoCollectionSupport
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilityAgeRepository

class HappyPathIntegrationSpec
  extends AnyWordSpec
     with Matchers
     with ScalaFutures
     with IntegrationPatience
     with Eventually
     with GuiceOneServerPerSuite
     with WireMockSupport
     with CleanMongoCollectionSupport {

  override def fakeApplication(): Application =
    GuiceApplicationBuilder()
      .configure(Map(
        "microservice.services.releases-api.port"           -> wireMockPort,
        "microservice.services.teams-and-repositories.port" -> wireMockPort,
        "xray.url"                                          -> wireMockUrl,
        "application.router"                                -> "testOnlyDoNotUseInAppConf.Routes",
        "scheduler.enabled"                                 -> "true",
        "mongodb.uri"                                       -> mongoUri
      ))
      .build()

  private val wsClient                   = app.injector.instanceOf[WSClient]
  private val vulnerabilityAgeCollection = app.injector.instanceOf[VulnerabilityAgeRepository]

  "updateVulnerabilities Service" should {
    "download & process reports from Xray, before transforming them into VulnerabilitySummaries and inserting to the collection" in {

      //stubbing
      stubFor(WireMock.get(urlPathMatching("/releases-api/whats-running-where"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.wrwBody))
      )

      stubFor(WireMock.post(urlPathMatching("/vulnerabilities"))
        .withRequestBody(containing("Service1_0.835"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.reportRequestResponse1))
      )

      stubFor(WireMock.post(urlPathMatching("/vulnerabilities"))
        .withRequestBody(containing("Service1_0.836"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.reportRequestResponse2))
      )

      stubFor(WireMock.get(urlPathMatching("/1"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.reportStatus1))
      )

      stubFor(WireMock.get(urlPathMatching("/2"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.reportStatus2))
      )

      stubFor(WireMock.get(urlMatching("/export/1\\?file_name=AppSec-report-Service1_0.835.0&format=json"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.zippedReport1))
      )

      stubFor(WireMock.get(urlMatching("/export/2\\?file_name=AppSec-report-Service1_0.836.0&format=json"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.zippedReport2))
      )

      stubFor(WireMock.delete(urlMatching("/1"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.reportDelete))
      )

      stubFor(WireMock.delete(urlMatching("/2"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.reportDelete))
      )

      stubFor(WireMock.get(urlPathMatching("/api/repository_teams"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.teamsAndRepos))
      )

      stubFor(WireMock.post(urlMatching("/\\?page_num=1&num_of_rows=100")).willReturn(
        aResponse()
          .withStatus(200)
          .withBody(
            s"""{"total_reports":2,"reports":[{"id":439753,"name":"AppSec-report-service1_1.0","report_type":"vulnerability","status":"completed","total_artifacts":2,"num_of_processed_artifacts":2,"progress":100,"number_of_rows":14,"start_time":"2023-01-01T11:20:20Z","end_time":"2023-08-07T11:20:21Z","author":"user1"},
               |{"id":439750,"name":"AppSec-report-service2>2.0","report_type":"vulnerability","status":"completed","total_artifacts":2,"num_of_processed_artifacts":2,"progress":100,"number_of_rows":14,"start_time":"2023-01-01T11:19:20Z","end_time":"2023-08-07T11:19:21Z","author":"user1"}]}""".stripMargin)
      ))

      stubFor(WireMock.delete(urlMatching("/439753"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.reportDelete))
      )

      stubFor(WireMock.delete(urlMatching("/439750"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.reportDelete))
      )

      //helpers
      implicit val fmt = VulnerabilitySummary.apiFormat

      val expectedResult = VulnerabilitySummary(
        DistinctVulnerability(
          vulnerableComponentName =  "gav://com.testxml.test.core:test-bind",
          vulnerableComponentVersion = "1.5.9",
          vulnerableComponents =  Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind","1.5.9")),
          id = "CVE-2022-12345", score = Some(8.0),
          description = "This is an exploit",
          fixedVersions = Some(Seq("1.6.0")),
          references = Seq("foo.com", "bar.net"),
          publishedDate = StubResponses.startOfYear,
          firstDetected = Some(StubResponses.startOfYear),
          assessment = None,
          curationStatus = Some(CurationStatus.Uncurated),
          ticket = None
        ),
        occurrences = Seq(
          VulnerabilityOccurrence("Service1","0.835.0","Service1-0.835.0/some/physical/path",Seq("Team1", "Team2"),Seq("staging"),"gav://com.testxml.test.core:test-bind","1.5.9"),
          VulnerabilityOccurrence("Service1","0.836.0","Service1-0.836.0/some/physical/path",Seq("Team1", "Team2"),Seq("production"),"gav://com.testxml.test.core:test-bind","1.5.9")
        ),
        teams = List("Team1", "Team2"),
        generatedDate = StubResponses.startOfYear
      )

      vulnerabilityAgeCollection.insertNonExisting(
        Seq(
          VulnerabilityAge(service = "", vulnerabilityId = "CVE-2022-12345", firstScanned = StubResponses.startOfYear)
        )
      )

      //Test occurs below
      eventually {
        val response = wsClient
          .url(resource("test-only/testResult/"))
          .get()
          .futureValue

        response.status shouldBe 200
        val result = response.json.as[Seq[VulnerabilitySummary]].map(_.copy(generatedDate = StubResponses.startOfYear))
        //update the results generated date as otherwise it would be dynamic - it would be the time of test

        result.length shouldBe 1
        result.head shouldBe expectedResult
      }
    }
  }

  def resource(path: String): String =
    s"http://localhost:$port/$path"
}
