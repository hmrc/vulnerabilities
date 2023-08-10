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
import com.github.tomakehurst.wiremock.client.WireMock.{aResponse, containing, stubFor, urlMatching, urlPathMatching}
import org.scalatest.concurrent.{Eventually, IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.play.guice.GuiceOneServerPerSuite
import play.api.Application
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.ws.WSClient
import uk.gov.hmrc.http.test.WireMockSupport
import uk.gov.hmrc.mongo.test.CleanMongoCollectionSupport
import uk.gov.hmrc.vulnerabilities.model.{CurationStatus, DistinctVulnerability, VulnerabilityOccurrence, VulnerabilitySummary, VulnerableComponent}
import uk.gov.hmrc.vulnerabilities.persistence.RawReportsRepository


class SomeReportsAlreadyExistIntegrationSpec
  extends AnyWordSpec
     with Matchers
     with ScalaFutures
     with Eventually
     with IntegrationPatience
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

  private val wsClient = app.injector.instanceOf[WSClient]

  val collection = app.injector.instanceOf[RawReportsRepository]

  /**
   *
   * This test exercises the fact that it is possible for a scheduler run to fail part of the way through.
   * When it retries 3 hours later it should only attempt to download reports that don't already exist
   * in the raw reports repository within the specified data cut off time. This means we don't have to
   * re-download the whole data set in case of transient error.
   *
   * */

  "updateVulnerabilities Service" should {
    "not attempt to redownload reports which are < 1 day old, but should still transform them into VulnerabilitySummary and add to collection" in {

      //stubbing
      stubFor(WireMock.get(urlPathMatching("/releases-api/whats-running-where"))
        .willReturn(aResponse().withStatus(200).withBody(StubResponses.wrwBody2))
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

      val expectedResult1 = VulnerabilitySummary(
        DistinctVulnerability(
          vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
          vulnerableComponentVersion = "1.5.9",
          vulnerableComponents       =  Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind","1.5.9")),
          id                         = "CVE-2022-12345", score = Some(8.0),
          description                = "This is an exploit",
          fixedVersions              = Some(Seq("1.6.0")),
          references                 = Seq("foo.com", "bar.net"),
          publishedDate              = StubResponses.startOfYear,
          assessment                 = None,
          curationStatus             = Some(CurationStatus.Uncurated),
          ticket                     = None
        ),
        occurrences = Seq(
          VulnerabilityOccurrence("Service1","0.835.0","Service1-0.835.0/some/physical/path",Seq("Team1", "Team2"),Seq("staging"),"gav://com.testxml.test.core:test-bind","1.5.9"),
          VulnerabilityOccurrence("Service1","0.836.0","Service1-0.836.0/some/physical/path",Seq("Team1", "Team2"),Seq("production"),"gav://com.testxml.test.core:test-bind","1.5.9")
        ),
        teams = List("Team1", "Team2"),
        generatedDate = StubResponses.startOfYear
      )

      val expectedResult2 = VulnerabilitySummary(
        DistinctVulnerability(
          vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
          vulnerableComponentVersion = "1.5.9",
          vulnerableComponents       = Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind","1.5.9")),
          id                         = "CVE-999-999", score = Some(8.0),
          description                = "This is an exploit",
          fixedVersions              = Some(Seq("1.6.0")),
          references                 = Seq("foo.com", "bar.net"),
          publishedDate              = StubResponses.startOfYear,
          assessment                 = None,
          curationStatus             = Some(CurationStatus.Uncurated),
          ticket                     = None
        ),
        occurrences   = Seq(
          VulnerabilityOccurrence(
            "Service5",
            "5.0.4",
            "Service5-5.0.4/some/physical/path",
            Seq(),
            Seq("staging", "production"),
            "gav://com.testxml.test.core:test-bind",
            "1.5.9"
          )
        ),
        teams         = Seq(),
        generatedDate = StubResponses.startOfYear
      )

      //Test occurs below
      collection.insertReport(StubResponses.alreadyDownloadedReport,  "AppSec-report-Service5_5.0.4")

      eventually {
        val response = wsClient
          .url(resource("test-only/testResult/"))
          .get()
          .futureValue

        response.status shouldBe 200
        val result = response.json.as[Seq[VulnerabilitySummary]].map(_.copy(generatedDate = StubResponses.startOfYear)).sortBy(_.distinctVulnerability.id)
        //update the results generated date as otherwise it would be dynamic - it would be the time of test

        result.length shouldBe 2
        result shouldBe Seq(expectedResult1, expectedResult2)
      }
    }
  }

  def resource(path: String): String =
    s"http://localhost:$port/$path"
}
