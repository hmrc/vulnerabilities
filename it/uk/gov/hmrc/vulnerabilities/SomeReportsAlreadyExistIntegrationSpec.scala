package uk.gov.hmrc.vulnerabilities

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.client.WireMock.{aResponse, containing, stubFor, urlMatching, urlPathMatching}
import com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig

import org.scalatest.BeforeAndAfterAll
import org.scalatest.concurrent.{IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.play.guice.GuiceOneServerPerSuite

import play.api.libs.ws.WSClient
import uk.gov.hmrc.integration.ServiceSpec
import uk.gov.hmrc.vulnerabilities.model.CurationStatus.Uncurated
import uk.gov.hmrc.vulnerabilities.model.{DistinctVulnerability, VulnerabilityOccurrence, VulnerabilitySummary, VulnerableComponent}
import uk.gov.hmrc.vulnerabilities.persistence.RawReportsRepository


class SomeReportsAlreadyExistIntegrationSpec
  extends AnyWordSpec
    with Matchers
    with ScalaFutures
    with IntegrationPatience
    with GuiceOneServerPerSuite
    with ServiceSpec
    with BeforeAndAfterAll {

  private val wireMockServer = new WireMockServer(wireMockConfig().port(8857))
  private val wsClient = app.injector.instanceOf[WSClient]
  val collection = app.injector.instanceOf[RawReportsRepository]

  def externalServices: Seq[String] = Seq()

  override def beforeAll(): Unit = {
    super.beforeAll()
    if (!wireMockServer.isRunning) {
      wireMockServer.start()
    }
    WireMock.configureFor("localhost", wireMockServer.port())
  }

  override def afterAll(): Unit = {
    wireMockServer.stop()
    // don't call afterAll, we don't need to stop smserver
  }

  override def additionalConfig: Map[String, _] =
    Map(
      "microservice.services.releases-api.port"           -> "8857",
      "microservice.services.teams-and-repositories.port" -> "8857",
      "xray.url"                                          -> "http://localhost:8857",
    )

  "updateVulnerabilities Service" should {
    "not attempt to redownload reports which are < 7 days old, but should still transform them into VulnerabilitySummary and add to collection" in {

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

      //helpers
      implicit val fmt = VulnerabilitySummary.apiFormat

      val expectedResult1 = VulnerabilitySummary(
        DistinctVulnerability(
          vulnerableComponentName =  "gav://com.testxml.test.core:test-bind",
          vulnerableComponentVersion = "1.5.9",
          vulnerableComponents =  Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind","1.5.9")),
          id = "CVE-2022-12345", score = Some(8.0),
          description = "This is an exploit",
          fixedVersions = Some(Seq("1.6.0")),
          references = Seq("foo.com", "bar.net"),
          publishedDate = StubResponses.startOfYear,
          assessment = None,
          curationStatus = Some(Uncurated),
          ticket = None
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
          vulnerableComponentName =  "gav://com.testxml.test.core:test-bind",
          vulnerableComponentVersion = "1.5.9",
          vulnerableComponents =  Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind","1.5.9")),
          id = "CVE-999-999", score = Some(8.0),
          description = "This is an exploit",
          fixedVersions = Some(Seq("1.6.0")),
          references = Seq("foo.com", "bar.net"),
          publishedDate = StubResponses.startOfYear,
          assessment = None,
          curationStatus = Some(Uncurated),
          ticket = None
        ),
        occurrences = Seq(
          VulnerabilityOccurrence("Service5","5.0.4","Service5-5.0.4/some/physical/path",Seq(),Seq("staging", "production"),"gav://com.testxml.test.core:test-bind","1.5.9"),
        ),
        teams = Seq(),
        generatedDate = StubResponses.startOfYear
      )

      //Test occurs below
      collection.insertReport(StubResponses.alreadyDownloadedReport,  "AppSec-report-Service5_5.0.4")

      Thread.sleep(15000) //Takes roughly 12.5 secs for scheduler to autostart, and run through entire process.
      wireMockServer.stop()     //Otherwise wiremock attempts to find stub for below request
      val response = wsClient
        .url(resource("/vulnerabilities/api/vulnerabilities/testResult"))
        .get.futureValue

      val result = response.json.as[Seq[VulnerabilitySummary]].map(_.copy(generatedDate = StubResponses.startOfYear)).sortBy(_.distinctVulnerability.id)
      //update the results generated date as otherwise it would be dynamic - it would be the time of test

      result.length shouldBe 2
      result shouldBe Seq(expectedResult1, expectedResult2)

    }
  }




}
