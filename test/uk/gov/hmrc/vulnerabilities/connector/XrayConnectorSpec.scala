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

package uk.gov.hmrc.vulnerabilities.connector

import org.apache.pekko.stream.Materializer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.client.WireMock.{aResponse, containing, equalToJson, postRequestedFor, stubFor, urlEqualTo, urlMatching}
import org.mockito.MockitoSugar
import org.scalatest.concurrent.{IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.Configuration
import uk.gov.hmrc.http.{HeaderCarrier, UpstreamErrorResponse}
import uk.gov.hmrc.http.test.{HttpClientV2Support, WireMockSupport}
import uk.gov.hmrc.vulnerabilities.connectors.XrayConnector
import uk.gov.hmrc.vulnerabilities.model.{ReportId, ReportResponse, ReportStatus, ServiceName, Version}

import java.time.temporal.ChronoUnit
import java.time.{Clock, LocalDate, ZoneOffset}
import scala.concurrent.ExecutionContext.Implicits.global

class XrayConnectorSpec
  extends AnyWordSpec
     with Matchers
     with ScalaFutures
     with IntegrationPatience
     with HttpClientV2Support
     with MockitoSugar
     with WireMockSupport {

  implicit val hc: HeaderCarrier = HeaderCarrier()

  private val config = Configuration.from(Map(
    "xray.url"               -> s"${wireMockUrl}",
    "xray.token"             -> "testToken",
    "xray.username"          -> "user1",
    "xray.reports.retention" -> "1 day"
  ))

  implicit private val materializer: Materializer = mock[Materializer]

  val now               = LocalDate.now().atStartOfDay(ZoneOffset.UTC).toInstant
  private val connector = new XrayConnector(config, httpClientV2, clock = Clock.fixed(now, ZoneOffset.UTC))

  "generateReport" when {
    "given a serviceVersionDeployments" should {
      "generate the expected request body" in {
        val expectedRequestBody =
          """{"name":"AppSec-report-service1_5_4_0","resources":{"repositories":[{"name":"webstore-local"}]},"filters":{"impacted_artifact":"*/service1_5.4.0*"}}"""

        stubFor(WireMock.post(urlMatching("/vulnerabilities"))
          .withRequestBody(containing(expectedRequestBody))
          .willReturn(
            aResponse().withBody(s"""{"report_id":1,"status":"pending"}""")
        ))

        connector.generateReport(ServiceName("service1"), Version("5.4.0")).futureValue

        wireMockServer.verify(postRequestedFor(urlEqualTo("/vulnerabilities"))
          .withRequestBody(equalToJson(expectedRequestBody)
        ))

      }
    }

    "it receives a valid response" should {
      "return a ReportRequestResponse" in {
        val expectedRequestBody =
          """{"name":"AppSec-report-service1_5_4_0","resources":{"repositories":[{"name":"webstore-local"}]},"filters":{"impacted_artifact":"*/service1_5.4.0*"}}"""

        stubFor(WireMock.post(urlMatching("/vulnerabilities"))
          .withRequestBody(containing(expectedRequestBody))
          .willReturn(
            aResponse().withBody(s"""{"report_id":1,"status":"pending"}""")
        ))

        val res = connector.generateReport(ServiceName("service1"), Version("5.4.0")).futureValue
        res shouldBe ReportResponse(reportID = 1, status = "pending")
      }
    }
  }

  "checkStatus" when {
    "given a reportId" should {
      "return a ReportStatus for the given reportID" in {

        stubFor(WireMock.get(urlMatching("/1")).willReturn(
          aResponse().withBody(s"""{"id":1,"name":"AppSec-service1","report_type":"vulnerability",
               |"status":"completed","total_artifacts":0,"num_of_processed_artifacts":0,"progress":100,
               |"number_of_rows":1,"start_time":"2022-09-20T11:06:21Z","end_time":"2022-09-20T11:06:21Z",
               |"author":"joe.bloggs"}""".stripMargin)
        ))

        val res = connector.checkStatus(id = 1).futureValue
        res shouldBe ReportStatus(status = "completed", rowCount = Some(1))
      }
    }
  }

  "deleteReport" when {
    "xray returns a 4XX response" should {
      "return an UpstreamErrorResponse Exception" in {
        stubFor(WireMock.delete(urlMatching("/1")).willReturn(
          aResponse().withStatus(404)
        ))

        val res = connector.deleteReportFromXray(reportId = 1).failed.futureValue
        res shouldBe a [UpstreamErrorResponse]
      }
    }

    "xray returns a 5XX response" should {
      "return an UpstreamErrorResponse Exception" in {
        stubFor(WireMock.delete(urlMatching("/1")).willReturn(
          aResponse().withStatus(500)
        ))

        val res = connector.deleteReportFromXray(reportId = 1).failed.futureValue
        res shouldBe a [UpstreamErrorResponse]
      }
    }
  }

  "getStaleReportDetails" should {
    "generated the expected request body" in {
      stubFor(WireMock.post(urlMatching("/\\?page_num=1&num_of_rows=100")).willReturn(
        aResponse()
          .withStatus(200)
          .withBody(
            s"""{"total_reports":2,"reports":[{"id":439753,"name":"AppSec-report-service1_1.0","report_type":"vulnerability","status":"completed","total_artifacts":2,"num_of_processed_artifacts":2,"progress":100,"number_of_rows":14,"start_time":"2023-01-01T11:20:20Z","end_time":"2023-08-07T11:20:21Z","author":"user1"},
               |{"id":439750,"name":"AppSec-report-service2>2.0","report_type":"vulnerability","status":"completed","total_artifacts":2,"num_of_processed_artifacts":2,"progress":100,"number_of_rows":14,"start_time":"2023-01-01T11:19:20Z","end_time":"2023-08-07T11:19:21Z","author":"user1"}]}""".stripMargin)
      ))

      connector.getStaleReportIds().futureValue

      val expectedRequestBody =
        s"""{"filters":{"author":"user1","start_time_range":{"start":"2023-06-01T00:00:00Z","end":"${now.minus(1, ChronoUnit.DAYS)}"}}}"""

      wireMockServer.verify(postRequestedFor(urlMatching("/\\?page_num=1&num_of_rows=100"))
        .withRequestBody(equalToJson(expectedRequestBody)
        ))
    }

    "return a Sequence of ReportIDs" in {
      stubFor(WireMock.post(urlMatching("/\\?page_num=1&num_of_rows=100")).willReturn(
        aResponse()
          .withStatus(200)
          .withBody(
            s"""{"total_reports":2,"reports":[{"id":439753,"name":"AppSec-report-service1_1.0","report_type":"vulnerability","status":"completed","total_artifacts":2,"num_of_processed_artifacts":2,"progress":100,"number_of_rows":14,"start_time":"2023-01-01T11:20:20Z","end_time":"2023-08-07T11:20:21Z","author":"user1"},
               |{"id":439750,"name":"AppSec-report-service2>2.0","report_type":"vulnerability","status":"completed","total_artifacts":2,"num_of_processed_artifacts":2,"progress":100,"number_of_rows":14,"start_time":"2023-01-01T11:19:20Z","end_time":"2023-08-07T11:19:21Z","author":"user1"}]}""".stripMargin)
      ))

      val res = connector.getStaleReportIds().futureValue

      res shouldBe Seq(ReportId(439753), ReportId(439750))

    }

    "return an UpstreamErrorResponse for 4XX errors" in {
      stubFor(WireMock.post(urlMatching("/\\?page_num=1&num_of_rows=100")).willReturn(
        aResponse()
          .withStatus(429)
      ))

      val res = connector.getStaleReportIds().failed.futureValue

      res shouldBe a [UpstreamErrorResponse]

    }

    "return an UpstreamErrorResponse for 5XX errors" in {
      stubFor(WireMock.post(urlMatching("/\\?page_num=1&num_of_rows=100")).willReturn(
        aResponse()
          .withStatus(500)
      ))

      val res = connector.getStaleReportIds().failed.futureValue

      res shouldBe a [UpstreamErrorResponse]

    }
  }
}
