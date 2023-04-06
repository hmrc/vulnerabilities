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

import akka.stream.Materializer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.client.WireMock.{aResponse, stubFor, urlMatching}
import org.mockito.MockitoSugar
import org.scalatest.BeforeAndAfterAll
import org.scalatest.concurrent.{IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.Configuration
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.http.test.{HttpClientV2Support, WireMockSupport}
import uk.gov.hmrc.vulnerabilities.config.XrayConfig
import uk.gov.hmrc.vulnerabilities.connectors.XrayConnector
import uk.gov.hmrc.vulnerabilities.model.{Filter, ReportDelete, ReportRequestPayload, ReportRequestResponse, ReportStatus, Resource, XrayRepo}

import scala.concurrent.ExecutionContext.Implicits.global

class XrayConnectorSpec
  extends AnyWordSpec
     with Matchers
     with ScalaFutures
     with IntegrationPatience
     with HttpClientV2Support
     with BeforeAndAfterAll
     with MockitoSugar
     with WireMockSupport {

  implicit val hc: HeaderCarrier = HeaderCarrier()

  private val config = new XrayConfig(
    configuration = Configuration.from(Map(
      "xray.url"     -> s"${wireMockUrl}",
      "xray.token"   -> "testToken",
    ))
  )

  implicit private val materializer: Materializer = mock[Materializer]
  private val connector = new XrayConnector(httpClientV2, config)

  val payload: ReportRequestPayload =  ReportRequestPayload(
    name      = s"AppSec-report-service1_5.4.0",
    resources = Resource(Seq(XrayRepo(name = "webstore-local"))),
    filters   = Filter(impactedArtifact = s"*/service1_5.4.0*")
  )

  "generateReport" when {
    "given a report request body" should {
      "return a ReportRequestResponse" in {
        stubFor(WireMock.post(urlMatching("/vulnerabilities")).willReturn(
            aResponse().withBody(s"""{"report_id":1,"status":"pending"}""")
        ))

        val res = connector.generateReport(payload).futureValue
        res shouldBe ReportRequestResponse(reportID = 1, status = "pending")
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
    "given a reportId" should {
      "return a ReportDelete for the given reportID" in {
        stubFor(WireMock.delete(urlMatching("/1")).willReturn(
          aResponse().withBody(s"""{"info": "Report successfully deleted"}""")
        ))

        val res = connector.deleteReportFromXray(reportId = 1).futureValue
        res shouldBe ReportDelete(info = "Report successfully deleted")
      }
    }
  }
}
