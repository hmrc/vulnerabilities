/*
 * Copyright 2026 HM Revenue & Customs
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

import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.client.WireMock.{aResponse, getRequestedFor, stubFor, urlEqualTo}
import org.scalatest.concurrent.{IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.prop.TableDrivenPropertyChecks._
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.mockito.MockitoSugar
import play.api.Configuration
import uk.gov.hmrc.http.{HeaderCarrier, UpstreamErrorResponse}
import uk.gov.hmrc.http.test.{HttpClientV2Support, WireMockSupport}

import java.time.{Instant, LocalDate}
import scala.concurrent.ExecutionContext.Implicits.global

class KEVCatalogConnectorSpec
  extends AnyWordSpec
     with Matchers
     with ScalaFutures
     with IntegrationPatience
     with HttpClientV2Support
     with MockitoSugar
     with WireMockSupport:

  private given HeaderCarrier = HeaderCarrier()

  private val connector =
    KEVCatalogConnector(
      Configuration("kev.downloadUrl" -> s"$wireMockUrl/kev.json"),
      httpClientV2
    )

  "downloadLatestReport" should:
    "download and deserialize a KEV catalog response" in:
      stubFor:
        WireMock.get(urlEqualTo("/kev.json"))
          .willReturn:
            aResponse()
              .withHeader("Content-Type", "application/json")
              .withBody:
                """
                  |{
                  |  "title": "CISA Catalog of Known Exploited Vulnerabilities",
                  |  "catalogVersion": "2026.09.16",
                  |  "dateReleased": "2026-09-16T18:47:50.6796Z",
                  |  "count": 2,
                  |  "vulnerabilities": [
                  |    {
                  |      "cveID": "CVE-2009-1537",
                  |      "vendorProject": "Microsoft",
                  |      "product": "DirectX",
                  |      "vulnerabilityName": "Microsoft DirectX NULL Byte Overwrite Vulnerability",
                  |      "dateAdded": "2026-05-20",
                  |      "shortDescription": "Microsoft DirectX contains a NULL byte overwrite vulnerability.",
                  |      "requiredAction": "Apply mitigations per vendor instructions.",
                  |      "dueDate": "2026-06-03",
                  |      "knownRansomwareCampaignUse": "Unknown",
                  |      "forensicTriage": "No",
                  |      "notes": "https://nvd.nist.gov/vuln/detail/CVE-2009-1537",
                  |      "cwes": []
                  |    },
                  |    {
                  |      "cveID": "CVE-2021-1782",
                  |      "vendorProject": "Apple",
                  |      "product": "Multiple Products",
                  |      "vulnerabilityName": "Apple Multiple Products Race Condition Vulnerability",
                  |      "dateAdded": "2021-11-03",
                  |      "shortDescription": "Apple products contain a race condition vulnerability.",
                  |      "requiredAction": "Apply updates per vendor instructions.",
                  |      "dueDate": "2021-11-17",
                  |      "knownRansomwareCampaignUse": "Unknown",
                  |      "forensicTriage": "No",
                  |      "notes": "https://nvd.nist.gov/vuln/detail/CVE-2021-1782",
                  |      "cwes": ["CWE-362", "CWE-667"]
                  |    }
                  |  ]
                  |}
                  |""".stripMargin

      val report = connector.downloadLatestReport().futureValue

      report.title shouldBe "CISA Catalog of Known Exploited Vulnerabilities"
      report.catalogVersion shouldBe "2026.09.16"
      report.dateReleased shouldBe Instant.parse("2026-09-16T18:47:50.6796Z")
      report.count shouldBe 2
      report.vulnerabilities should have size 2

      report.vulnerabilities.head shouldBe KevEntry(
        cveID = "CVE-2009-1537",
        vendorProject = "Microsoft",
        product = "DirectX",
        vulnerabilityName = "Microsoft DirectX NULL Byte Overwrite Vulnerability",
        dateAdded = LocalDate.parse("2026-05-20"),
        shortDescription = "Microsoft DirectX contains a NULL byte overwrite vulnerability.",
        requiredAction = "Apply mitigations per vendor instructions.",
        dueDate = LocalDate.parse("2026-06-03"),
        knownRansomwareCampaignUse = "Unknown",
        forensicTriage = "No",
        notes = "https://nvd.nist.gov/vuln/detail/CVE-2009-1537",
        cwes = Seq.empty
      )

      report.vulnerabilities(1).cveID shouldBe "CVE-2021-1782"
      report.vulnerabilities(1).dateAdded shouldBe LocalDate.parse("2021-11-03")
      report.vulnerabilities(1).cwes shouldBe Seq("CWE-362", "CWE-667")

      wireMockServer.verify(
        1,
        getRequestedFor(urlEqualTo("/kev.json"))
      )

    val httpErrorStatusCases = Table(
      ("status", "description"),
      (400, "bad request"),
      (401, "unauthorized"),
      (403, "forbidden"),
      (404, "not found"),
      (429, "rate limited"),
      (500, "server error"),
      (503, "service unavailable")
    )
    forAll(httpErrorStatusCases): (status, description) =>
      s"return HTTP $status $description error" in:
        stubFor:
          WireMock.get(urlEqualTo("/kev.json"))
            .willReturn:
              aResponse().withStatus(status)

        val result = connector.downloadLatestReport().failed.futureValue
        result shouldBe a [UpstreamErrorResponse]

    "fail when the response contains malformed JSON" in:
      stubFor:
        WireMock.get(urlEqualTo("/kev.json"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withHeader("Content-Type", "application/json")
              .withBody("{not valid json")

      connector.downloadLatestReport().failed.futureValue should not be null

    "fail when the response is missing required catalog fields" in:
      stubFor:
        WireMock.get(urlEqualTo("/kev.json"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withHeader("Content-Type", "application/json")
              .withBody("""{"title":"incomplete catalog"}""")

      connector.downloadLatestReport().failed.futureValue should not be null

