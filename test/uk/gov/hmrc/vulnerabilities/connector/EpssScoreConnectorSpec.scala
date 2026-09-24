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
import com.github.tomakehurst.wiremock.client.WireMock.{aResponse, getRequestedFor, stubFor, urlPathMatching}
import org.apache.pekko.actor.ActorSystem
import org.apache.pekko.stream.Materializer
import org.apache.pekko.stream.SystemMaterializer
import org.scalatest.OptionValues
import org.scalatest.concurrent.{IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.prop.TableDrivenPropertyChecks._
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.mockito.MockitoSugar
import play.api.Configuration
import uk.gov.hmrc.http.{HeaderCarrier, UpstreamErrorResponse}
import uk.gov.hmrc.http.test.{HttpClientV2Support, WireMockSupport}

import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream
import scala.concurrent.ExecutionContext.Implicits.global

class EpssScoreConnectorSpec
  extends AnyWordSpec
    with Matchers
    with ScalaFutures
    with IntegrationPatience
    with HttpClientV2Support
    with MockitoSugar
    with OptionValues
    with WireMockSupport:

  private given HeaderCarrier = HeaderCarrier()
  private val actorSystem = ActorSystem("epss-score-connector-spec")
  private given Materializer = SystemMaterializer(actorSystem).materializer
  private val connector = EpssScoreConnector(
    Configuration("epss.downloadUrl" -> wireMockUrl),
    httpClientV2
  )

  override def afterAll(): Unit =
    actorSystem.terminate()
    super.afterAll()

  "downloadLatestReport" should:
    "download the gzipped EPSS report - Happy Path" in:
      stubEpssReportSuccess()

      val response = connector.downloadLatestReport().futureValue
      val compressedByteCount = response.source
        .runFold(0L)((total, bytes) => total + bytes.length)
        .futureValue

      response.gzip shouldBe true
      compressedByteCount should be > 0L
      wireMockServer.verify(
        1,
        getRequestedFor(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
      )

    "return a response with gzip flag set to true" in:
      stubEpssReportSuccess()

      val response = connector.downloadLatestReport().futureValue
      response.gzip shouldBe true

    "stream source should produce non-empty bytes" in:
      stubEpssReportSuccess()

      val response = connector.downloadLatestReport().futureValue
      val byteSequence = response.source
        .runFold(Seq[Int]())((acc, bytes) => acc :+ bytes.length)
        .futureValue

      byteSequence should not be empty
      byteSequence.foreach(_ should be > 0)

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
          WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
            .willReturn:
              aResponse().withStatus(status)

        val result = connector.downloadLatestReport().failed.futureValue
        result shouldBe a [UpstreamErrorResponse]

  "getLatestReportEpssScores" should:
    "return a list containing all the CVEs and EPSS scores - Happy Path" in:
      stubEpssReportSuccess()

      val epssList: Seq[EpssScore] = connector.getLatestReportEpssScores().futureValue.scores
      epssList.size shouldBe 228
      epssList should contain allOf(
        EpssScore("CVE-1999-1324", 0.03094, 0.87153),
        EpssScore("CVE-2024-29010", 0.00621, 0.48412),
        EpssScore("CVE-2024-51319", 0.00455, 0.38826),
        EpssScore("CVE-2026-89838", 0.00157, 0.05282)
      )
      wireMockServer.verify(1, getRequestedFor(urlPathMatching("/epss_scores-.*\\.csv\\.gz")))

    "validate individual EpssScore fields have correct types and ranges" in:
      stubEpssReportSuccess()

      val epssList = connector.getLatestReportEpssScores().futureValue.scores

      epssList.foreach { score =>
        // CVE ID format validation
        score.cveId should startWith ("CVE-")
        score.cveId should not be empty

        // EPSS score should be between 0.0 and 1.0 (exploit probability)
        score.score should be >= 0.0
        score.score should be <= 1.0

        // Percentile should be between 0.0 and 1.0
        score.percentile should be >= 0.0
        score.percentile should be <= 1.0
      }

    "verify no duplicate CVE entries exist in results" in:
      stubEpssReportSuccess()

      val epssList = connector.getLatestReportEpssScores().futureValue.scores
      val uniqueCveIds = epssList.map(_.cveId).distinct

      uniqueCveIds.length shouldBe epssList.length

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
          WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
            .willReturn:
              aResponse().withStatus(status)

        val result = connector.getLatestReportEpssScores().failed.futureValue
        result shouldBe a [UpstreamErrorResponse]

    "handle malformed gzip data" in:
      val invalidGzipData = Array[Byte](0x1f.toByte, 0x8b.toByte, 0x08.toByte, 0x00.toByte, 0x00.toByte, 0x00.toByte)  // Incomplete gzip header

      stubFor:
        WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withBody(invalidGzipData)

      val result = connector.getLatestReportEpssScores().failed.futureValue
      result should not be null  // Should throw exception during decompression

    "handle empty gzipped CSV file" in:
      val emptyGzipCsv = gzip("".getBytes)

      stubFor:
        WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withBody(emptyGzipCsv)

      val epssList = connector.getLatestReportEpssScores().futureValue.scores
      epssList shouldBe empty

    "handle CSV with only headers (no data rows)" in:
      val headerOnlyCsv = gzip("#model_version:v2026.06.15,score_date:2026-09-22T12:02:55Z\ncve,epss,percentile\n".getBytes)

      stubFor:
        WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withBody(headerOnlyCsv)

      val epssList = connector.getLatestReportEpssScores().futureValue.scores
      epssList shouldBe empty

    "handle CSV with missing columns" in:
      val malformedCsv = gzip("cve,epss\nCVE-2024-1234,0.5\n".getBytes)  // Missing percentile column

      stubFor:
        WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withBody(malformedCsv)

      val report = connector.getLatestReportEpssScores().futureValue
      report.scores shouldBe empty
      report.errorCount shouldBe 1
      report.errors should have size 1

    "handle CSV with invalid score values (non-numeric)" in:
      val invalidScoreCsv = gzip("cve,epss,percentile\nCVE-2024-1234,invalid,0.5\n".getBytes)

      stubFor:
        WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withBody(invalidScoreCsv)

      val report = connector.getLatestReportEpssScores().futureValue
      report.scores shouldBe empty
      report.errorCount shouldBe 1
      report.errors should have size 1

    "handle CSV with out-of-range score values (< 0)" in:
      val negativeScoreCsv = gzip("cve,epss,percentile\nCVE-2024-1234,-0.5,0.5\n".getBytes)

      stubFor:
        WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withBody(negativeScoreCsv)

      val report = connector.getLatestReportEpssScores().futureValue
      report.scores should have size 1
      report.errorCount shouldBe 0

    "handle CSV with out-of-range score values (> 1.0)" in:
      val exceedingScoreCsv = gzip("cve,epss,percentile\nCVE-2024-1234,1.5,0.5\n".getBytes)

      stubFor:
        WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withBody(exceedingScoreCsv)

      val report = connector.getLatestReportEpssScores().futureValue
      report.scores should have size 1
      report.errorCount shouldBe 0

    "handle CSV with leading/trailing whitespace in CVE IDs" in:
      val whitespaceCsv = gzip("cve,epss,percentile\n  CVE-2024-1234  ,0.5,0.5\n".getBytes)

      stubFor:
        WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withBody(whitespaceCsv)

      // Depending on implementation, this may be handled gracefully or fail
      val result = connector.getLatestReportEpssScores().futureValue.scores
      result should not be empty  // Test if trimming is applied

    "handle single valid CVE entry" in:
      val singleEntryCsv = gzip("cve,epss,percentile\nCVE-2024-1234,0.5,0.75\n".getBytes)

      stubFor:
        WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withBody(singleEntryCsv)

      val epssList = connector.getLatestReportEpssScores().futureValue.scores
      epssList.length shouldBe 1
      epssList.head shouldBe EpssScore("CVE-2024-1234", 0.5, 0.75)

    "handle boundary score values (0.0 and 1.0)" in:
      val boundaryCsv = gzip("cve,epss,percentile\nCVE-2024-0,0.0,0.0\nCVE-2024-1,1.0,1.0\n".getBytes)

      stubFor:
        WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withBody(boundaryCsv)

      val epssList = connector.getLatestReportEpssScores().futureValue.scores
      epssList should contain allOf(
        EpssScore("CVE-2024-0", 0.0, 0.0),
        EpssScore("CVE-2024-1", 1.0, 1.0)
      )

    "handle high precision decimal values" in:
      val precisionCsv = gzip("cve,epss,percentile\nCVE-2024-1234,0.123456789,0.987654321\n".getBytes)

      stubFor:
        WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
          .willReturn:
            aResponse()
              .withStatus(200)
              .withBody(precisionCsv)

      val epssList = connector.getLatestReportEpssScores().futureValue.scores
      epssList.length shouldBe 1
      epssList.head.score shouldBe 0.123456789
      epssList.head.percentile shouldBe 0.987654321

  private def stubEpssReportSuccess(): Unit =
    val compressedCsv = gzip(loadResource("epss_subset.csv"))

    stubFor:
      WireMock.get(urlPathMatching("/epss_scores-.*\\.csv\\.gz"))
        .willReturn:
          aResponse()
            .withStatus(200)
            .withHeader("Content-Type", "binary/octet-stream")
            .withBody(compressedCsv)

  private def loadResource(name: String): Array[Byte] =
    val stream = Option(getClass.getResourceAsStream(s"/$name")).getOrElse(
      throw new IllegalArgumentException(s"Test resource not found: $name")
    )

    try
      stream.readAllBytes()
    finally
      stream.close()

  private def gzip(value: Array[Byte]): Array[Byte] =
    val output = new ByteArrayOutputStream()
    val gzip = new GZIPOutputStream(output)

    try
      gzip.write(value)
    finally
      gzip.close()

    output.toByteArray

