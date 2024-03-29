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

package uk.gov.hmrc.vulnerabilities.service

import com.typesafe.config.ConfigFactory
import org.apache.pekko.actor.ActorSystem
import org.mockito.ArgumentMatchers.{any, anyInt}
import org.mockito.{IdiomaticMockito, Mockito}
import org.mockito.MockitoSugar.when
import org.scalatest.concurrent.IntegrationPatience
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.Configuration
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.mongo.test.{CleanMongoCollectionSupport, PlayMongoRepositorySupport}
import uk.gov.hmrc.vulnerabilities.config.{AppConfig, DataConfig}
import uk.gov.hmrc.vulnerabilities.connectors.XrayConnector
import uk.gov.hmrc.vulnerabilities.data.UnrefinedVulnerabilitySummariesData
import uk.gov.hmrc.vulnerabilities.config.SchedulerConfigs
import uk.gov.hmrc.vulnerabilities.model.{CVE, RawVulnerability, Report, ReportId, ReportResponse, ReportStatus, ServiceVersionDeployments, XrayNoData, XrayNotReady, XraySuccess}
import uk.gov.hmrc.vulnerabilities.persistence.RawReportsRepository

import java.io.ByteArrayInputStream
import java.time.{Instant, LocalDateTime, ZoneOffset}
import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

class XrayServiceSpec extends AnyWordSpec
  with PlayMongoRepositorySupport[Report]
  with CleanMongoCollectionSupport
  with IdiomaticMockito
  with IntegrationPatience
  with Matchers {

  val schedulerConfigs = mock[SchedulerConfigs]
  val configuration: DataConfig = new DataConfig(Configuration(
    "data.refresh-cutoff"           -> "7 days",
    "data.transformation-cutoff"    -> "8 days",
  ))

  implicit val hc: HeaderCarrier = HeaderCarrier()

  private val appConfig = new AppConfig(new Configuration(ConfigFactory.load()))

  override lazy val repository = new RawReportsRepository(mongoComponent, configuration, appConfig)

  "processReports" when {
    "given a list of service version deployments" should {
      "Generate a payload, request a report, download the report, and insert the report into the rawReportsrepository for each svd sequentially" in new Setup {
        val res = spy.processReports(Seq(svd1, svd3))

        Thread.sleep(3000)

        val collectionRes = res.flatMap(_ => repository.collection.find().toFuture())
        val finalRes = collectionRes.futureValue.sortBy(_.rows.length).map(rep => rep.copy(rows = rep.rows.sortBy(_.cves.head.cveId)))

        finalRes.length shouldBe 2
        finalRes should contain theSameElementsAs Seq(report1, report3)
      }
    }

    "given a list of service version deployments, one of which doesn't have any rows to Download from Xray" should {
      "Not attempt to download the empty report, or insert it Into the collection " in new Setup {
        val res = spy.processReports(Seq(svd1, svd2, svd3))

        Thread.sleep(3000)

        val collectionRes = res.flatMap(_ => repository.collection.find().toFuture())
        val finalRes = collectionRes.futureValue.sortBy(_.rows.length).map(rep => rep.copy(rows = rep.rows.sortBy(_.cves.head.cveId)))

        finalRes.length shouldBe 2
        finalRes should contain theSameElementsAs Seq(report1, report3)
      }
    }

    "given a list of service version deployments, the first of which returns an XrayNotReady" should {
      "Eventually raise an exception, and halt the execution flow, meaning no payloads are processed and added to the collection" in new Setup {
        val exceptionF = {spy.processReports(Seq(svd4, svd1, svd2, svd3))}

        Thread.sleep(3000)

        exceptionF.map(res => res shouldBe a [RuntimeException])
        val colRes = repository.collection.find().toFuture()
        colRes.futureValue.length shouldBe 0
      }
    }
  }

  "getReport" when {
    "given a reportId and Name" should {
      "request a report, unzip the report, and parse it to the Report case class" in new Setup {
        when(xrayConnector.downloadReport(1, svd)).thenReturn(Future(new ByteArrayInputStream("".getBytes())))
        Some("""{"total_rows": 1,
               |  "rows": [
               |    {
               |      "cves": [{"cve": "CVE-2022-12345","cvss_v3_score": 8.0,"cvss_v3_vector": "test"}],
               |      "cvss3_max_score": 8.0,
               |      "summary": "This is an exploit",
               |      "severity": "High",
               |      "severity_source": "Source",
               |      "vulnerable_component": "gav://com.testxml.test.core:test-bind:1.5.9",
               |      "component_physical_path": "service1-1.0.4/some/physical/path",
               |      "impacted_artifact": "fooBar",
               |      "impact_path": ["hello","world"],
               |      "path": "test/slugs/service1/service1_1.0.4_0.0.1.tgz",
               |      "fixed_versions": ["1.6.0"],
               |      "published": "2022-01-01T00:00:00Z",
               |      "artifact_scan_time": "2022-01-01T00:00:00Z",
               |      "issue_id": "XRAY-000003",
               |      "package_type": "maven",
               |      "provider": "test",
               |      "description": "This is an exploit",
               |      "references": ["foo.com","bar.net"],
               |      "project_keys": []
               |    }
               |    ]
               |}""".stripMargin) willBe returned by spy.unzipReport(any())

        val res = spy.getReport(1, svd).futureValue.map(rep => rep.copy(generatedDate = now))
        res.get shouldBe report1
      }
    }

    "unzip report returns None" should {
      "return none, and not attempt to parse the case class" in new Setup {
        when(xrayConnector.downloadReport(2, svd)).thenReturn(Future(new ByteArrayInputStream("".getBytes())))
        None willBe returned by spy.unzipReport(any())
        spy.getReport(2, svd).futureValue shouldBe None
      }
    }
  }

  "check if report ready" when {
    val xrayConnector = mock[XrayConnector]
    val actorSystem = ActorSystem("testActor") //Create a test Actor as this method uses org.apache.pekko.pattern.after{}
    val repository = mock[RawReportsRepository]

    val service = new XrayService(
      xrayConnector,
      actorSystem,
      repository
    )
    "a report that is ready" should {
      "return an XraySuccess" in {
        when(xrayConnector.checkStatus(id = 1)).thenReturn(Future(ReportStatus(status = "completed", rowCount = Some(1))))
        service.checkIfReportReady((ReportResponse(1, "pending")), 0).futureValue shouldBe XraySuccess
      }
    }

    "a report that has no rows" should {
      "return an XrayNoData" in {
        when(xrayConnector.checkStatus(id = 2)).thenReturn(Future(ReportStatus(status = "completed", rowCount = Some(0))))
        service.checkIfReportReady((ReportResponse(2, "pending")), 0).futureValue shouldBe XrayNoData
      }
    }

    "a report that never becomes ready" should {
      "eventually return an XrayFailure" in {

        when(xrayConnector.checkStatus(id = 3)).thenReturn(Future(ReportStatus(status = "creating", rowCount = None)))
        val resF = service.checkIfReportReady((ReportResponse(3, "pending")))

        Thread.sleep(16000) //as it should return XrayFailure after 15 loops of 1 second

        val res = resF.futureValue
        res shouldBe XrayNotReady
      }
    }
  }

  "deleteStaleReports" should {
    val mockXrayConnector = mock[XrayConnector]
    val mockActorSystem   = mock[ActorSystem]
    val mockRepository    = mock[RawReportsRepository]

    val service = new XrayService(
      mockXrayConnector,
      mockActorSystem,
      mockRepository
    )

    "request deletion for all stale reports" in {
      when(mockXrayConnector.getStaleReportIds()(any[HeaderCarrier])).thenReturn(Future.successful(Seq(ReportId(1), ReportId(2), ReportId(3))))
      when(mockXrayConnector.deleteReportFromXray(anyInt())(any[HeaderCarrier])).thenReturn(Future.unit)

      service.deleteStaleReports().futureValue

      mockXrayConnector.deleteReportFromXray((1)) wasCalled once
      mockXrayConnector.deleteReportFromXray((2)) wasCalled once
      mockXrayConnector.deleteReportFromXray((3)) wasCalled once

    }
  }

  trait Setup {

    val xrayConnector = mock[XrayConnector]
    val actorSystem = mock[ActorSystem]

    val now: Instant = UnrefinedVulnerabilitySummariesData.now
    val before: Instant = LocalDateTime.of(2022, 1, 1, 0,0,0).toInstant(ZoneOffset.UTC)

    //Create spy for service, rather than mock, as want to use real methods when no stub specified,
    //and also want to pass a real repository, rather than a mocked one into the test.
    val spy = Mockito.spy( new XrayService(xrayConnector, actorSystem, repository))

    val svd = ServiceVersionDeployments(serviceName = "service1", version = "1.0.4", environments = Seq("production"))

    val svd1 = ServiceVersionDeployments(serviceName = "service1", version = "1.0", environments = Seq("production"))
    val svd2 = ServiceVersionDeployments(serviceName = "service2", version = "2.0", environments = Seq("production"))
    val svd3 = ServiceVersionDeployments(serviceName = "service3", version = "3.0", environments = Seq("production"))
    val svd4 = ServiceVersionDeployments(serviceName = "service4", version = "4.0", environments = Seq("production"))
    val svds = Seq(svd1, svd2, svd3)

    val reportRequestResponse1 = ReportResponse(reportID = 1, status = "pending")
    val reportRequestResponse2 = ReportResponse(reportID = 2, status = "pending")
    val reportRequestResponse3 = ReportResponse(reportID = 3, status = "pending")
    val reportRequestResponse4 = ReportResponse(reportID = 4, status = "pending")

    //mock checkXrayResponse
    Future(XraySuccess) willBe returned by spy.checkIfReportReady(reportRequestResponse1, anyInt())
    Future(XrayNoData)  willBe returned by spy.checkIfReportReady(reportRequestResponse2, anyInt())
    Future(XraySuccess) willBe returned by spy.checkIfReportReady(reportRequestResponse3, anyInt())
    Future(XrayNotReady) willBe returned by spy.checkIfReportReady(reportRequestResponse4, anyInt())

    //mock xray Connector
    when(xrayConnector.generateReport(svd1)).thenReturn(Future(reportRequestResponse1))
    when(xrayConnector.generateReport(svd2)).thenReturn(Future(reportRequestResponse2))
    when(xrayConnector.generateReport(svd3)).thenReturn(Future(reportRequestResponse3))
    when(xrayConnector.generateReport(svd4)).thenReturn(Future(reportRequestResponse4))

    when(xrayConnector.deleteReportFromXray(anyInt())(any[HeaderCarrier])).thenReturn(Future.unit)

    //mock getReport

    Future(Some(report1)) willBe returned by spy.getReport(reportRequestResponse1.reportID, svd1)
    Future(Some(report3)) willBe returned by spy.getReport(reportRequestResponse3.reportID, svd3)

    lazy val report1: Report =
      Report(
        serviceName    = "service1",
        serviceVersion = "1.0.4",
        rows = Seq(
          RawVulnerability(
            cves = Seq(CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
            cvss3MaxScore = Some(8.0), summary = "This is an exploit", severity = "High", severitySource = "Source",
            vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.5.9", componentPhysicalPath = "service1-1.0.4/some/physical/path",
            impactedArtifact = "fooBar", impactPath = Seq("hello", "world"), path = "test/slugs/service1/service1_1.0.4_0.0.1.tgz", fixedVersions = Seq("1.6.0"),
            published = before, artifactScanTime = before,
            issueId = "XRAY-000003", packageType = "maven", provider = "test", description = "This is an exploit", references = Seq("foo.com", "bar.net"), projectKeys = Seq()
          )),
        generatedDate = now
      )

    lazy val report3: Report =
      Report(
        serviceName    = "service3",
        serviceVersion = "3.0.4",
        rows = Seq(
          RawVulnerability(
            cves = Seq(CVE(cveId = Some("CVE-2021-99999"), cveV3Score = Some(7.0), cveV3Vector = Some("test2"))),
            cvss3MaxScore = Some(7.0), summary = "This is an exploit", severity = "High", severitySource = "Source",
            vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.6.8", componentPhysicalPath = "service3-3.0.4/some/physical/path",
            impactedArtifact = "fooBar", impactPath = Seq("hello", "world"), path = "test/slugs/service3/service3_3.0.4_0.0.1.tgz",
            fixedVersions = Seq("1.6.9"), published = now.minus(14, ChronoUnit.DAYS), artifactScanTime = now.minus(1, ChronoUnit.HOURS),
            issueId = "XRAY-000002", packageType = "maven", provider = "test", description = "This is an exploit", references = Seq("foo.com", "bar.net"), projectKeys = Seq()
          ),
          RawVulnerability(
            cves = Seq(CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
            cvss3MaxScore = Some(8.0), summary = "This is an exploit", severity = "High", severitySource = "Source",
            vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.5.9", componentPhysicalPath = "service3-3.0.4/some/physical/path",
            impactedArtifact = "fooBar", impactPath = Seq("hello", "world"), path = "test/slugs/service3/service3_3.0.4_0.0.1.tgz",
            fixedVersions = Seq("1.6.0"), published = now.minus(14, ChronoUnit.DAYS), artifactScanTime = now.minus(1, ChronoUnit.HOURS),
            issueId = "XRAY-000003", packageType = "maven", provider = "test", description = "This is an exploit", references = Seq("foo.com", "bar.net"), projectKeys = Seq()
          )
        ),
        generatedDate = now
      )

  }
}

