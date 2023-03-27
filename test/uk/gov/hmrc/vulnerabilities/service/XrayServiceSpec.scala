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

import akka.actor.ActorSystem
import org.mockito.ArgumentMatchers.{any, anyInt}
import org.mockito.{IdiomaticMockito, Mockito}
import org.mockito.MockitoSugar.when
import org.scalatest.concurrent.IntegrationPatience
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.Configuration
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.mongo.test.{CleanMongoCollectionSupport, PlayMongoRepositorySupport}
import uk.gov.hmrc.vulnerabilities.config.SchedulerConfigs
import uk.gov.hmrc.vulnerabilities.connectors.XrayConnector
import uk.gov.hmrc.vulnerabilities.data.UnrefinedVulnerabilitySummariesData
import uk.gov.hmrc.vulnerabilities.model.{CVE, Filter, RawVulnerability, Report, ReportDelete, ReportRequestPayload, ReportRequestResponse, ReportStatus, Resource, ServiceVersionDeployments, XrayNotReady, XrayNoData, XrayRepo, XraySuccess}
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
  val configuration: Configuration = Configuration(
    "data.refresh-cutoff"    -> "7 days",
  )

  implicit val hc: HeaderCarrier = HeaderCarrier()

  override lazy val repository = new RawReportsRepository(mongoComponent, configuration)
  "XrayService" when {
    "creating an xray payload" should {
      "Transform a serviceVersionDeployments into a ReportRequestPayload" in {
        val svd1 = ServiceVersionDeployments(serviceName = "service1", version = "1.0", environments = Seq("production"))

        val xrayConnector = mock[XrayConnector]
        val actorSystem = mock[ActorSystem]
        val repository = mock[RawReportsRepository]

        val service = new XrayService(
          xrayConnector,
          actorSystem,
          repository
        )

        val expectedResult = ReportRequestPayload(
          name = s"AppSec-report-service1_1.0",
          resources = Resource(Seq(XrayRepo(name = "webstore-local"))),
          filters = Filter(impactedArtifact = s"*/service1_1.0*")
        )

        val res = service.createXrayPayload(svd1)

        res shouldBe (expectedResult)
      }
    }
  }

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
        when(xrayConnector.downloadReport(1, "AppSec-report-service1_1.0.4")).thenReturn(Future(new ByteArrayInputStream("".getBytes())))
        Some(""""{total_rows": 1,
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

        val res = spy.getReport(1, "AppSec-report-service1_1.0.4").futureValue.map(rep => rep.copy(generatedDate = now))
        res.get shouldBe report1
      }
    }

    "unzip report returns None" should {
      "return none, and not attempt to parse the case class" in new Setup {
        when(xrayConnector.downloadReport(2, "AppSec-report-service1_1.0.4")).thenReturn(Future(new ByteArrayInputStream("".getBytes())))
        None willBe returned by spy.unzipReport(any())
        spy.getReport(2, "AppSec-report-service1_1.0.4").futureValue shouldBe None
      }
    }

  "check if report ready" when {
    val xrayConnector = mock[XrayConnector]
    val actorSystem = ActorSystem("testActor") //Create a test Actor as this method uses akka.pattern.after{}
    val repository = mock[RawReportsRepository]

    val service = new XrayService(
      xrayConnector,
      actorSystem,
      repository
    )
    "a report that is ready" should {
      "return an XraySuccess" in {
        when(xrayConnector.checkStatus(id = 1)).thenReturn(Future(ReportStatus(status = "completed", rowCount = Some(1))))
        service.checkIfReportReady((ReportRequestResponse(1, "pending")), 0).futureValue shouldBe XraySuccess
      }
    }

    "a report that has no rows" should {
      "return an XrayNoData" in {
        when(xrayConnector.checkStatus(id = 2)).thenReturn(Future(ReportStatus(status = "completed", rowCount = Some(0))))
        service.checkIfReportReady((ReportRequestResponse(2, "pending")), 0).futureValue shouldBe XrayNoData
      }
    }

    "a report that never becomes ready" should {
      "eventually return an XrayFailure" in {

        when(xrayConnector.checkStatus(id = 3)).thenReturn(Future(ReportStatus(status = "creating", rowCount = None)))
        val resF = service.checkIfReportReady((ReportRequestResponse(3, "pending")))

        Thread.sleep(16000) //as it should return XrayFailure after 15 loops of 1 second

        val res = resF.futureValue
        res shouldBe XrayNotReady
      }
    }
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


    val svd1 = ServiceVersionDeployments(serviceName = "service1", version = "1.0", environments = Seq("production"))
    val svd2 = ServiceVersionDeployments(serviceName = "service2", version = "2.0", environments = Seq("production"))
    val svd3 = ServiceVersionDeployments(serviceName = "service3", version = "3.0", environments = Seq("production"))
    val svd4 = ServiceVersionDeployments(serviceName = "service4", version = "4.0", environments = Seq("production"))
    val svds = Seq(svd1, svd2, svd3)


    val payload1 = ReportRequestPayload(name = s"AppSec-report-service1_1.0.4", resources = Resource(Seq(XrayRepo(name = "webstore-local"))), filters = Filter(impactedArtifact = s"*/service1_1.0*"))
    val payload2 = ReportRequestPayload(name = s"AppSec-report-service2_2.0",   resources = Resource(Seq(XrayRepo(name = "webstore-local"))), filters = Filter(impactedArtifact = s"*/service2_2.0*"))
    val payload3 = ReportRequestPayload(name = s"AppSec-report-service3_3.0.4", resources = Resource(Seq(XrayRepo(name = "webstore-local"))), filters = Filter(impactedArtifact = s"*/service3_3.0*"))
    val payload4 = ReportRequestPayload(name = s"AppSec-report-service4_4.0.4", resources = Resource(Seq(XrayRepo(name = "webstore-local"))), filters = Filter(impactedArtifact = s"*/service4_4.0*"))


    val reportRequestResponse1 = ReportRequestResponse(reportID = 1, status = "pending")
    val reportRequestResponse2 = ReportRequestResponse(reportID = 2, status = "pending")
    val reportRequestResponse3 = ReportRequestResponse(reportID = 3, status = "pending")
    val reportRequestResponse4 = ReportRequestResponse(reportID = 4, status = "pending")

    //mock createXrayPayload
    payload1 willBe returned by spy.createXrayPayload(svd1)
    payload2 willBe returned by spy.createXrayPayload(svd2)
    payload3 willBe returned by spy.createXrayPayload(svd3)
    payload4 willBe returned by spy.createXrayPayload(svd4)

    //mock checkXrayResponse
    Future(XraySuccess) willBe returned by spy.checkIfReportReady(reportRequestResponse1, anyInt())
    Future(XrayNoData)  willBe returned by spy.checkIfReportReady(reportRequestResponse2, anyInt())
    Future(XraySuccess) willBe returned by spy.checkIfReportReady(reportRequestResponse3, anyInt())
    Future(XrayNotReady) willBe returned by spy.checkIfReportReady(reportRequestResponse4, anyInt())

    //mock xray Connector
    when(xrayConnector.generateReport(payload1)).thenReturn(Future(reportRequestResponse1))
    when(xrayConnector.generateReport(payload2)).thenReturn(Future(reportRequestResponse2))
    when(xrayConnector.generateReport(payload3)).thenReturn(Future(reportRequestResponse3))
    when(xrayConnector.generateReport(payload4)).thenReturn(Future(reportRequestResponse4))

    when(xrayConnector.deleteReportFromXray(anyInt())(any[HeaderCarrier])).thenReturn(Future(ReportDelete("Report successfully deleted")))

    //mock getReport

    Future(Some(report1)) willBe returned by spy.getReport(reportRequestResponse1.reportID, payload1.name)
    Future(Some(report3)) willBe returned by spy.getReport(reportRequestResponse3.reportID, payload3.name)

    lazy val report1: Report =
      Report(
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

