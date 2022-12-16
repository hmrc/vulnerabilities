/*
 * Copyright 2022 HM Revenue & Customs
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

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import uk.gov.hmrc.vulnerabilities.model.{CVE, Deployment, RawVulnerability, Report, ServiceVersionDeployments, WhatsRunningWhere}

import java.time.Instant
import java.time.temporal.ChronoUnit



class WhatsRunningWhereServiceSpec extends AnyWordSpec with Matchers {

  "WhatsRunningWhereService" when {
    "getting envs for service version" should {
      "Transform each WRW deployment into a unique ServiceVersionDeployment, and sort by (name, version)" in new Setup {
        val expectedResult = Seq(svd1, svd2, svd3, svd4, svd5)


        val result = whatsRunningWhereService.getEnvsForServiceVersion(connectorResponseHigherEnvs)

        result.length shouldBe 5
        result should contain theSameElementsInOrderAs expectedResult
        result.last.environments shouldBe Seq("staging", "production")
      }

      "Remove integration & development Deployments, and filter out empty ServiceVersionDeployments" in new Setup {
        val expectedResult = Seq(svd1, svd2, svd3, svd4, svd5, svd6)

        val result = whatsRunningWhereService.getEnvsForServiceVersion(connectorResponseAllEnvs)

        result.length shouldBe 6
        result should contain theSameElementsInOrderAs expectedResult
        result.last.environments shouldBe Seq("production", "externaltest")
      }


    }

    "removeSVDIfRecentReportExists" should {
      "filter out any SVDs that have same serviceName & Version as a recent report" in new Setup {
        val result = whatsRunningWhereService.removeSVDIfRecentReportExists(Seq(svd1, svd2, svd3, svd4, svd5), (Seq(report1)))

        result.length shouldBe 4
        result shouldBe Seq(svd1, svd3, svd4, svd5)
      }

      "Not filter out SVDs that have EITHER a common serviceName OR serviceVersion with a report, but not BOTH." in new Setup {
        val result = whatsRunningWhereService.removeSVDIfRecentReportExists(Seq(svd1, svd2, svd3, svd4, svd5), (Seq(report2)))

        result.length shouldBe 5
        result shouldBe Seq(svd1, svd2, svd3, svd4, svd5)

      }
    }
  }
  trait Setup {
    val wrw1 = WhatsRunningWhere(serviceName = "service1",
      deployments = Seq(Deployment(environment = "qa", version = "1.1"), Deployment(environment = "production", version = "1.0")))
    val wrw2 = WhatsRunningWhere(serviceName = "service2",
      deployments = Seq(Deployment(environment = "externaltest", version = "1.9.8"), Deployment(environment = "qa", version = "1.9.6")))
    val wrw3 = WhatsRunningWhere(serviceName = "service3",
      deployments = Seq(Deployment(environment = "staging", version = "1.22"), Deployment(environment = "production", version = "1.22")))
    val wrw4 = WhatsRunningWhere(serviceName = "service4",
      deployments = Seq(Deployment(environment = "integration", version = "1.23"), Deployment(environment = "development", version = "1.23")))
    val wrw5 =  WhatsRunningWhere(serviceName = "service5",
      deployments = Seq(Deployment(environment = "integration", version = "1.29"), Deployment(environment = "production", version = "1.29"), Deployment(environment = "externaltest", version = "1.29")))

    val svd1 = ServiceVersionDeployments(serviceName = "service1", version = "1.0", environments = Seq("production"))
    val svd2 = ServiceVersionDeployments(serviceName = "service1", version = "1.1", environments = Seq("qa"))
    val svd3 = ServiceVersionDeployments(serviceName = "service2", version = "1.9.6", environments = Seq("qa"))
    val svd4 = ServiceVersionDeployments(serviceName = "service2", version = "1.9.8", environments = Seq("externaltest"))
    val svd5 = ServiceVersionDeployments(serviceName = "service3", version = "1.22", environments = Seq("staging", "production"))
    val svd6 = ServiceVersionDeployments(serviceName = "service5", version = "1.29", environments = Seq("production", "externaltest"))

    val connectorResponseHigherEnvs   = Seq(wrw1, wrw2, wrw3)
    val connectorResponseAllEnvs      = Seq(wrw1, wrw2, wrw3, wrw4, wrw5)

    val whatsRunningWhereService = new WhatsRunningWhereService

    private val now: Instant = Instant.now()

    val report1: Report =
      Report(
        rows = Seq(
          RawVulnerability(
            cves = Seq(CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
            cvss3MaxScore = Some(8.0),
            summary = "This is an exploit",
            severity = "High",
            severitySource = "Source",
            vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.5.9",
            componentPhysicalPath = "service1-1.1/some/physical/path",
            impactedArtifact = "fooBar",
            impactPath = Seq("hello", "world"),
            path = "test/slugs/service1/service1_1.1_0.0.1.tgz",
            fixedVersions = Seq("1.6.0"),
            published = now.minus(14, ChronoUnit.DAYS),
            artifactScanTime = now.minus(1, ChronoUnit.HOURS),
            issueId = "XRAY-000003",
            packageType = "maven",
            provider = "test",
            description = "This is an exploit",
            references = Seq("foo.com", "bar.net"),
            projectKeys = Seq()
          )),
        generatedDate = now
      )

    //Report should contain a serviceName from one SVD, and a service version from another SVD, and should not filter out either.
    val report2: Report =
      Report(
        rows = Seq(
          RawVulnerability(
            cves = Seq(CVE(cveId = Some("CVE-2021-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
            cvss3MaxScore = Some(8.0),
            summary = "This is an exploit",
            severity = "High",
            severitySource = "Source",
            vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.5.9",
            componentPhysicalPath = "service2-1.22/some/physical/path",
            impactedArtifact = "fooBar",
            impactPath = Seq("hello", "world"),
            path = "test/slugs/service2/service2_1.22_0.0.1.tgz",
            fixedVersions = Seq("1.6.0"),
            published = now.minus(14, ChronoUnit.DAYS),
            artifactScanTime = now.minus(1, ChronoUnit.HOURS),
            issueId = "XRAY-000004",
            packageType = "maven",
            provider = "test",
            description = "This is an exploit",
            references = Seq("foo.com", "bar.net"),
            projectKeys = Seq()
          )),
        generatedDate = now
      )
  }
}
