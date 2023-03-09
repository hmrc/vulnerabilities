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

import uk.gov.hmrc.vulnerabilities.model.{CVE, Filter, RawVulnerability, Report, ReportRequestPayload, Resource, XrayRepo}

import java.nio.file.{Files, Paths}
import java.time.{Instant, LocalDateTime, ZoneOffset}
import java.time.temporal.ChronoUnit

object StubResponses {

  private val now: Instant = Instant.now()


  val wrwBody =
    """[
      |{
      |"applicationName": "Service1",
      |"versions": [
      |               {
      |                "environment": "staging",
      |                "versionNumber": "0.835.0"
      |                },
      |               {
      |                 "environment": "production",
      |                 "versionNumber": "0.836.0"
      |                }
      |             ]
      |}
      |]
      |""".stripMargin

  val wrwBody2 =
    """[
      |{
      |"applicationName": "Service1",
      |"versions": [
      |               {
      |                "environment": "staging",
      |                "versionNumber": "0.835.0"
      |                },
      |               {
      |                 "environment": "production",
      |                 "versionNumber": "0.836.0"
      |                }
      |             ]
      |},
      |{
      |"applicationName": "Service5",
      |"versions": [
      |               {
      |                "environment": "staging",
      |                "versionNumber": "5.0.4"
      |                },
      |               {
      |                 "environment": "production",
      |                 "versionNumber": "5.0.4"
      |                }
      |             ]
      |}
      |]
      |""".stripMargin

  val reportRequestResponse1 = s"""{"report_id":1,"status":"pending"}"""
  val reportRequestResponse2 = s"""{"report_id":2,"status":"pending"}"""

  val reportStatus1 = s"""{"id":1,"name":"AppSec-service1_0.835.0","report_type":"vulnerability",
                        |"status":"completed","total_artifacts":0,"num_of_processed_artifacts":0,"progress":100,
                        |"number_of_rows":1,"start_time":"2022-09-20T11:06:21Z","end_time":"2022-09-20T11:06:21Z",
                        |"author":"joe.bloggs"}""".stripMargin

  val reportStatus2 = s"""{"id":2,"name":"AppSec-service1_0.836.0","report_type":"vulnerability",
                         |"status":"completed","total_artifacts":0,"num_of_processed_artifacts":0,"progress":100,
                         |"number_of_rows":1,"start_time":"2022-09-20T11:06:21Z","end_time":"2022-09-20T11:06:21Z",
                         |"author":"joe.bloggs"}""".stripMargin

  val path1 = Paths.get("it/Resources/report1new.txt.zip")
  val zippedReport1 = Files.readAllBytes(path1)

  val path2 = Paths.get("it/Resources/report2new.txt.zip")
  val zippedReport2 = Files.readAllBytes(path2)

  val reportDelete = s"""{"info": "Report successfully deleted"}"""

  val teamsAndRepos = s"""{"Service1": ["Team1", "Team2"]}"""

  val startOfYear = LocalDateTime.of(2022, 1, 1, 0, 0, 0).toInstant(ZoneOffset.UTC)

  val alreadyDownloadedReport =
  Report(
    rows = Seq(
      RawVulnerability(
        cves = Seq(CVE(cveId = Some("CVE-999-999"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
        cvss3MaxScore = Some(8.0),
        summary = "This is an exploit",
        severity = "High",
        severitySource = "Source",
        vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.5.9",
        componentPhysicalPath = "Service5-5.0.4/some/physical/path",
        impactedArtifact = "fooBar",
        impactPath = Seq("hello", "world"),
        path = "test/slugs/Service5/Service5_5.0.4_0.0.1.tgz",
        fixedVersions = Seq("1.6.0"),
        published = startOfYear,
        artifactScanTime = now.minus(1, ChronoUnit.HOURS),
        issueId = "XRAY-000005",
        packageType = "maven",
        provider = "test",
        description = "This is an exploit",
        references = Seq("foo.com", "bar.net"),
        projectKeys = Seq()
      )),
    generatedDate = now.minus(167, ChronoUnit.HOURS)
  )
}

object generatedValues {
  val payload1 = ReportRequestPayload(
    name      = s"AppSec-report-Service1_0.835.0",
    resources = Resource(Seq(XrayRepo(name = "webstore-local"))),
    filters   = Filter(impactedArtifact = s"*/Service1_0.836.0*")
  )
  val payload2 = ReportRequestPayload(
    name      = s"AppSec-report-Service1_0.836.0",
    resources = Resource(Seq(XrayRepo(name = "webstore-local"))),
    filters   = Filter(impactedArtifact = s"*/Service1_0.835.0*")
  )
}