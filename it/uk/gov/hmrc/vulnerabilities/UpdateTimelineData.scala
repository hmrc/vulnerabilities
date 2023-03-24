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

import uk.gov.hmrc.vulnerabilities.model.CurationStatus.{ActionRequired, InvestigationOngoing, NoActionRequired, Uncurated}
import uk.gov.hmrc.vulnerabilities.model.{CVE, RawVulnerability, Report}
import uk.gov.hmrc.vulnerabilities.utils.Assessment

import java.time.{DayOfWeek, Instant, LocalDateTime, ZoneOffset}
import java.time.temporal.{ChronoUnit, TemporalAdjusters}

object UpdateTimelineData {
  val october  = Instant.ofEpochSecond(1666346891)
  val now = Instant.now()
  //No 'nice' native method for truncating to start of week (as there is in Mongo).
  val nowTruncated = LocalDateTime.ofInstant(now, ZoneOffset.UTC)
    .truncatedTo(ChronoUnit.DAYS)
    .`with`(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY))
    .toInstant(ZoneOffset.UTC)

  lazy val report1: Report =
    Report(
      rows = Seq(
        RawVulnerability(
          cves = Seq(CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
          cvss3MaxScore = Some(8.0),
          summary = "This is an exploit",
          severity = "High",
          severitySource = "Source",
          vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.5.9",
          componentPhysicalPath = "service1-1.0.4/some/physical/path",
          impactedArtifact = "fooBar",
          impactPath = Seq("hello", "world"),
          path = "test/slugs/service1/service1_1.0.4_0.0.1.tgz",
          fixedVersions = Seq("1.6.0"),
          published = october.minus(14, ChronoUnit.DAYS),
          artifactScanTime = october.minus(1, ChronoUnit.HOURS),
          issueId = "XRAY-000003",
          packageType = "maven",
          provider = "test",
          description = "This is an exploit",
          references = Seq("foo.com", "bar.net"),
          projectKeys = Seq()
        )),
      generatedDate = october
    )

  lazy val report2: Report =
    Report(
      rows = Seq(
        RawVulnerability(
          cves = Seq(CVE(cveId = Some("CVE-2021-99999"), cveV3Score = Some(7.0), cveV3Vector = Some("test2"))),
          cvss3MaxScore = Some(7.0),
          summary = "This is an exploit",
          severity = "High",
          severitySource = "Source",
          vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.6.8",
          componentPhysicalPath = "service3-3.0.4/some/physical/path",
          impactedArtifact = "fooBar",
          impactPath = Seq("hello", "world"),
          path = "test/slugs/service3/service3_3.0.4_0.0.1.tgz",
          fixedVersions = Seq("1.6.9"),
          published = now.minus(14, ChronoUnit.DAYS),
          artifactScanTime = now.minus(1, ChronoUnit.HOURS),
          issueId = "XRAY-000002",
          packageType = "maven",
          provider = "test",
          description = "This is an exploit",
          references = Seq("foo.com", "bar.net"),
          projectKeys = Seq()
        ),
        RawVulnerability(
          cves = Seq(CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
          cvss3MaxScore = Some(8.0),
          summary = "This is an exploit",
          severity = "High",
          severitySource = "Source",
          vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.5.9",
          componentPhysicalPath = "service3-3.0.4/some/physical/path",
          impactedArtifact = "fooBar",
          impactPath = Seq("hello", "world"),
          path = "test/slugs/service3/service3_3.0.4_0.0.1.tgz",
          fixedVersions = Seq("1.6.0"),
          published = now.minus(14, ChronoUnit.DAYS),
          artifactScanTime = now.minus(1, ChronoUnit.HOURS),
          issueId = "XRAY-000003",
          packageType = "maven",
          provider = "test",
          description = "This is an exploit",
          references = Seq("foo.com", "bar.net"),
          projectKeys = Seq()
        )
      ),
      generatedDate = now
    )

  lazy val report3: Report =
    Report(
      rows = Seq(
        RawVulnerability(
          cves = Seq(CVE(cveId = None, cveV3Score = None, cveV3Vector = None)),
          cvss3MaxScore = None,
          summary = "This is an exploit",
          severity = "High",
          severitySource = "Source",
          vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.8.0",
          componentPhysicalPath = "service4-4.0.4/some/physical/path",
          impactedArtifact = "fooBar",
          impactPath = Seq("hello", "world"),
          path = "test/slugs/service4/service4_4.0.4_0.0.1.tgz",
          fixedVersions = Seq("1.8.1"),
          published = now.minus(14, ChronoUnit.DAYS).truncatedTo(ChronoUnit.MILLIS),
          artifactScanTime = now.minus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.MILLIS),
          issueId = "XRAY-000004",
          packageType = "maven",
          provider = "test",
          description = "This is an exploit",
          references = Seq("foo.com", "bar.net"),
          projectKeys = Seq()
        )),
      generatedDate = now
    )

  lazy val report4: Report =
    Report(
      rows = Seq(
        RawVulnerability(
          cves = Seq(CVE(cveId = None, cveV3Score = None, cveV3Vector = None)),
          cvss3MaxScore = None,
          summary = "This is an exploit",
          severity = "High",
          severitySource = "Source",
          vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.8.0",
          componentPhysicalPath = "service4-4.0.5/some/physical/path",
          impactedArtifact = "fooBar",
          impactPath = Seq("hello", "world"),
          path = "test/slugs/service4/service4_4.0.5_0.0.1.tgz",
          fixedVersions = Seq("1.8.1"),
          published = now.minus(14, ChronoUnit.DAYS).truncatedTo(ChronoUnit.MILLIS),
          artifactScanTime = now.minus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.MILLIS),
          issueId = "XRAY-000004",
          packageType = "maven",
          provider = "test",
          description = "This is an exploit",
          references = Seq("foo.com", "bar.net"),
          projectKeys = Seq()
        )),
      generatedDate = now
    )

  lazy val rawReports = Seq(report1, report2, report3, report4)

  val assessments = Seq(
    Assessment(id = "CVE-2022-12345", assessment = "N/A", curationStatus = NoActionRequired, lastReviewed = october, ticket = "BDOG-1"),
    Assessment(id = "XRAY-000004", assessment = "N/A", curationStatus = ActionRequired, lastReviewed = october, ticket = "BDOG-3"),
  )

}

object UpdateTimelineStubResponses {
  val teamsAndRepos =
    s"""{
       |"service4": ["Team4", "Team4.4"],
       |"service3": ["Team3"],
       |"service1": ["Team1"]
       |}""".stripMargin
}
