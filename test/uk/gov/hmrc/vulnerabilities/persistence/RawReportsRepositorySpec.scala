package uk.gov.hmrc.vulnerabilities.persistence

import org.scalatest.concurrent.IntegrationPatience
import org.scalatest.matchers.must.Matchers
import org.scalatest.wordspec.AnyWordSpecLike
import uk.gov.hmrc.mongo.test.{CleanMongoCollectionSupport, PlayMongoRepositorySupport}
import uk.gov.hmrc.vulnerabilities.data.UnrefinedVulnerabilitySummariesData
import uk.gov.hmrc.vulnerabilities.model.{CVE, RawVulnerability, Report}

import java.time.temporal.ChronoUnit
import java.time.{Instant}
import scala.concurrent.ExecutionContext.Implicits.global


class RawReportsRepositorySpec
  extends AnyWordSpecLike
    with Matchers
    with PlayMongoRepositorySupport[Report]
    with CleanMongoCollectionSupport
    with IntegrationPatience {

  override protected def repository = new RawReportsRepository(mongoComponent)
  private val now: Instant = UnrefinedVulnerabilitySummariesData.now

  "getNewDistinctVulnerabilities" must {

    //Create expected results
    val expected1 = UnrefinedVulnerabilitySummariesData.unrefined1
    val expected2 = UnrefinedVulnerabilitySummariesData.unrefined2
    val expected3 = UnrefinedVulnerabilitySummariesData.unrefined3

    //test
    "Transform raw XRAY reports into UnrefinedVulnerabilitySummaries, and default to issueID if no CVEid exists" in new Setup {
      repository.collection.insertMany(Seq(report1, report2, report3)).toFuture().futureValue

      val result = repository.getNewDistinctVulnerabilities.futureValue
      val resSorted = result.map(res => res.copy(occurrences = res.occurrences.sortBy(_.path))).sortBy(_.id)

      resSorted.length mustBe 3
      resSorted must contain theSameElementsInOrderAs (Seq(expected1, expected2, expected3))
    }

    "Only transform reports generated in the last 24 hours" in new Setup {
      repository.collection.insertMany(Seq(report1, report2, report3, report4)).toFuture().futureValue

      val result = repository.getNewDistinctVulnerabilities.futureValue
      val resSorted = result.map(res => res.copy(occurrences = res.occurrences.sortBy(_.path))).sortBy(_.id)

      resSorted.length mustBe 3
      resSorted must contain theSameElementsInOrderAs (Seq(expected1, expected2, expected3))
    }
  }

  trait Setup {

   lazy val report1: Report =
      Report(
        rows = Some(Seq(
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
            published = now.minus(14, ChronoUnit.DAYS),
            artifactScanTime = now.minus(1, ChronoUnit.HOURS),
            issueId = "XRAY-000003",
            packageType = "maven",
            provider = "test",
            description = "This is an exploit",
            references = Seq("foo.com", "bar.net"),
            projectKeys = Seq()
        ))),
        generatedDate = now
      )

    lazy val report2: Report =
      Report(
        rows = Some(Seq(
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
        )),
        generatedDate = now
      )

    lazy val report3: Report =
      Report(
        rows = Some(Seq(
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
            published = now.minus(14, ChronoUnit.DAYS),
            artifactScanTime = now.minus(1, ChronoUnit.HOURS),
            issueId = "XRAY-000004",
            packageType = "maven",
            provider = "test",
            description = "This is an exploit",
            references = Seq("foo.com", "bar.net"),
            projectKeys = Seq()
          ))),
        generatedDate = now
      )

    lazy val report4: Report =
      Report(
        rows = Some(Seq(
          RawVulnerability(
            cves = Seq(CVE(cveId = None, cveV3Score = None, cveV3Vector = None)),
            cvss3MaxScore = None,
            summary = "This is an exploit",
            severity = "High",
            severitySource = "Source",
            vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.9.0",
            componentPhysicalPath = "service5-5.0.4/some/physical/path",
            impactedArtifact = "fooBar",
            impactPath = Seq("hello", "world"),
            path = "test/slugs/service5/service5_5.0.4_0.0.1.tgz",
            fixedVersions = Seq("1.8.1"),
            published = now.minus(14, ChronoUnit.DAYS),
            artifactScanTime = now.minus(1, ChronoUnit.HOURS),
            issueId = "XRAY-000005",
            packageType = "maven",
            provider = "test",
            description = "This is an exploit",
            references = Seq("foo.com", "bar.net"),
            projectKeys = Seq()
          ))),
        generatedDate = now.minus(3, ChronoUnit.DAYS)
      )
  }
}