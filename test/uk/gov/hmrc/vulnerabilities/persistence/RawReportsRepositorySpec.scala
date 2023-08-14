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

package uk.gov.hmrc.vulnerabilities.persistence

import org.mongodb.scala.MongoCollection
import org.scalatest.concurrent.IntegrationPatience
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpecLike
import play.api.Configuration
import uk.gov.hmrc.mongo.play.json.CollectionFactory
import uk.gov.hmrc.mongo.test.DefaultPlayMongoRepositorySupport
import uk.gov.hmrc.vulnerabilities.config.DataConfig
import uk.gov.hmrc.vulnerabilities.data.UnrefinedVulnerabilitySummariesData
import uk.gov.hmrc.vulnerabilities.model.{CVE, CurationStatus, RawVulnerability, Report, TimelineEvent}
import uk.gov.hmrc.vulnerabilities.model.CurationStatus.{ActionRequired, InvestigationOngoing, NoActionRequired, Uncurated}
import uk.gov.hmrc.vulnerabilities.utils.Assessment

import java.time.Instant
import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global


class RawReportsRepositorySpec
  extends AnyWordSpecLike
     with Matchers
     with DefaultPlayMongoRepositorySupport[Report]
     with IntegrationPatience {

  //Tests exercise aggregation pipeline, which don't make use of indices.
  override protected def checkIndexedQueries: Boolean = false

  val configuration: DataConfig = new DataConfig(Configuration(
    "data.refresh-cutoff"    -> "7 days",
    "data.transformation-cutoff"    -> "8 days",
  ))

  override lazy val repository = new RawReportsRepository(mongoComponent, configuration)
  private val now: Instant = UnrefinedVulnerabilitySummariesData.now

  "getNewDistinctVulnerabilities" should {
    //Create expected results
    val expected1 = UnrefinedVulnerabilitySummariesData.unrefined1
    val expected2 = UnrefinedVulnerabilitySummariesData.unrefined2
    val expected3 = UnrefinedVulnerabilitySummariesData.unrefined3

    //test
    "Transform raw XRAY reports into UnrefinedVulnerabilitySummaries, and default to issueID if no CVEid exists" in new Setup {
      repository.collection.insertMany(Seq(report1, report2, report3)).toFuture().futureValue

      val result = repository.getNewDistinctVulnerabilities().futureValue
      val resSorted = result.map(res => res.copy(occurrences = res.occurrences.sortBy(_.path))).sortBy(_.id)

      resSorted.length shouldBe 3
      resSorted should contain theSameElementsInOrderAs (Seq(expected1, expected2, expected3))
    }

    "Transform reports generated up to data.transformation-cutoff, but not reports generated after the data.transformation-cutoff" in new Setup {
      repository.collection.insertMany(Seq(report1, report2, report3, report4, report5)).toFuture().futureValue

      val result = repository.getNewDistinctVulnerabilities().futureValue
      val resSorted = result.map(res => res.id).sorted

      resSorted.length shouldBe 4
      resSorted shouldBe (Seq("CVE-2021-99999", "CVE-2022-12345", "XRAY-000004", "XRAY-000006"))
    }

  }

  "getReportsInLastXDays" should {
    "Only return reports generated within the data.refresh-cutoff" in new Setup {
      val rep6 = report5.copy(generatedDate = now.minus(configuration.dataRefreshCutoff.toMillis.toInt, ChronoUnit.MILLIS).plus(5, ChronoUnit.MINUTES))
      val rep7 = report5.copy(generatedDate = now.minus(configuration.dataRefreshCutoff.toMillis.toInt, ChronoUnit.MILLIS))

      repository.collection.insertMany(Seq(rep6,rep7)).toFuture().futureValue

      val result = repository.getReportsInLastXDays().futureValue
      result.length shouldBe 1
      result should contain theSameElementsAs(Seq(rep6))
    }
  }

  "getTimelineData" should {
    "only return reports with a generatedDate equal to or after the passed in parameter" in new Setup {
      val rep1 = report5.copy(generatedDate = october)
      val rep2 = report5.copy(generatedDate = november)

      repository.collection.insertMany(Seq(rep1, rep2)).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(november).futureValue

      res.length shouldBe 1
      res.head.weekBeginning.toString should include ("2022-11")
    }

    "truncate Sunday to previous monday of week" in new Setup {
      val rep1 = report5.copy(generatedDate = Instant.parse("2022-12-25T23:59:59.00Z"))

      repository.collection.insertOne(rep1).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(november).futureValue
      res.head.weekBeginning shouldBe Instant.parse("2022-12-19T00:00:00.00Z")
    }

    "truncate Monday to the start of the day" in new Setup {
      val rep2 = report5.copy(generatedDate = Instant.parse("2022-12-26T00:00:01.00Z"))

      repository.collection.insertOne(rep2).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(november).futureValue
      println(res)

      res.head.weekBeginning shouldBe Instant.parse("2022-12-26T00:00:00.00Z")
    }

    "parse issue id for vulnerabilities with AND without CVE ids" in new Setup {
      val rep1 = report1.copy(generatedDate = november)
      val rep2 = report3.copy(generatedDate = december)

      repository.collection.insertMany(Seq(rep1, rep2)).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(november).futureValue
      res.map(_.id) should contain theSameElementsAs Seq("CVE-2022-12345", "XRAY-000004")
    }

    "extract the serviceName from the path" in new Setup {
      val rep1 = report1.copy(generatedDate = november)
      val rep2 = report3.copy(generatedDate = december)

      repository.collection.insertMany(Seq(rep1, rep2)).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(november).futureValue
      res.map(_.service) should contain theSameElementsAs Seq("service1", "service4")
    }

    "de-dupe data for same service, service version AND vulnerability in the SAME time period (possible due to multiple occurrences in slug path, or multiple scans)" in new Setup {
      val rep1 = report1.copy(generatedDate = november)
      val rep2 = report1.copy(generatedDate = november)

      repository.collection.insertMany(Seq(rep1, rep2)).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(november).futureValue
      res.length shouldBe 1
    }

    "de-dupe data for same service AND vulnerability (but different service version) in the SAME time period" in new Setup {
      val rep1 = report1.copy(generatedDate = november, rows = report1.rows.map(_.copy(path = "test/slugs/service1/service1_1.0.5_0.0.1.tgz")))
      val rep2 = report1.copy(generatedDate = november)

      repository.collection.insertMany(Seq(rep1, rep2)).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(november).futureValue
      res.length shouldBe 1
    }

    "return multiple data points for the same service AND vulnerability in DIFFERENT time periods" in new Setup {
      val rep1 = report1.copy(generatedDate = december)
      val rep2 = report1.copy(generatedDate = november)

      repository.collection.insertMany(Seq(rep1, rep2)).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(november).futureValue
      res.length shouldBe 2
    }

    "default curationStatus to uncurated if the Vulnerability does not exist in the collecitons assessment" in new Setup {
      val rep1 = report5.copy(generatedDate = november, rows = report5.rows.map(_.copy(issueId = "XRAY2222"))) //this issueID is not in assessments collection

      repository.collection.insertOne(rep1).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(november).futureValue
      res.head.curationStatus shouldBe CurationStatus.Uncurated
    }

    "fully transform raw reports to vulnerability timeline data, in which the data is grouped by service AND issue AND weekBeginning" in new Setup {
      val rep1 = report1.copy(generatedDate = november)
      val rep2 = report2.copy(generatedDate = november) //contains two cves, so will create two vulnerabilities
      val rep3 = report3.copy(generatedDate = october) //should be omitted due to cutoff date
      val rep4 = report4.copy(generatedDate = december)
      val rep5 = report5.copy(generatedDate = december)
      val rep6 = report5.copy(generatedDate = december) //should be de-duped, XRAY-00006 should appear only once in results.

      repository.collection.insertMany(Seq(rep1, rep2, rep3, rep4, rep5, rep6)).toFuture().futureValue
      assessmentsCollection.insertMany(assessments).toFuture().futureValue

      val res = repository.getTimelineData(november).futureValue

      res.length shouldBe 5
      res should contain theSameElementsAs Seq(
        TimelineEvent(id = "CVE-2022-12345", service = "service1", weekBeginning = Instant.parse("2022-11-21T00:00:00.00Z"), teams = Seq(), curationStatus = NoActionRequired),
        TimelineEvent(id = "CVE-2021-99999", service = "service3", weekBeginning = Instant.parse("2022-11-21T00:00:00.00Z"), teams = Seq(), curationStatus = ActionRequired),
        TimelineEvent(id = "CVE-2022-12345", service = "service3", weekBeginning = Instant.parse("2022-11-21T00:00:00.00Z"), teams = Seq(), curationStatus = NoActionRequired),
        TimelineEvent(id = "XRAY-000005", service = "service5", weekBeginning = Instant.parse("2022-12-19T00:00:00.00Z"), teams = Seq(), curationStatus = InvestigationOngoing),
        TimelineEvent(id = "XRAY-000006", service = "service6", weekBeginning = Instant.parse("2022-12-19T00:00:00.00Z"), teams = Seq(), curationStatus = Uncurated),
      )
    }
  }

  trait Setup {

    val october  = Instant.ofEpochSecond(1666346891)
    val november = Instant.ofEpochSecond(1669025291)
    val december = Instant.ofEpochSecond(1671617291)

   val assessmentsCollection: MongoCollection[Assessment] = CollectionFactory.collection(mongoComponent.database, "assessments", Assessment.mongoFormat)
   lazy val assessments = Seq(
     Assessment(id = "CVE-2022-12345", assessment = "N/A", curationStatus = CurationStatus.NoActionRequired    , lastReviewed = october , ticket = "BDOG-1"),
     Assessment(id = "CVE-2021-99999", assessment = "N/A", curationStatus = CurationStatus.ActionRequired      , lastReviewed = november, ticket = "BDOG-2"),
     Assessment(id = "XRAY-000004"   , assessment = "N/A", curationStatus = CurationStatus.NoActionRequired    , lastReviewed = november, ticket = "BDOG-3"),
     Assessment(id = "XRAY-000005"   , assessment = "N/A", curationStatus = CurationStatus.InvestigationOngoing, lastReviewed = december, ticket = "BDOG-3"),
     Assessment(id = "XRAY-000006"   , assessment = "N/A", curationStatus = CurationStatus.Uncurated           , lastReviewed = december, ticket = "BDOG-3")
   )

   lazy val report1: Report =
      Report(
        rows = Seq(
          RawVulnerability(
            cves                  = Seq(CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
            cvss3MaxScore         = Some(8.0),
            summary               = "This is an exploit",
            severity              = "High",
            severitySource        = "Source",
            vulnerableComponent   = "gav://com.testxml.test.core:test-bind:1.5.9",
            componentPhysicalPath = "service1-1.0.4/some/physical/path",
            impactedArtifact      = "fooBar",
            impactPath            = Seq("hello", "world"),
            path                  = "test/slugs/service1/service1_1.0.4_0.0.1.tgz",
            fixedVersions         = Seq("1.6.0"),
            published             = now.minus(14, ChronoUnit.DAYS),
            artifactScanTime      = now.minus(1, ChronoUnit.HOURS),
            issueId               = "XRAY-000003",
            packageType           = "maven",
            provider              = "test",
            description           = "This is an exploit",
            references            = Seq("foo.com", "bar.net"),
            projectKeys           = Seq()
        )),
        generatedDate = now
      )

    lazy val report2: Report =
      Report(
        rows = Seq(
          RawVulnerability(
            cves                  = Seq(CVE(cveId = Some("CVE-2021-99999"), cveV3Score = Some(7.0), cveV3Vector = Some("test2"))),
            cvss3MaxScore         = Some(7.0),
            summary               = "This is an exploit",
            severity              = "High",
            severitySource        = "Source",
            vulnerableComponent   = "gav://com.testxml.test.core:test-bind:1.6.8",
            componentPhysicalPath = "service3-3.0.4/some/physical/path",
            impactedArtifact      = "fooBar",
            impactPath            = Seq("hello", "world"),
            path                  = "test/slugs/service3/service3_3.0.4_0.0.1.tgz",
            fixedVersions         = Seq("1.6.9"),
            published             = now.minus(14, ChronoUnit.DAYS),
            artifactScanTime      = now.minus(1, ChronoUnit.HOURS),
            issueId               = "XRAY-000002",
            packageType           = "maven",
            provider              = "test",
            description           = "This is an exploit",
            references            = Seq("foo.com", "bar.net"),
            projectKeys           = Seq()
          ),
          RawVulnerability(
            cves                  = Seq(CVE(cveId = Some("CVE-2022-12345"), cveV3Score = Some(8.0), cveV3Vector = Some("test"))),
            cvss3MaxScore         = Some(8.0),
            summary               = "This is an exploit",
            severity              = "High",
            severitySource        = "Source",
            vulnerableComponent   = "gav://com.testxml.test.core:test-bind:1.5.9",
            componentPhysicalPath = "service3-3.0.4/some/physical/path",
            impactedArtifact      = "fooBar",
            impactPath            = Seq("hello", "world"),
            path                  = "test/slugs/service3/service3_3.0.4_0.0.1.tgz",
            fixedVersions         = Seq("1.6.0"),
            published             = now.minus(14, ChronoUnit.DAYS),
            artifactScanTime      = now.minus(1, ChronoUnit.HOURS),
            issueId               = "XRAY-000003",
            packageType           = "maven",
            provider              = "test",
            description           = "This is an exploit",
            references            = Seq("foo.com", "bar.net"),
            projectKeys           = Seq()
          )
        ),
        generatedDate = now
      )

    lazy val report3: Report =
      Report(
        rows = Seq(
          RawVulnerability(
            cves                  = Seq(CVE(cveId = None, cveV3Score = None, cveV3Vector = None)),
            cvss3MaxScore         = None,
            summary               = "This is an exploit",
            severity              = "High",
            severitySource        = "Source",
            vulnerableComponent   = "gav://com.testxml.test.core:test-bind:1.8.0",
            componentPhysicalPath = "service4-4.0.4/some/physical/path",
            impactedArtifact      = "fooBar",
            impactPath            = Seq("hello", "world"),
            path                  = "test/slugs/service4/service4_4.0.4_0.0.1.tgz",
            fixedVersions         = Seq("1.8.1"),
            published             = now.minus(14, ChronoUnit.DAYS).truncatedTo(ChronoUnit.MILLIS),
            artifactScanTime      = now.minus(1, ChronoUnit.HOURS).truncatedTo(ChronoUnit.MILLIS),
            issueId               = "XRAY-000004",
            packageType           = "maven",
            provider              = "test",
            description           = "This is an exploit",
            references            = Seq("foo.com", "bar.net"),
            projectKeys           = Seq()
          )),
        generatedDate = now
      )

    lazy val report4: Report =
      Report(
        rows = Seq(
          RawVulnerability(
            cves                  = Seq(CVE(cveId = None, cveV3Score = None, cveV3Vector = None)),
            cvss3MaxScore         = None,
            summary               = "This is an exploit",
            severity              = "High",
            severitySource        = "Source",
            vulnerableComponent   = "gav://com.testxml.test.core:test-bind:1.9.0",
            componentPhysicalPath = "service5-5.0.4/some/physical/path",
            impactedArtifact      = "fooBar",
            impactPath            = Seq("hello", "world"),
            path                  = "test/slugs/service5/service5_5.0.4_0.0.1.tgz",
            fixedVersions         = Seq("1.8.1"),
            published             = now.minus(14, ChronoUnit.DAYS),
            artifactScanTime      = now.minus(1, ChronoUnit.HOURS),
            issueId               = "XRAY-000005",
            packageType           = "maven",
            provider              = "test",
            description           = "This is an exploit",
            references            = Seq("foo.com", "bar.net"),
            projectKeys           = Seq()
          )),
        generatedDate = now
          .minus(configuration.dataTransformationCutoff.toMillis.toInt, ChronoUnit.DAYS)
      )

    lazy val report5: Report =
      Report(
        rows = Seq(
          RawVulnerability(
            cves                  = Seq(CVE(cveId = None, cveV3Score = None, cveV3Vector = None)),
            cvss3MaxScore         = None,
            summary               = "This is an exploit",
            severity              = "High",
            severitySource        = "Source",
            vulnerableComponent   = "gav://com.testxml.test.core:test-bind:1.9.0",
            componentPhysicalPath = "service6-6.0.4/some/physical/path",
            impactedArtifact      = "fooBar",
            impactPath            = Seq("hello", "world"),
            path                  = "test/slugs/service6/service6_5.0.4_0.0.1.tgz",
            fixedVersions         = Seq("1.8.1"),
            published             = now.minus(14, ChronoUnit.DAYS),
            artifactScanTime      = now.minus(1, ChronoUnit.HOURS),
            issueId               = "XRAY-000006",
            packageType           = "maven",
            provider              = "test",
            description           = "This is an exploit",
            references            = Seq("foo.com", "bar.net"),
            projectKeys           = Seq()
          )),
        generatedDate = now
          .minus(configuration.dataTransformationCutoff.toMillis.toInt, ChronoUnit.MILLIS)
          .plus(5, ChronoUnit.MINUTES)
      )
  }
}
