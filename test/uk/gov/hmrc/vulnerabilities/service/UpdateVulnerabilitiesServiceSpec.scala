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

import org.mockito.ArgumentMatchers.any
import org.mockito.MockitoSugar.{mock, verify, when}
import org.scalatest.concurrent.{ScalaFutures, IntegrationPatience}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.vulnerabilities.connectors.{ReleasesConnector, TeamsAndRepositoriesConnector}
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.persistence.{AssessmentsRepository, RawReportsRepository, VulnerabilityAgeRepository, VulnerabilitySummariesRepository}
import uk.gov.hmrc.vulnerabilities.utils.Assessment

import java.time.Instant
import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

class UpdateVulnerabilitiesServiceSpec
  extends AnyWordSpec
    with Matchers
    with ScalaFutures
    with IntegrationPatience {


  private implicit val hc: HeaderCarrier = HeaderCarrier()

  //Note - the 'main' updateVulnerabilitySummaries private method is exercised by the integration tests.

  "updateVulnerabilities" should {
    "attempt to process the Xray report for the requested service & version only" in new Setup {

      when(rawReportsRepository.getNewDistinctVulnerabilities()).thenReturn(
        Future.successful(Seq(
          UnrefinedVulnerabilitySummary(
            distinctVulnerability = UnrefinedDistinctVulnerability(
              vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.5.9",
              description         = "serious bug",
              fixedVersions       = Some(Seq("4.0")),
              references          = Seq("reference1"),
              publishedDate       = now
            ),
            occurrences = Seq(
              UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.5.9", path = "test/slugs/service1/service1_0.9_0.0.1.tgz", componentPhysicalPath = "service1-0.9/some/physical/path"),
              UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.5.9", path = "test/slugs/service1/service1_0.8_0.0.1.tgz", componentPhysicalPath = "service1-0.8/some/physical/path"),
              UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.5.9", path = "test/slugs/service2/service2_2.0_0.0.1.tgz", componentPhysicalPath = "service2-2.0/some/physical/path"),
            ),
            id            = "CVE-1",
            generatedDate = now,
            score         = Some(10.0)
          )
        ))
      )

     when(vulnerabilityAgeRepository.filterById("CVE-1")).thenReturn(
       Future.successful(Seq(
         VulnerabilityAge(
           service = "service2", vulnerabilityId = "CVE-1", firstScanned = now
         )
       ))
     )

      service.updateVulnerabilities(serviceName = "service2", version = "2.0", environment = "production").futureValue

      verify(xrayService).processReports(Seq(ServiceVersionDeployments(serviceName = "service2", version = "2.0", environments = Seq("production"))))
    }

   "remove integration & development Deployments transform the reports into VulnerabilitySummaries " +
     "and insert them into the VulnerabilitySummariesRepository" in new Setup {

     when(rawReportsRepository.getNewDistinctVulnerabilities()).thenReturn(
       Future.successful(Seq(
         UnrefinedVulnerabilitySummary(
           distinctVulnerability = UnrefinedDistinctVulnerability(
             vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.5.9",
             description         = "serious bug",
             fixedVersions       = Some(Seq("4.0")),
             references          = Seq("reference1"),
             publishedDate       = now
           ),
           occurrences = Seq(
             UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.5.9", path = "test/slugs/service1/service1_0.9_0.0.1.tgz", componentPhysicalPath = "service1-0.9/some/physical/path"),
             UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.5.9", path = "test/slugs/service1/service1_0.8_0.0.1.tgz", componentPhysicalPath = "service1-0.8/some/physical/path"),
             UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.5.9", path = "test/slugs/service2/service2_2.0_0.0.1.tgz", componentPhysicalPath = "service2-2.0/some/physical/path"),
           ),
           id            = "CVE-1",
           generatedDate = now,
           score         = Some(10.0)
         )
       ))
     )

     when(vulnerabilityAgeRepository.insertNonExisting(any[Seq[VulnerabilityAge]])).thenReturn(
       Future.successful(Seq.empty)
     )

     when(vulnerabilityAgeRepository.filterById("CVE-1")).thenReturn(
       Future.successful(Seq(
         VulnerabilityAge(
           service = "service1", vulnerabilityId = "CVE-1", firstScanned = now
         )
       ))
     )

     service.updateVulnerabilities(serviceName = "service2", version = "2.0", environment = "production").futureValue

     verify(vulnerabilitiesSummariesRepository).deleteOldAndInsertNewSummaries(
       Seq(
         VulnerabilitySummary(
           DistinctVulnerability(
             vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
             vulnerableComponentVersion = "1.5.9",
             vulnerableComponents       = Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind", "1.5.9")),
             id                         = "CVE-1",
             score                      = Some(10.0),
             description                = "serious bug",
             fixedVersions              = Some(Seq("4.0")),
             references                 = Seq("reference1"),
             publishedDate              = now,
             firstDetected              = Some(now),
             assessment                 = Some("must fix"),
             curationStatus             = Some(CurationStatus.ActionRequired),
             ticket                     = Some("BDOG-1")
           ),
           occurrences = Seq(
             VulnerabilityOccurrence(
               service                    = "service1",
               serviceVersion             = "0.8",
               componentPathInSlug        = "service1-0.8/some/physical/path",
               teams                      = Seq("team1", "teamA"),
               envs                       = Seq("staging"),
               vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
               vulnerableComponentVersion = "1.5.9"),
             VulnerabilityOccurrence(
               service                    = "service1",
               serviceVersion             = "0.9",
               componentPathInSlug        = "service1-0.9/some/physical/path",
               teams                      = Seq("team1", "teamA"),
               envs                       = Seq("qa"),
               vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
               vulnerableComponentVersion = "1.5.9"),
             VulnerabilityOccurrence(
               service                    = "service2",
               serviceVersion             = "2.0",
               componentPathInSlug        = "service2-2.0/some/physical/path",
               teams                      = Seq("team2"),
               envs                       = Seq("production", "staging"),
               vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
               vulnerableComponentVersion = "1.5.9"),
           ),
           teams         = List("team1", "team2", "teamA"),
           generatedDate = now
         )
       ),
       Seq(
         ServiceVersionDeployments("service1","0.8",List("staging")),
         ServiceVersionDeployments("service1","0.9",List("qa")),
         ServiceVersionDeployments("service2","2.0",List("production", "staging")))
     )
   }

   }

 "updateAllVulnerabilities" should {
   "attempt to process XrayReports only for serviceVersionDeployments that don't have a `recent` report" in new Setup {

     when(rawReportsRepository.getNewDistinctVulnerabilities()).thenReturn(
       Future.successful(Seq.empty[UnrefinedVulnerabilitySummary])
     )

     when(vulnerabilityAgeRepository.insertNonExisting(any[Seq[VulnerabilityAge]])).thenReturn(
       Future.successful(Seq.empty)
     )

     when(rawReportsRepository.getReportsInLastXDays()).thenReturn(
       Future.successful(
         Seq(
           Report(
             rows = Seq(RawVulnerability(
               cves                  = Seq(CVE(cveId = Some("CVE-2"), cveV3Score = Some(6.0), cveV3Vector = None)),
               cvss3MaxScore         = Some(6.0),
               summary               = "",
               severity              = "",
               severitySource        = "",
               vulnerableComponent   = "",
               componentPhysicalPath = "",
               impactedArtifact      = "",
               impactPath            = Seq(""),
               path                  = "test/slugs/service2/service2_2.0_0.0.1.tgz",
               fixedVersions         = Seq(""),
               published             = now.minus(5, ChronoUnit.MINUTES),
               artifactScanTime      = now.minus(5, ChronoUnit.MINUTES),
               issueId               = "CVE-2",
               packageType           = "",
               provider              = "",
               description           = "",
               references            = Seq(""),
               projectKeys           = Seq("")
             )),
             generatedDate = now.minus(5, ChronoUnit.MINUTES)
           )
         )
       )
     )

     service.updateAllVulnerabilities().futureValue

     //Only download xray report for the SVDs that don't have a recent report (so not service2 - 2.0)
     verify(xrayService).processReports(Seq(
       ServiceVersionDeployments(serviceName = "service1", version = "0.8", environments = Seq("staging")),
       ServiceVersionDeployments(serviceName = "service1", version = "0.9", environments = Seq("qa")),
     ))
   }

   "Attempt to process Xray reports for serviceVersionDeployments that have EITHER a common serviceName OR serviceVersion with a recent report," +
     " but not BOTH." in new Setup {
     when(rawReportsRepository.getNewDistinctVulnerabilities()).thenReturn(
       Future.successful(Seq.empty[UnrefinedVulnerabilitySummary])
     )

     when(vulnerabilityAgeRepository.insertNonExisting(any[Seq[VulnerabilityAge]])).thenReturn(
       Future.successful(Seq.empty)
     )

     when(vulnerabilityAgeRepository.filterById(any[String])).thenReturn(
       Future.successful(Seq.empty[VulnerabilityAge])
     )

     when(rawReportsRepository.getReportsInLastXDays()).thenReturn(
       Future.successful(
         Seq(
           Report(
             rows = Seq(RawVulnerability(
               cves                  = Seq(CVE(cveId = Some("CVE-2"), cveV3Score = Some(6.0), cveV3Vector = None)),
               cvss3MaxScore         = Some(6.0),
               summary               = "",
               severity              = "",
               severitySource        = "",
               vulnerableComponent   = "",
               componentPhysicalPath = "",
               impactedArtifact      = "",
               impactPath            = Seq(""),
               path                  = "test/slugs/service2/service2_3.0_0.0.1.tgz",
               fixedVersions         = Seq(""),
               published             = now.minus(5, ChronoUnit.MINUTES),
               artifactScanTime      = now.minus(5, ChronoUnit.MINUTES),
               issueId               = "CVE-2",
               packageType           = "",
               provider              = "",
               description           = "",
               references            = Seq(""),
               projectKeys           = Seq("")
             )),
             generatedDate = now.minus(5, ChronoUnit.MINUTES)
           ),
           Report(
             rows = Seq(RawVulnerability(
               cves                  = Seq(CVE(cveId = Some("CVE-1"), cveV3Score = Some(10.0), cveV3Vector = None)),
               cvss3MaxScore         = Some(10.0),
               summary               = "",
               severity              = "",
               severitySource        = "",
               vulnerableComponent   = "",
               componentPhysicalPath = "",
               impactedArtifact      = "",
               impactPath            = Seq(""),
               path                  = "test/slugs/service2/service3_0.8_0.0.1.tgz",
               fixedVersions         = Seq(""),
               published             = now.minus(5, ChronoUnit.MINUTES),
               artifactScanTime      = now.minus(5, ChronoUnit.MINUTES),
               issueId               = "CVE-1",
               packageType           = "",
               provider              = "",
               description           = "",
               references            = Seq(""),
               projectKeys           = Seq("")
             )),
             generatedDate = now.minus(5, ChronoUnit.MINUTES)
           ),
           Report( //serviceName and serviceVersion match SVD, so shouldn't get a new report)
             rows = Seq(RawVulnerability(
               cves                  = Seq(CVE(cveId = Some("CVE-1"), cveV3Score = Some(10.0), cveV3Vector = None)),
               cvss3MaxScore         = Some(10.0),
               summary               = "",
               severity              = "",
               severitySource        = "",
               vulnerableComponent   = "",
               componentPhysicalPath = "",
               impactedArtifact      = "",
               impactPath            = Seq(""),
               path                  = "test/slugs/service1/service1_0.9_0.0.1.tgz",
               fixedVersions         = Seq(""),
               published             = now.minus(5, ChronoUnit.MINUTES),
               artifactScanTime      = now.minus(5, ChronoUnit.MINUTES),
               issueId               = "CVE-2",
               packageType           = "",
               provider              = "",
               description           = "",
               references            = Seq(""),
               projectKeys           = Seq("")
             )),
             generatedDate = now.minus(5, ChronoUnit.MINUTES)
           )
         )
       )
     )

     service.updateAllVulnerabilities().futureValue

     verify(xrayService).processReports(Seq(
       ServiceVersionDeployments(serviceName = "service1", version = "0.8", environments = Seq("staging")),
       ServiceVersionDeployments(serviceName = "service2", version = "2.0", environments = Seq("production", "staging")),
     ))
   }

   "remove integration & development Deployments, transform the reports into VulnerabilitySummaries " +
     "and insert them into the VulnerabilitySummariesRepository" in new Setup {

     when(rawReportsRepository.getNewDistinctVulnerabilities()).thenReturn(
       Future.successful(Seq(
         UnrefinedVulnerabilitySummary(
           distinctVulnerability = UnrefinedDistinctVulnerability(
             vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.5.9",
             description         = "serious bug",
             fixedVersions       = Some(Seq("4.0")),
             references          = Seq("reference1"),
             publishedDate       = now
           ),
           occurrences = Seq(
             UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.5.9", path = "test/slugs/service1/service1_0.9_0.0.1.tgz", componentPhysicalPath = "service1-0.9/some/physical/path"),
             UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.5.9", path = "test/slugs/service1/service1_0.8_0.0.1.tgz", componentPhysicalPath = "service1-0.8/some/physical/path"),
             UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.5.9", path = "test/slugs/service2/service2_2.0_0.0.1.tgz", componentPhysicalPath = "service2-2.0/some/physical/path"),
           ),
           id            = "CVE-1",
           generatedDate = now,
           score         = Some(10.0)
         ),
         UnrefinedVulnerabilitySummary(
           distinctVulnerability = UnrefinedDistinctVulnerability(
             vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.6.0",
             description         = "moderate bug",
             fixedVersions       = Some(Seq("3.0")),
             references          = Seq("reference2"),
             publishedDate       = now
           ),
           occurrences = Seq(
             UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.6.0", path = "test/slugs/service1/service1_0.9_0.0.1.tgz", componentPhysicalPath = "service1-0.9/some/physical/path"),
             UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.6.0", path = "test/slugs/service2/service2_2.0_0.0.1.tgz", componentPhysicalPath = "service2-2.0/some/physical/path"),
           ),
           id            = "CVE-2",
           generatedDate = now,
           score         = Some(6.0)
         ),
         UnrefinedVulnerabilitySummary(
           distinctVulnerability = UnrefinedDistinctVulnerability(
             vulnerableComponent = "gav://com.testxml.test.core:test-bind:1.6.1",
             description         = "bug",
             fixedVersions       = Some(Seq("5.0")),
             references          = Seq("reference3"),
             publishedDate       = now
           ),
           occurrences = Seq(
             UnrefinedVulnerabilityOccurrence(vulnComponent = "gav://com.testxml.test.core:test-bind:1.6.1", path = "test/slugs/service1/service1_0.9_0.0.1.tgz", componentPhysicalPath = "service1-0.9/some/physical/path"),
           ),
           id            = "CVE-3",
           generatedDate = now,
           score         = Some(8.0)
         )
       ))
     )

     when(rawReportsRepository.getReportsInLastXDays()).thenReturn(
       Future.successful(Seq.empty[Report])
     )

     when(vulnerabilityAgeRepository.insertNonExisting(any[Seq[VulnerabilityAge]])).thenReturn(
       Future.successful(Seq.empty)
     )

     when(vulnerabilityAgeRepository.filterById(any[String])).thenReturn(
       Future.successful(Seq(
         VulnerabilityAge(
           service = "service1", vulnerabilityId = "CVE-1", firstScanned = now
         )
       ))
     )

     service.updateAllVulnerabilities().futureValue

     verify(vulnerabilitiesSummariesRepository).deleteOldAndInsertNewSummaries(
       Seq(
         VulnerabilitySummary(
           DistinctVulnerability(
             vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
             vulnerableComponentVersion = "1.5.9",
             vulnerableComponents       = Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind", "1.5.9")),
             id                         = "CVE-1",
             score                      = Some(10.0),
             description                = "serious bug",
             fixedVersions              = Some(Seq("4.0")),
             references                 = Seq("reference1"),
             publishedDate              = now,
             firstDetected              = Some(now),
             assessment                 = Some("must fix"),
             curationStatus             = Some(CurationStatus.ActionRequired),
             ticket                     = Some("BDOG-1")
           ),
           occurrences = Seq(
             VulnerabilityOccurrence(
               service                    = "service1",
               serviceVersion             = "0.8",
               componentPathInSlug        = "service1-0.8/some/physical/path",
               teams                      = Seq("team1", "teamA"),
               envs                       = Seq("staging"),
               vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
               vulnerableComponentVersion = "1.5.9"),
             VulnerabilityOccurrence(
               service                    = "service1",
               serviceVersion             = "0.9",
               componentPathInSlug        = "service1-0.9/some/physical/path",
               teams                      = Seq("team1", "teamA"),
               envs                       = Seq("qa"),
               vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
               vulnerableComponentVersion = "1.5.9"),
             VulnerabilityOccurrence(
               service                    = "service2",
               serviceVersion             = "2.0",
               componentPathInSlug        = "service2-2.0/some/physical/path",
               teams = Seq("team2"), envs = Seq("production", "staging"),
               vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
               vulnerableComponentVersion = "1.5.9"),
           ),
           teams         = List("team1", "team2", "teamA"),
           generatedDate = now
         ),
         VulnerabilitySummary(
           DistinctVulnerability(
             vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
             vulnerableComponentVersion = "1.6.0",
             vulnerableComponents       = Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind", "1.6.0")),
             id                         = "CVE-2",
             score                      = Some(6.0),
             description                = "moderate bug",
             fixedVersions              = Some(Seq("3.0")),
             references                 = Seq("reference2"),
             publishedDate              = now,
             firstDetected              = Some(now),
             assessment                 = None,
             curationStatus             = Some(CurationStatus.Uncurated),
             ticket                     = None
           ),
           occurrences = Seq(
             VulnerabilityOccurrence(
               service                    = "service1",
               serviceVersion             = "0.9",
               componentPathInSlug        = "service1-0.9/some/physical/path",
               teams                      = Seq("team1", "teamA"),
               envs                       = Seq("qa"),
               vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
               vulnerableComponentVersion = "1.6.0"),
             VulnerabilityOccurrence(
               service                    = "service2",
               serviceVersion             = "2.0",
               componentPathInSlug        = "service2-2.0/some/physical/path",
               teams                      = Seq("team2"),
               envs                       = Seq("production", "staging"),
               vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
               vulnerableComponentVersion = "1.6.0"),
           ),
           teams         = List("team1", "team2", "teamA"),
           generatedDate = now
         ),
         VulnerabilitySummary(
           DistinctVulnerability(
             vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
             vulnerableComponentVersion = "1.6.1",
             vulnerableComponents       = Seq(VulnerableComponent("gav://com.testxml.test.core:test-bind", "1.6.1")),
             id                         = "CVE-3",
             score                      = Some(8.0),
             description                = "bug",
             fixedVersions              = Some(Seq("5.0")),
             references                 = Seq("reference3"),
             publishedDate              = now,
             firstDetected              = Some(now),
             assessment                 = Some("fix"),
             curationStatus             = Some(CurationStatus.NoActionRequired),
             ticket                     = None  //Whitespace should default to none
           ),
           occurrences = Seq(
             VulnerabilityOccurrence(
               service                    = "service1",
               serviceVersion             = "0.9",
               componentPathInSlug        = "service1-0.9/some/physical/path",
               teams                      = Seq("team1", "teamA"),
               envs                       = Seq("qa"),
               vulnerableComponentName    = "gav://com.testxml.test.core:test-bind",
               vulnerableComponentVersion = "1.6.1"
             ),
           ),
           teams         = List("team1", "teamA"),
           generatedDate = now
         )
       ),
       Seq(
         ServiceVersionDeployments("service1","0.8",List("staging")),
         ServiceVersionDeployments("service1","0.9",List("qa")),
         ServiceVersionDeployments("service2","2.0",List("production", "staging")))
     )
   }

//   "transform raw reports into VulnerabilityAges and insert them into the VulnerabilityAgeRepository" in new Setup {
//
//     when(rawReportsRepository.getNewDistinctVulnerabilities()).thenReturn(
//       Future.successful(Seq.empty[UnrefinedVulnerabilitySummary])
//     )
//
//     when(rawReportsRepository.getReportsInLastXDays()).thenReturn(
//       Future.successful(
//         Seq(
//           Report(
//             rows = Seq(RawVulnerability(
//               cves                  = Seq(CVE(cveId = Some("CVE-1"), cveV3Score = Some(6.0), cveV3Vector = None)),
//               cvss3MaxScore         = Some(6.0),
//               summary               = "",
//               severity              = "",
//               severitySource        = "",
//               vulnerableComponent   = "",
//               componentPhysicalPath = "",
//               impactedArtifact      = "",
//               impactPath            = Seq(""),
//               path                  = "test/slugs/service1/service1_3.0_0.0.1.tgz",
//               fixedVersions         = Seq(""),
//               published             = now.minus(5,  ChronoUnit.MINUTES),
//               artifactScanTime      = now.minus(10, ChronoUnit.MINUTES),
//               issueId               = "CVE-1",
//               packageType           = "",
//               provider              = "",
//               description           = "",
//               references            = Seq(""),
//               projectKeys           = Seq("")
//             )),
//             generatedDate = now.minus(5, ChronoUnit.MINUTES)
//           ),
//           Report(
//             rows = Seq(RawVulnerability(
//               cves                  = Seq(CVE(cveId = Some("CVE-1"), cveV3Score = Some(6.0), cveV3Vector = None)),
//               cvss3MaxScore         = Some(6.0),
//               summary               = "",
//               severity              = "",
//               severitySource        = "",
//               vulnerableComponent   = "",
//               componentPhysicalPath = "",
//               impactedArtifact      = "",
//               impactPath            = Seq(""),
//               path                  = "test/slugs/service1/service1_3.0_0.0.2.tgz",
//               fixedVersions         = Seq(""),
//               published             = now.minus(5, ChronoUnit.MINUTES),
//               artifactScanTime      = now.minus(5, ChronoUnit.MINUTES),
//               issueId               = "CVE-1",
//               packageType           = "",
//               provider              = "",
//               description           = "",
//               references            = Seq(""),
//               projectKeys           = Seq("")
//             )),
//             generatedDate = now.minus(5, ChronoUnit.MINUTES)
//           ),
//           Report(
//             rows = Seq(RawVulnerability(
//               cves                  = Seq(CVE(cveId = Some("CVE-2"), cveV3Score = Some(10.0), cveV3Vector = None)),
//               cvss3MaxScore         = Some(10.0),
//               summary               = "",
//               severity              = "",
//               severitySource        = "",
//               vulnerableComponent   = "",
//               componentPhysicalPath = "",
//               impactedArtifact      = "",
//               impactPath            = Seq(""),
//               path                  = "test/slugs/service1/service1_0.9_0.0.1.tgz",
//               fixedVersions         = Seq(""),
//               published             = now.minus(5, ChronoUnit.MINUTES),
//               artifactScanTime      = now.minus(5, ChronoUnit.MINUTES),
//               issueId               = "CVE-2",
//               packageType           = "",
//               provider              = "",
//               description           = "",
//               references            = Seq(""),
//               projectKeys           = Seq("")
//             )),
//             generatedDate = now.minus(5, ChronoUnit.MINUTES)
//           )
//         )
//       )
//     )
//
//     verify(vulnerabilityAgeRepository).insertNonExisting(
//       Seq(
//         VulnerabilityAge(
//           service = "service1", vulnerabilityId = "CVE-1", firstScanned = now.minus(10, ChronoUnit.MINUTES)
//         ),
//         VulnerabilityAge(
//           service = "service1", vulnerabilityId = "CVE-2", firstScanned = now.minus(5, ChronoUnit.MINUTES)
//         )
//       )
//     )
//   }
//
//   "transform the raw reports into VulnerabilitySummaries with the earliest scanned platform date" in new Setup {
//
//   }
 }


    trait Setup {
      val now: Instant = Instant.now()

      val releasesConnector                  = mock[ReleasesConnector]
      val xrayService                        = mock[XrayService]
      val rawReportsRepository               = mock[RawReportsRepository]
      val vulnerabilityAgeRepository         = mock[VulnerabilityAgeRepository]
      val teamsAndRepositoriesConnector      = mock[TeamsAndRepositoriesConnector]
      val assessmentsRepository              = mock[AssessmentsRepository]
      val vulnerabilitiesSummariesRepository = mock [VulnerabilitySummariesRepository]

      val service = new UpdateVulnerabilitiesService(
        releasesConnector                = releasesConnector,
        teamsAndRepositoriesConnector    = teamsAndRepositoriesConnector,
        xrayService                      = xrayService,
        rawReportsRepository             = rawReportsRepository,
        vulnerabilityAgeRepository       = vulnerabilityAgeRepository,
        assessmentsRepository            = assessmentsRepository,
        vulnerabilitySummariesRepository = vulnerabilitiesSummariesRepository
      )

      when(releasesConnector.getCurrentReleases()(any[HeaderCarrier])).thenReturn(
        Future.successful(
          Seq(
            WhatsRunningWhere(serviceName = "service1",
              deployments = Seq(
                Deployment(environment = "integration", version = "1.0"),
                Deployment(environment = "development", version = "1.0"),
                Deployment(environment = "qa",          version = "0.9"),
                Deployment(environment = "staging",     version = "0.8"),
              )),
            WhatsRunningWhere(serviceName = "service2",
              deployments = Seq(
                Deployment(environment = "production", version = "2.0"),
                Deployment(environment = "staging",    version = "2.0")
              )),
            WhatsRunningWhere(serviceName = "service3",
              deployments = Seq(
                Deployment(environment = "integration", version = "3.0"),
                Deployment(environment = "development", version = "3.0"),
              ))
          ))
      )

      when(xrayService.deleteStaleReports()(any[HeaderCarrier])).thenReturn(Future.unit)


      when(xrayService.processReports(any[Seq[ServiceVersionDeployments]])(any[HeaderCarrier])).thenReturn(Future.unit)

      when(teamsAndRepositoriesConnector.getCurrentReleases()).thenReturn(
        Future.successful(
          Map("service1" -> Seq("team1", "teamA"), "service2" -> Seq("team2"))
        )
      )

      when(assessmentsRepository.getAssessments()).thenReturn(
        Future.successful(
          Seq(
            Assessment(
              id             = "CVE-1",
              assessment     = "must fix",
              curationStatus = CurationStatus.ActionRequired,
              lastReviewed   = now.minus(12, ChronoUnit.HOURS),
              ticket         = "BDOG-1"
            ),
            Assessment(
              id             = "CVE-3",
              assessment     = "fix",
              curationStatus = CurationStatus.NoActionRequired,
              lastReviewed   = now.minus(12, ChronoUnit.HOURS),
              ticket         = "         " //Tests that whitespace is transformed to a 'None'
            )
          )
        )
      )

      when(vulnerabilitiesSummariesRepository.deleteOldAndInsertNewSummaries(any[Seq[VulnerabilitySummary]], any[Seq[ServiceVersionDeployments]])).thenReturn(Future.successful(1))
    }
}

