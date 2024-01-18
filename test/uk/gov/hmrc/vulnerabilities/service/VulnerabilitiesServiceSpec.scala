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
import org.mockito.MockitoSugar.{mock, when}
import org.scalatest.concurrent.ScalaFutures
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import uk.gov.hmrc.vulnerabilities.model.CurationStatus.{ActionRequired, InvestigationOngoing, NoActionRequired}
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.persistence.{RawReportsRepository, VulnerabilitySummariesRepository}

import java.time.Instant
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future

class VulnerabilitiesServiceSpec extends AnyWordSpec with Matchers with ScalaFutures {

  "vulnerabilitiesService" when {
    "VulnerabilitiesService.totalCountsPerService" should {
      "sum the number of vulnerabilities for each curation status and return TotalVulnerabilityCount objects" in new Setup {

        val totalVulnerabilityCounts = Seq(
          TotalVulnerabilityCount("service-one", actionRequired = 40, noActionRequired = 20, investigationOngoing = 4, uncurated = 0),
          TotalVulnerabilityCount("service-two", actionRequired = 40, noActionRequired = 20, investigationOngoing = 0, uncurated = 0),
        )

        vulnerabilitiesService.totalCountsPerService(vulnerabilityCounts) shouldBe totalVulnerabilityCounts
      }
    }
    "VulnerabilitiesService.distinctVulnerabilitiesSummary" should {
      "return None if there is no raw reports data" when {
        "a service is specified" in new Setup {
          when(rawReportsRepository.vulnerabilitiesCount(any[String], any[Option[String]]))
            .thenReturn(Future.successful(None))

          val result = vulnerabilitiesService.distinctVulnerabilitiesSummary(
            vulnerability  = None,
            curationStatus = None,
            service        = Some("service"),
            version        = None,
            team           = None,
            component      = None,
          ).futureValue

          result shouldBe empty
        }
      }
      "return Some if there is raw reports data" when {
        "a service is specified" in new Setup {

          val result = vulnerabilitiesService.distinctVulnerabilitiesSummary(
            vulnerability  = None,
            curationStatus = None,
            service        = Some("service"),
            version        = None,
            team           = None,
            component      = None,
          ).futureValue

          result shouldBe defined
        }
      }
      "return ignore if there is no raw reports data" when {
        "a service is not specified" in new Setup {
          when(rawReportsRepository.vulnerabilitiesCount(any[String], any[Option[String]]))
            .thenReturn(Future.successful(None))

          val result = vulnerabilitiesService.distinctVulnerabilitiesSummary(
            vulnerability  = None,
            curationStatus = None,
            service        = None,
            version        = None,
            team           = None,
            component      = None,
          ).futureValue

          result shouldBe defined
        }
      }
    }
  }

  trait Setup {

    val vulnerabilitySummariesRepository: VulnerabilitySummariesRepository = mock[VulnerabilitySummariesRepository]
    val rawReportsRepository: RawReportsRepository                         = mock[RawReportsRepository]
    val vulnerabilitiesService: VulnerabilitiesService                     = new VulnerabilitiesService(
                                                                                vulnerabilitySummariesRepository,
                                                                                rawReportsRepository
                                                                              )

    when(vulnerabilitySummariesRepository.distinctVulnerabilitiesSummary(
        any[Option[String]],
        any[Option[String]],
        any[Option[String]],
        any[Option[Version]],
        any[Option[String]],
        any[Option[String]]
      ))
      .thenReturn(Future.successful(Seq(VulnerabilitySummary(
        distinctVulnerability= DistinctVulnerability(
          vulnerableComponentName   = "vulnerableComponentName",
          vulnerableComponentVersion= "vulnerableComponentVersion",
          vulnerableComponents      = Seq.empty,
          id                        = "id",
          score                     = None,
          description               = "description",
          fixedVersions             = None,
          references                = Seq.empty,
          publishedDate             = Instant.now,
          firstDetected             = None,
          assessment                = None,
          curationStatus            = None,
          ticket                    = None,
        ),
        occurrences          = Seq.empty,
        teams                = Seq.empty,
        generatedDate        = Instant.now
      ))))

    when(rawReportsRepository.vulnerabilitiesCount(any[String], any[Option[String]]))
      .thenReturn(Future.successful(Some(0)))

    val vulnerabilityCounts = Seq(
      VulnerabilityCount("service-one", "production",   ActionRequired, 10),
      VulnerabilityCount("service-one", "staging",      ActionRequired, 10),
      VulnerabilityCount("service-one", "qa",           ActionRequired, 10),
      VulnerabilityCount("service-one", "externalTest", ActionRequired, 10),

      VulnerabilityCount("service-two", "production",   ActionRequired, 10),
      VulnerabilityCount("service-two", "staging",      ActionRequired, 10),
      VulnerabilityCount("service-two", "qa",           ActionRequired, 10),
      VulnerabilityCount("service-two", "externalTest", ActionRequired, 10),

      VulnerabilityCount("service-one", "production",   NoActionRequired, 5),
      VulnerabilityCount("service-one", "staging",      NoActionRequired, 5),
      VulnerabilityCount("service-one", "qa",           NoActionRequired, 5),
      VulnerabilityCount("service-one", "externalTest", NoActionRequired, 5),

      VulnerabilityCount("service-two", "production",   NoActionRequired, 5),
      VulnerabilityCount("service-two", "staging",      NoActionRequired, 5),
      VulnerabilityCount("service-two", "qa",           NoActionRequired, 5),
      VulnerabilityCount("service-two", "externalTest", NoActionRequired, 5),

      VulnerabilityCount("service-one", "production",   InvestigationOngoing, 1),
      VulnerabilityCount("service-one", "staging",      InvestigationOngoing, 1),
      VulnerabilityCount("service-one", "qa",           InvestigationOngoing, 1),
      VulnerabilityCount("service-one", "externalTest", InvestigationOngoing, 1),

      VulnerabilityCount("service-two", "production",   InvestigationOngoing, 0),
      VulnerabilityCount("service-two", "staging",      InvestigationOngoing, 0),
      VulnerabilityCount("service-two", "qa",           InvestigationOngoing, 0),
      VulnerabilityCount("service-two", "externalTest", InvestigationOngoing, 0),
    )
  }
}
