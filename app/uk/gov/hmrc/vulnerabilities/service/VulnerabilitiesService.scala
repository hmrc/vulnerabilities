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

import uk.gov.hmrc.vulnerabilities.model.CurationStatus.{ActionRequired, InvestigationOngoing, NoActionRequired, Uncurated}
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitySummariesRepository
import uk.gov.hmrc.vulnerabilities.utils.Assessment

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class VulnerabilitiesService @Inject() (
 vulnerabilitySummariesRepository: VulnerabilitySummariesRepository
)(implicit val ec: ExecutionContext) {

  def countDistinctVulnerabilities(service: String): Future[Int] = {
    // adds quotes for regex exact match
    val serviceWithQuotes = Some(s"\"$service\"")
    vulnerabilitySummariesRepository
      .distinctVulnerabilitiesSummary(
        id             = None,
        curationStatus = Some(ActionRequired.asString),
        service        = serviceWithQuotes,
        team           = None,
        component      = None
      )
      .map(_.map(vs => vs.distinctVulnerability.id).toSet.size)
  }

  def distinctVulnerabilitiesSummary(
    vulnerability  : Option[String],
    curationStatus : Option[String],
    service        : Option[String],
    team           : Option[String],
    component      : Option[String]
  ): Future[Seq[VulnerabilitySummary]] =
    vulnerabilitySummariesRepository.distinctVulnerabilitiesSummary(vulnerability, curationStatus, service, team, component)

  def vulnerabilitiesCountPerService(service: Option[String], team: Option[String], environment: Option[Environment]): Future[Seq[TotalVulnerabilityCount]] =
    vulnerabilitySummariesRepository.vulnerabilitiesCount(service, team, environment).map(totalCountsPerService)

  def totalCountsPerService(filteredCounts: Seq[VulnerabilityCount]): Seq[TotalVulnerabilityCount] =
    filteredCounts.foldLeft(Map.empty[String, TotalVulnerabilityCount])((acc, cur) => {
      val record        = acc.getOrElse(cur.service, TotalVulnerabilityCount(cur.service, 0, 0, 0, 0))
      val updatedRecord = cur.curationStatus match {
                            case ActionRequired       => record.copy(actionRequired       = record.actionRequired + cur.count)
                            case NoActionRequired     => record.copy(noActionRequired     = record.noActionRequired + cur.count)
                            case InvestigationOngoing => record.copy(investigationOngoing = record.investigationOngoing + cur.count)
                            case Uncurated            => record.copy(uncurated            = record.investigationOngoing + cur.count)
                          }
      acc + (cur.service -> updatedRecord)
    }).values.toSeq.sortBy(_.service)
}
