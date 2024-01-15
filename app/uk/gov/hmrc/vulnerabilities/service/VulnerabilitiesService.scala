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

import cats.data.OptionT

import uk.gov.hmrc.vulnerabilities.model.CurationStatus.{ActionRequired, InvestigationOngoing, NoActionRequired, Uncurated}
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.persistence.{RawReportsRepository, VulnerabilitySummariesRepository}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class VulnerabilitiesService @Inject() (
 vulnerabilitySummariesRepository: VulnerabilitySummariesRepository,
 rawReportsRepository            : RawReportsRepository
)(implicit val ec: ExecutionContext) {

  def countDistinctVulnerabilities(service: String): Future[Option[Int]] = {
    distinctVulnerabilitiesSummary(None, Some(ActionRequired.asString), Some(service), None, None, None, exactMatch = true)
      .map(_.map(_.map(_.distinctVulnerability.id).distinct.size))
  }

  def distinctVulnerabilitiesSummary(
    vulnerability  : Option[String],
    curationStatus : Option[String],
    service        : Option[String],
    version        : Option[Version],
    team           : Option[String],
    component      : Option[String],
    exactMatch     : Boolean = false
  ): Future[Option[Seq[VulnerabilitySummary]]] =
    service.fold(
      vulnerabilitySummariesRepository.distinctVulnerabilitiesSummary(vulnerability, curationStatus, service, version, team, component).map(Option(_))
    )(s =>
      (for {
        count          <- OptionT(rawReportsRepository.vulnerabilitiesCount(s, version.map(_.original)))
        // adds quotes for regex exact match
        serviceQuery   = if (exactMatch)
          service.map(s => s"\"$s\"")
          else
            service
        distinctCount  <- if(count > 0) {
          OptionT.liftF(vulnerabilitySummariesRepository.distinctVulnerabilitiesSummary(vulnerability, curationStatus, serviceQuery, version, team, component))
          } else {
            OptionT.liftF(Future.successful(Seq.empty[VulnerabilitySummary]))
          }
      } yield distinctCount).value
    )

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
