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
        version        = None,
        team           = None,
        component      = None
      )
      .map(_.map(vs => vs.distinctVulnerability.id).toSet.size)
  }

  def distinctVulnerabilitiesSummary(
    vulnerability  : Option[String],
    curationStatus : Option[String],
    service        : Option[String],
    version        : Option[Version],
    team           : Option[String],
    component      : Option[String]
  ): Future[Seq[VulnerabilitySummary]] =
    vulnerabilitySummariesRepository.distinctVulnerabilitiesSummary(vulnerability, curationStatus, service, version, team, component)

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

  def convertToVulnerabilitySummary(
    unrefined: Seq[UnrefinedVulnerabilitySummary],
    repoWithTeams: Map[String, Seq[String]],
    svds: Seq[ServiceVersionDeployments]
  ): Seq[VulnerabilitySummary] =
    unrefined.map { u =>
      val occs = u.occurrences.map { occ =>
        val service = occ.path.split("/")(2)
        val serviceVersion = occ.path.split("_")(1)
        VulnerabilityOccurrence(
          service                    = service,
          serviceVersion             = serviceVersion,
          componentPathInSlug        = occ.componentPhysicalPath,
          teams                      = repoWithTeams.getOrElse(service, Seq.empty).sorted,
          envs                       = svds
            .find(s => s.serviceName == service && s.version == serviceVersion)
            .getOrElse(ServiceVersionDeployments("", "", Seq.empty))
            .environments,
          vulnerableComponentName    = occ.vulnComponent.split(":").dropRight(1).mkString(":"),
          vulnerableComponentVersion = occ.vulnComponent.split(":").last
        )
      }

      VulnerabilitySummary(
        distinctVulnerability = DistinctVulnerability(
          vulnerableComponentName    = occs.head.vulnerableComponentName,
          vulnerableComponentVersion = occs.head.vulnerableComponentVersion,
          vulnerableComponents       = occs.map( o => VulnerableComponent(o.vulnerableComponentName, o.vulnerableComponentVersion)).distinct.sortBy(o => (o.component, o.version)),
          id                         = u.id,
          score                      = u.score,
          description                = u.distinctVulnerability.description,
          fixedVersions              = u.distinctVulnerability.fixedVersions,
          references                 = u.distinctVulnerability.references,
          publishedDate              = u.distinctVulnerability.publishedDate,
          assessment                 = None,
          curationStatus             = None,
          ticket                     = None,
        ),
        occurrences           = occs.sortBy(o => (o.service, o.serviceVersion)),
        teams                 = occs.flatMap(_.teams).distinct.sorted,
        generatedDate         = u.generatedDate
      )
    }


  def addInvestigationsToSummaries(summaries: Seq[VulnerabilitySummary], investigations: Map[String, Assessment]): Seq[VulnerabilitySummary] =
    summaries.map { vs =>
      investigations.get(vs.distinctVulnerability.id) match {
        case Some(inv) => vs.copy(distinctVulnerability =
                            vs.distinctVulnerability.copy(
                              assessment            = Some(inv.assessment),
                              curationStatus        = Some(inv.curationStatus),
                              ticket                = Some(inv.ticket.trim).filter(_.nonEmpty)
                            )
                          )
        case None => vs.copy(distinctVulnerability =
                        vs.distinctVulnerability.copy(curationStatus = Some(Uncurated)
                     )
        )
      }
    }
}
