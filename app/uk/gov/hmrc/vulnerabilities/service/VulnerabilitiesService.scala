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

import uk.gov.hmrc.vulnerabilities.model.CurationStatus.{ActionRequired, Uncurated}
import uk.gov.hmrc.vulnerabilities.model.{CurationStatus, DistinctVulnerability, ServiceVersionDeployments, UnrefinedVulnerabilityOccurrence, UnrefinedVulnerabilitySummary, Vulnerability, VulnerabilityOccurrence, VulnerabilitySummary, VulnerableComponent, WhatsRunningWhere}
import uk.gov.hmrc.vulnerabilities.persistence.{VulnerabilitiesRepository, VulnerabilitySummariesRepository}
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
    vulnerabilitySummariesRepository.distinctVulnerabilitiesSummary(None, Some(ActionRequired.asString), serviceWithQuotes, None)
      .map(_.map(vs => vs.distinctVulnerability.id).toSet.size)
  }

  def distinctVulnerabilitiesSummary(vulnerability: Option[String], curationStatus: Option[String], service: Option[String], team: Option[String]): Future[Seq[VulnerabilitySummary]] = {
    vulnerabilitySummariesRepository.distinctVulnerabilitiesSummary(vulnerability, curationStatus, service, team)
  }

  def convertToVulnerabilitySummary(
    unrefined: Seq[UnrefinedVulnerabilitySummary],
    repoWithTeams: Map[String, Seq[String]],
    svds: Seq[ServiceVersionDeployments]
  ): Seq[VulnerabilitySummary] =
    unrefined.map{u =>
      val occs = u.occurrences.map{ occ =>
        val service = occ.path.split("/")(2)
        val serviceVersion = occ.path.split("_")(1)
        VulnerabilityOccurrence(
          service = service,
          serviceVersion = serviceVersion,
          componentPathInSlug = occ.componentPhysicalPath,
          teams = repoWithTeams.getOrElse(service, Seq.empty).sorted,
          envs = svds
            .find(s => s.serviceName == service && s.version == serviceVersion)
            .getOrElse(ServiceVersionDeployments("", "", Seq.empty))
            .environments,
          vulnerableComponentName = occ.vulnComponent.split(":").dropRight(1).mkString(":"),
          vulnerableComponentVersion = occ.vulnComponent.split(":").last
        )
      }

      VulnerabilitySummary(
        distinctVulnerability = DistinctVulnerability(
          vulnerableComponentName = occs.head.vulnerableComponentName,
          vulnerableComponentVersion = occs.head.vulnerableComponentVersion,
          vulnerableComponents = occs.map( o => VulnerableComponent(o.vulnerableComponentName, o.vulnerableComponentVersion)).distinct.sortBy(o => (o.component, o.version)),
          id = u.id,
          score = u.score,
          description = u.distinctVulnerability.description,
          fixedVersions = u.distinctVulnerability.fixedVersions,
          references = u.distinctVulnerability.references,
          publishedDate = u.distinctVulnerability.publishedDate,
          assessment = None,
          curationStatus = None,
          ticket = None,
        ),
        occurrences   = occs.sortBy(o => (o.service, o.serviceVersion)),
        teams         = occs.flatMap(_.teams).distinct.sorted,
        generatedDate = u.generatedDate
      )
    }


  def addInvestigationsToSummaries(summaries: Seq[VulnerabilitySummary], investigations: Map[String, Assessment]): Seq[VulnerabilitySummary] =
    summaries.map { vs =>
      investigations.get(vs.distinctVulnerability.id) match {
        case Some(inv) => vs.copy(distinctVulnerability = vs.distinctVulnerability
              .copy(assessment = Some(inv.assessment), curationStatus = Some(inv.curationStatus), ticket = Some(inv.ticket)
              ))
        case None => vs.copy(distinctVulnerability = vs.distinctVulnerability
            .copy(curationStatus = Some(Uncurated))
        )
      }
    }
}
