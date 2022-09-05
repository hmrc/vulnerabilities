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

import uk.gov.hmrc.vulnerabilities.model.{DistinctVulnerability, Vulnerability, VulnerabilityCountSummary}
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitiesRepository

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class VulnerabilitiesService @Inject() (
  vulnerabilitiesRepository: VulnerabilitiesRepository
)(implicit val ec: ExecutionContext) {

  def allVulnerabilities(service: Option[String], id: Option[String], description: Option[String], team: Option[String]): Future[Seq[Vulnerability]] =
    vulnerabilitiesRepository.search(service, id, description, team)

  def distinctVulnerabilitiesSummary(vulnerability: Option[String], requiresActionOnly: Option[Boolean]): Future[Seq[VulnerabilityCountSummary]] =
    for {
      allVulns <- vulnerabilitiesRepository.search(service = None, id = vulnerability, description = None, team = None, requiresAction = requiresActionOnly )
      distinct = allVulns.groupBy(_.id)
      servicesPerVuln = distinct.view.mapValues(_.map(_.service)).toMap
      teamsPerVuln = distinct.view.mapValues(_.flatMap(_.teams.getOrElse(Seq())).distinct).toMap
      distinctWithServicesAndTeams = distinct.map(_._2.head).map(v => VulnerabilityCountSummary(
        DistinctVulnerability(v.vulnerableComponentName, v.vulnerableComponentVersion, v.id, v.score, v.description, v.references, v.publishedDate, v.requiresAction, v.assessment, v.lastReviewed),
        servicesPerVuln(v.id),
        teamsPerVuln(v.id)
      ))
    } yield distinctWithServicesAndTeams
      .toSeq
      .sortBy(_.distinctVulnerability.id)
}