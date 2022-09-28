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

import uk.gov.hmrc.vulnerabilities.model.CurationStatus.ActionRequired
import uk.gov.hmrc.vulnerabilities.model.{Vulnerability, VulnerabilitySummary}
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitiesRepository

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class VulnerabilitiesService @Inject() (
  vulnerabilitiesRepository: VulnerabilitiesRepository,
)(implicit val ec: ExecutionContext) {

  def allVulnerabilities(service: Option[String], id: Option[String], description: Option[String], team: Option[String]): Future[Seq[Vulnerability]] =
    vulnerabilitiesRepository.search(service, id, description, team)

  def countDistinctVulnerabilities(service: String): Future[Int] = {
    // adds quotes for regex exact match
    val serviceWithQuotes = Some(s"\"$service\"")
    vulnerabilitiesRepository.distinctVulnerabilitiesSummary(None, Some(ActionRequired.asString), serviceWithQuotes, None)
      .map(_.map(vs => vs.distinctVulnerability.id).toSet.size)
  }

  def distinctVulnerabilitiesSummary(vulnerability: Option[String], curationStatus: Option[String], service: Option[String], team: Option[String]): Future[Seq[VulnerabilitySummary]] = {
    vulnerabilitiesRepository.distinctVulnerabilitiesSummary(vulnerability, curationStatus, service, team)
  }
}
