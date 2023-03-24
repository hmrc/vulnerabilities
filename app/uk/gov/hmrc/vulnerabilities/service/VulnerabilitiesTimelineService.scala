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

import play.api.Logger
import uk.gov.hmrc.vulnerabilities.config.VulnerabilitiesTimelineConfig
import uk.gov.hmrc.vulnerabilities.connectors.TeamsAndRepositoriesConnector
import uk.gov.hmrc.vulnerabilities.model.ServiceVulnerability
import uk.gov.hmrc.vulnerabilities.persistence.{RawReportsRepository, VulnerabilitiesTimelineRepository}

import java.time.Instant
import java.time.temporal.ChronoUnit
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class VulnerabilitiesTimelineService @Inject()(
  rawReportsRepository: RawReportsRepository,
  vulnerabilitiesTimelineRepository: VulnerabilitiesTimelineRepository,
  teamsAndRepositoriesConnector: TeamsAndRepositoriesConnector,
  vulnerabilitiesTimelineConfig: VulnerabilitiesTimelineConfig
)(implicit ec: ExecutionContext
) {

  private val logger = Logger(this.getClass)
  val processingCutoff = Instant.now().minusMillis(vulnerabilitiesTimelineConfig.timelineProcessingCutoff.toMillis)

  def updateTimelineData(): Future[Unit] = {
   for {
      reposWithTeams                  <- teamsAndRepositoriesConnector.getCurrentReleases()
      serviceVulnerabilities          <- rawReportsRepository.getTimelineData(processingCutoff)
      serviceVulnerabilitiesWithTeams  = addTeamsToServiceVulnerability(serviceVulnerabilities, reposWithTeams)
      _                               <- vulnerabilitiesTimelineRepository.replaceOrInsert(serviceVulnerabilitiesWithTeams)
    } yield ()
  }

  def addTeamsToServiceVulnerability(serviceVulnerabilities: Seq[ServiceVulnerability], reposWithTeams:  Map[String, Seq[String]]): Seq[ServiceVulnerability] = {
    serviceVulnerabilities.map(sv =>
      sv.copy(teams = reposWithTeams.getOrElse(sv.service, Seq()))
    )
  }
}
