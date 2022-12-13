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

import play.api.Logging
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.vulnerabilities.connectors.{ReleasesConnector, TeamsAndRepositoriesConnector}
import uk.gov.hmrc.vulnerabilities.persistence.{AssessmentsRepository, RawReportsRepository, VulnerabilitySummariesRepository}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class UpdateVulnerabilitiesService @Inject()(
  releasesConnector: ReleasesConnector,
  teamsAndRepositoriesConnector: TeamsAndRepositoriesConnector,
  whatsRunningWhereService: WhatsRunningWhereService,
  xrayService: XrayService,
  rawReportsRepository: RawReportsRepository,
  vulnerabilitiesService: VulnerabilitiesService,
  assessmentsRepository: AssessmentsRepository,
  vulnerabilitySummariesRepository: VulnerabilitySummariesRepository

)(implicit ec: ExecutionContext) extends
  Logging {

  def updateVulnerabilities()(implicit hc: HeaderCarrier): Future[Unit] = {
    for {
      wrw             <- releasesConnector.getCurrentReleases()
      svDeps           = whatsRunningWhereService.getEnvsForServiceVersion(wrw)
      //Only download reports that don't exist in last 7 days in our raw reports collection
      recentReports   <- rawReportsRepository.getReportsInLastXDays()
      outOfDateSVDeps  = whatsRunningWhereService.removeSVDIfRecentReportExists(svDeps, recentReports)
      _               <- xrayService.processReports(outOfDateSVDeps)
      _                = logger.info(s"Finished generating and inserting reports into the rawReports collection")
      //Transform raw reports to Vulnerability Summaries
      unrefined       <- rawReportsRepository.getNewDistinctVulnerabilities()
      _                = logger.info(s"Retrieved ${unrefined.length} unrefined vulnerability summaries")
      reposWithTeams  <- teamsAndRepositoriesConnector.getCurrentReleases()
      refined          = vulnerabilitiesService.convertToVulnerabilitySummary(unrefined, reposWithTeams, svDeps)
      assessments     <- assessmentsRepository.getAssessments()
      finalAssessments = assessments.map(a => a.id -> a).toMap
      finalSummaries   = vulnerabilitiesService.addInvestigationsToSummaries(refined, finalAssessments)
      _                = logger.info("About to delete all documents from the vulnerabilitySummaries repository")
      //Update final Collection
      summariesCount  <- vulnerabilitySummariesRepository.deleteOldAndInsertNewSummaries(finalSummaries)
    } yield logger.info(s"Inserted ${summariesCount} documents into the vulnerabilitySummaries repository")
  }
}
