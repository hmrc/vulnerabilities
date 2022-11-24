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

package uk.gov.hmrc.vulnerabilities.controllers

import play.api.Logging
import play.api.libs.json.Json
import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import uk.gov.hmrc.vulnerabilities.connectors.{ReleasesConnector, TeamsAndRepositoriesConnector, XrayConnector}
import uk.gov.hmrc.vulnerabilities.model.{Filter, ServiceVersionDeployments, VulnerabilitySummary, WhatsRunningWhere}
import uk.gov.hmrc.vulnerabilities.persistence.{AssessmentsRepository, RawReportsRepository, VulnerabilitySummariesRepository}
import uk.gov.hmrc.vulnerabilities.service.{VulnerabilitiesService, WhatsRunningWhereService, XrayService}
import uk.gov.hmrc.vulnerabilities.utils.AssessmentParser

import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext

@Singleton
class UpdateVulnerabilitiesController @Inject()(
  cc: ControllerComponents,
  releasesConnector: ReleasesConnector,
  teamsAndRepositoriesConnector: TeamsAndRepositoriesConnector,
  whatsRunningWhereService: WhatsRunningWhereService,
  xrayService: XrayService,
  rawReportsRepository: RawReportsRepository,
  vulnerabilitiesService: VulnerabilitiesService,
  assessmentParser: AssessmentParser,
  assessmentsRepository: AssessmentsRepository,
  vulnerabilitySummariesRepository: VulnerabilitySummariesRepository

)(implicit ec: ExecutionContext) extends
  BackendController(cc)
  with Logging {

  def updateVulnerabilities: Action[AnyContent] = Action.async {
    implicit val fmt = VulnerabilitySummary.apiFormat
    for {
      wrw             <- releasesConnector.getCurrentReleases
      svDeps           = whatsRunningWhereService.getEnvsForServiceVersion(wrw).take(1)
      requestReports  <- xrayService.generateReports(svDeps)
      insertedCount   <- rawReportsRepository.insertReports(requestReports.flatten)
      _                = logger.info(s"Inserted ${insertedCount} documents into the rawReports collection")
      //When scheduler is implemented, need to add a date filter on generatedDate, so that the only
      //new raw reports are transformed and added to final collection. Otherwise would get duplicates.
      unrefined       <- rawReportsRepository.getDistinctVulnerabilities
      _=println(unrefined.size)
      reposWithTeams  <- teamsAndRepositoriesConnector.getCurrentReleases
      refined          = vulnerabilitiesService.convertToVulnerabilitySummary(unrefined, reposWithTeams, svDeps)
      assessments     <- assessmentsRepository.getAssessments
      finalAssessments = assessments.map(a => a.id -> a).toMap
      finalSummaries   = vulnerabilitiesService.addInvestigationsToSummaries(refined, finalAssessments)
      summariesCount  <- vulnerabilitySummariesRepository.insertSummaries(finalSummaries)
    } yield Ok(s"Inserted ${summariesCount} documents into the vulnerabilitySummaries repository")
  }

  def updateAssessments: Action[AnyContent] = Action.async {
    for {
      assessments <- assessmentParser.getAssessments()
      insertCount <- assessmentsRepository.insertAssessments(assessments.values.toSeq)
    } yield Ok(s"Inserted ${insertCount} documents into the assessments collection")
  }
}
