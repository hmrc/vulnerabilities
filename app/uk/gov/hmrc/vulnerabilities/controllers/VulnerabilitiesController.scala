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

package uk.gov.hmrc.vulnerabilities.controllers

import play.api.Logging
import play.api.libs.json.{Json, OFormat, Writes}
import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import uk.gov.hmrc.vulnerabilities.model.{Environment, TotalVulnerabilityCount, Version, VulnerabilitySummary}
import uk.gov.hmrc.vulnerabilities.persistence.{AssessmentsRepository, VulnerabilitySummariesRepository}
import uk.gov.hmrc.vulnerabilities.service.{UpdateVulnerabilitiesService, VulnerabilitiesService}
import uk.gov.hmrc.vulnerabilities.utils.{AssessmentParser, Scheduler, TimelineScheduler}

import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext

@Singleton()
class VulnerabilitiesController @Inject()(
  cc                              : ControllerComponents,
  vulnerabilitiesService          : VulnerabilitiesService,
  updateVulnerabilitiesService    : UpdateVulnerabilitiesService,
  assessmentParser                : AssessmentParser,
  assessmentsRepository           : AssessmentsRepository,
  scheduler                       : Scheduler,
  timelineScheduler               : TimelineScheduler,
  vulnerabilitySummariesRepository: VulnerabilitySummariesRepository
)(implicit ec: ExecutionContext)
  extends BackendController(cc)
     with Logging {

  def distinctVulnerabilitySummaries(
    vulnerability  : Option[String ] = None,
    curationStatus : Option[String ] = None,
    service        : Option[String ] = None,
    version        : Option[Version] = None,
    team           : Option[String ] = None,
    component      : Option[String ] = None
  ): Action[AnyContent] =
    Action.async {
      implicit val fmt: OFormat[VulnerabilitySummary] = VulnerabilitySummary.apiFormat
      vulnerabilitiesService.distinctVulnerabilitiesSummary(vulnerability, curationStatus, service, version, team, component)
        .map(_.fold(NotFound("Vulnerabilities not found"))(result => Ok(Json.toJson(result))))
    }

  def getDistinctVulnerabilities(service: String): Action[AnyContent] = Action.async {
    vulnerabilitiesService.countDistinctVulnerabilities(service)
      .map(_.fold(
          NotFound(s"Service ${service} not scanned for vulnerabilities yet.")
        )(result =>
          Ok(Json.toJson(result))
        )
      )
  }

  def updateAssessments: Action[AnyContent] = Action.async {
    for {
      assessments <- assessmentParser.getAssessments()
      insertCount <- assessmentsRepository.insertAssessments(assessments.values.toSeq)
    } yield Ok(s"Inserted ${insertCount} documents into the assessments collection")
  }

  def manualReload() = Action { implicit request =>
    scheduler
      .manualReload()
      .recover(ex => logger.error("Error running manual data reload", ex))

    Accepted("Vulnerabilities data reload triggered.")
  }

  def manualTimelineUpdate() = Action { implicit request =>
    timelineScheduler
      .manualReload()
      .recover(ex => logger.error("Error running manual timeline data reload", ex))
    Accepted("Vulnerabilities timeline data update triggered.")
  }

  def testResult: Action[AnyContent] = Action.async {
    implicit val fmt = VulnerabilitySummary.apiFormat
    vulnerabilitySummariesRepository.getVulnerabilitySummaries()
      .map(res => Ok(Json.toJson(res)))
  }

  def testDeployment(serviceName: String, version: String, environment: String): Action[AnyContent] =
    Action.async { implicit request =>
      updateVulnerabilitiesService.updateVulnerabilities(serviceName, version, environment)
        .map(result => Ok)
    }

  def getVulnerabilityCountsPerService(
    service: Option[String],
    team: Option[String],
    environment: Option[Environment]
  ): Action[AnyContent] = Action.async {
    implicit val tvw: Writes[TotalVulnerabilityCount] = TotalVulnerabilityCount.writes
    vulnerabilitiesService.vulnerabilitiesCountPerService(service, team, environment)
      .map(result => Ok(Json.toJson(result)))
  }
}
