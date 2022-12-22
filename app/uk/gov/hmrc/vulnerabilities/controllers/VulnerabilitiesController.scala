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
import play.api.libs.json.{Json, OFormat}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.vulnerabilities.model.VulnerabilitySummary
import uk.gov.hmrc.vulnerabilities.persistence.{AssessmentsRepository, VulnerabilitySummariesRepository}
import uk.gov.hmrc.vulnerabilities.service.VulnerabilitiesService
import uk.gov.hmrc.vulnerabilities.utils.{AssessmentParser, Scheduler}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton()
class VulnerabilitiesController @Inject()(
    cc: ControllerComponents,
    vulnerabilitiesService: VulnerabilitiesService,
    assessmentParser: AssessmentParser,
    assessmentsRepository: AssessmentsRepository,
    scheduler: Scheduler,
    vulnerabilitySummariesRepository: VulnerabilitySummariesRepository
)(implicit ec: ExecutionContext) extends BackendController(cc)
with Logging {

  def distinctVulnerabilitySummaries(vulnerability: Option[String] = None, curationStatus: Option[String] = None, service: Option[String] = None, team: Option[String] = None): Action[AnyContent] =
    Action.async {
    implicit val fmt: OFormat[VulnerabilitySummary] = VulnerabilitySummary.apiFormat
    vulnerabilitiesService.distinctVulnerabilitiesSummary(vulnerability, curationStatus, service, team).map {
      result => Ok(Json.toJson(result))
    }
  }

  def getDistinctVulnerabilities(service: String): Action[AnyContent] = Action.async {
    vulnerabilitiesService.countDistinctVulnerabilities(service).map {
      result => Ok(Json.toJson(result))
    }
  }

  def updateAssessments: Action[AnyContent] = Action.async {
    for {
      assessments <- assessmentParser.getAssessments()
      insertCount <- assessmentsRepository.insertAssessments(assessments.values.toSeq)
    } yield Ok(s"Inserted ${insertCount} documents into the assessments collection")
  }

  def manualReload() = Action { implicit request =>
    scheduler.manualReload()
    Accepted("Vulnerabilities data reload triggered.")
  }

  def testResult: Action[AnyContent] = Action.async {
    vulnerabilitySummariesRepository.getVulnerabilitySummaries().map {
      implicit val fmt = VulnerabilitySummary.apiFormat
      res => Ok(Json.toJson(res))
    }
  }
}

