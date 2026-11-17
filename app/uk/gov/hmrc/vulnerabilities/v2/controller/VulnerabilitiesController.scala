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

package uk.gov.hmrc.vulnerabilities.v2.controller

import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext
import uk.gov.hmrc.vulnerabilities.v2.service.{DeploymentOccurrencesService, TeamVulnerabilityService, VulnerabilityGuidanceService}
import uk.gov.hmrc.vulnerabilities.v2.model.api.AddGuidanceRequest
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}
import play.api.libs.json.{Json, JsValue}
import scala.concurrent.Future
import play.api.libs.json.JsError

@Singleton()
class VulnerabilitiesController @Inject(
  service: TeamVulnerabilityService,
  deployments: DeploymentOccurrencesService,
  guidanceService: VulnerabilityGuidanceService
)(cc: ControllerComponents)
 (using ExecutionContext) extends BackendController(cc):

  def teamSummary(team: String): Action[AnyContent] =
    Action:
      service.teamVulnerabilitySummary(team) match
        case Some(summary) => Ok(Json.toJson(summary))
        case None          => NotFound

  def deploymentOccurrences(serviceName: ServiceName, appVersion: Version): Action[AnyContent] =
    Action.async:
      deployments.get(serviceName, appVersion).map:
        case Some(report) => Ok(Json.toJson(report))
        case None         => NotFound

  def updateGuidance(vulnerabilityId: String): Action[JsValue] =
    Action.async(parse.json) { request =>
      request.body.validate[AddGuidanceRequest].fold(
        errors => Future.successful(BadRequest(JsError.toJson(errors))),
        guidanceRequest =>
          guidanceService
            .addGuidance(vulnerabilityId, guidanceRequest)
            .map {
              case Some(_) => NoContent
              case None    => NotFound
            }
    )}
