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
import play.api.libs.json.Json
import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import uk.gov.hmrc.vulnerabilities.model.VulnerabilitiesTimelineCount
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitiesTimelineRepository

import java.time.Instant
import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext

@Singleton()
class VulnerabilitiesTimelineController @Inject()(
 cc: ControllerComponents,
 vulnerabilitiesTimelineRepository: VulnerabilitiesTimelineRepository
) (implicit ec: ExecutionContext) extends BackendController(cc)
  with Logging {

  implicit val fmt = VulnerabilitiesTimelineCount.apiFormat

  def getTimelineCountsForService(service: Option[String], team: Option[String], vulnerability: Option[String], from: Instant, to: Instant): Action[AnyContent] = Action.async {
    vulnerabilitiesTimelineRepository.getTimelineCountsForService(service, team, vulnerability, from, to).map {
      result => Ok(Json.toJson(result))
    }
  }
}
