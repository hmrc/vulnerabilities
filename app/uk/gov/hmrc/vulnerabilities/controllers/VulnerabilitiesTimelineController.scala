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
import play.api.libs.json.{Json, OFormat}
import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import uk.gov.hmrc.vulnerabilities.model.{CurationStatus, ServiceName, VulnerabilitiesTimelineCount}
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitiesTimelineRepository

import java.time.Instant
import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext

@Singleton()
class VulnerabilitiesTimelineController @Inject()(
 cc: ControllerComponents,
 vulnerabilitiesTimelineRepository: VulnerabilitiesTimelineRepository
)(implicit ec: ExecutionContext)
  extends BackendController(cc)
     with Logging {

  implicit val fmt: OFormat[VulnerabilitiesTimelineCount] = VulnerabilitiesTimelineCount.apiFormat

  def getTimelineCounts(
    service       : Option[ServiceName],
    team          : Option[String],
    vulnerability : Option[String],
    curationStatus: Option[CurationStatus],
    from          : Instant,
    to            : Instant
  ): Action[AnyContent] = Action.async {
    vulnerabilitiesTimelineRepository
      .getTimelineCounts(service, team, vulnerability, curationStatus, from, to)
      .map(result => Ok(Json.toJson(result)))
  }
}
