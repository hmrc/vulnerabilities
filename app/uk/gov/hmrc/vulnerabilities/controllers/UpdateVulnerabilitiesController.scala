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

import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import uk.gov.hmrc.vulnerabilities.connectors.ReleasesConnector
import uk.gov.hmrc.vulnerabilities.model.{ServiceVersionDeployments, WhatsRunningWhere}
import uk.gov.hmrc.vulnerabilities.service.WhatsRunningWhereService

import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext

@Singleton
class UpdateVulnerabilitiesController @Inject()(
  cc: ControllerComponents,
  releasesConnector: ReleasesConnector,
  whatsRunningWhereService: WhatsRunningWhereService
)(implicit ec: ExecutionContext) extends BackendController(cc){

  def updateVulnerabilities: Action[AnyContent] = Action.async {
    //WIP - This will grow with each commit.
    for {
      wrw         <- releasesConnector.getCurrentReleases
      svDeps      = whatsRunningWhereService.getEnvsForServiceVersion(wrw)
    } yield Ok("hi")
  }
}
