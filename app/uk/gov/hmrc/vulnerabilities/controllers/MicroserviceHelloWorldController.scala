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

import play.api.libs.json.Format.GenericFormat
import play.api.libs.json.Json
import play.api.libs.json.Json.toJson
import play.api.libs.json.OFormat.oFormatFromReadsAndOWrites
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.vulnerabilities.model.Vulnerability
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitiesRepository

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton()
class MicroserviceHelloWorldController @Inject()(
    cc: ControllerComponents,
    vulnerabilitiesRepository: VulnerabilitiesRepository
)(implicit ec: ExecutionContext) extends BackendController(cc) {

  private implicit val x = Vulnerability.apiFormat

  def helloWorld(): Action[AnyContent] = Action.async {
    vulnerabilitiesRepository.findAll().map {
      result => Ok(Json.toJson(result))
    }
  }
}

