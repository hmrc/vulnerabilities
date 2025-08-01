/*
 * Copyright 2025 HM Revenue & Customs
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

package uk.gov.hmrc.vulnerabilities.controller

import play.api.Logging
import play.api.mvc.{Action, AnyContent, ControllerComponents, RequestHeader}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import uk.gov.hmrc.vulnerabilities.service.XrayService

import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext

@Singleton()
class AdminController @Inject()(
  cc         : ControllerComponents,
  xrayService: XrayService
)(using
  ExecutionContext
) extends BackendController(cc)
     with Logging:

  def rescan(): Action[AnyContent] =
    Action:
      request =>
        given RequestHeader = request
        xrayService.rescanLatestAndDeployed()
          .recover(ex => logger.error("Error running manually triggered rescan", ex))

        Accepted("Rescan triggered")
