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
import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import uk.gov.hmrc.vulnerabilities.connectors.{ReleasesConnector, XrayConnector}
import uk.gov.hmrc.vulnerabilities.model.{Filter, ServiceVersionDeployments, WhatsRunningWhere}
import uk.gov.hmrc.vulnerabilities.persistence.RawReportsRepository
import uk.gov.hmrc.vulnerabilities.service.{WhatsRunningWhereService, XrayService}

import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext

@Singleton
class UpdateVulnerabilitiesController @Inject()(
  cc: ControllerComponents,
  releasesConnector: ReleasesConnector,
  whatsRunningWhereService: WhatsRunningWhereService,
  xrayService: XrayService,
  rawReportsRepository: RawReportsRepository

)(implicit ec: ExecutionContext) extends
  BackendController(cc)
  with Logging {

  def updateVulnerabilities: Action[AnyContent] = Action.async {
    //WIP - This will grow with each commit.
    for {
      wrw             <- releasesConnector.getCurrentReleases
      svDeps          = whatsRunningWhereService.getEnvsForServiceVersion(wrw)
      _               = println(svDeps.length)
      requestReports  <- xrayService.generateReports(svDeps)
      insertedCount   <- rawReportsRepository.insertReports(requestReports.flatten)
      _               = logger.info(s"Inserted ${insertedCount} documents into the rawReports collection")
    } yield Ok(s"hi")
  }
}
