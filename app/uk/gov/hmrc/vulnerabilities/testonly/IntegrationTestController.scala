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

package uk.gov.hmrc.vulnerabilities.testonly

import org.mongodb.scala.bson.BsonDocument
import play.api.libs.json.{JsError, JsString, OFormat, Reads}
import play.api.mvc.{Action, AnyContent, BodyParser, ControllerComponents}
import uk.gov.hmrc.mongo.play.json.PlayMongoRepository
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import uk.gov.hmrc.vulnerabilities.model.{Assessment, RawVulnerability, TimelineEvent, VulnerabilityAge}
import uk.gov.hmrc.vulnerabilities.persistence.{AssessmentsRepository, RawReportsRepository, VulnerabilityAgeRepository, VulnerabilitiesTimelineRepository}

import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext
import uk.gov.hmrc.vulnerabilities.model.Report

@Singleton
class IntegrationTestController @Inject()(
  assessmentsRepository            : AssessmentsRepository
, rawReportsRepository             : RawReportsRepository
, vulnerabilityAgeRepository       : VulnerabilityAgeRepository
, vulnerabilitiesTimelineRepository: VulnerabilitiesTimelineRepository
, cc: ControllerComponents
)(implicit
  ec: ExecutionContext
) extends BackendController(cc) {

  def postAssessments(): Action[Seq[Assessment]] = {
    implicit val te: OFormat[Assessment] = Assessment.apiFormat
    addAll(assessmentsRepository)
  }

  def deleteAssessments(): Action[AnyContent] =
    deleteAll(assessmentsRepository)

  def postReports(): Action[Seq[Report]] = {
    implicit val te: OFormat[Report] = Report.apiFormat
    addAll(rawReportsRepository)
  }

  def deleteReports(): Action[AnyContent] =
    deleteAll(rawReportsRepository)

  def postVulnerabilityAges(): Action[Seq[VulnerabilityAge]] = {
    implicit val te: OFormat[VulnerabilityAge] = VulnerabilityAge.apiFormat
    addAll(vulnerabilityAgeRepository)
  }

  def deleteVulnerabilityAges(): Action[AnyContent] =
    deleteAll(vulnerabilityAgeRepository)

  def postTimelineEvents(): Action[Seq[TimelineEvent]] = {
    implicit val te: OFormat[TimelineEvent] = TimelineEvent.apiFormat
    addAll(vulnerabilitiesTimelineRepository)
  }

  def deleteTimelineEvents(): Action[AnyContent] =
    deleteAll(vulnerabilitiesTimelineRepository)

  private def validNelJson[A: Reads]: BodyParser[Seq[A]] =
    parse.json.validate(
      _.validate[Seq[A]].asEither
        .left.map(e => BadRequest(JsError.toJson(e)))
        .flatMap(l => if (l.isEmpty) Left(BadRequest(JsString("Array cannot be empty"))) else Right(l))
    )

  private def addAll[A: Reads](repo: PlayMongoRepository[A]): Action[Seq[A]] =
    Action.async(validNelJson[A]) { implicit request =>
      repo.collection.insertMany(request.body).toFuture()
        .map(_ => NoContent)
    }

  private def deleteAll[A](repo: PlayMongoRepository[A]) =
    Action.async {
      repo.collection.deleteMany(filter = BsonDocument()).toFuture()
        .map(_ => NoContent)
    }
}
