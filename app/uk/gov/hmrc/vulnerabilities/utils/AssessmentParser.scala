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

package uk.gov.hmrc.vulnerabilities.utils

import play.api.libs.functional.syntax.{toFunctionalBuilderOps, toInvariantFunctorOps, unlift}
import play.api.libs.json.{Json, __}
import uk.gov.hmrc.vulnerabilities.model.CurationStatus

import java.io.FileInputStream
import java.time.Instant
import scala.io.Source

object AssessmentParser extends App{

  def getAssessments(): Map[String, Investigation] = {
    implicit val fmt = Investigation.reads
    val stream = new FileInputStream("app/uk/gov/hmrc/vulnerabilities/assets/investigations-idx.json")
    val json = try {  Json.parse(stream) } finally { stream.close() }
    json.as[Map[String, Investigation]]
  }
}

case class Investigation(
  id            : String,
  assessment    : String,
  curationStatus: CurationStatus,
  lastReviewed  : Date,
  ticket        : String
)

object Investigation {
  val reads = {
    implicit val df = Date.reads
    implicit val cf = CurationStatus.format
    ( (__ \ "id").format[String]
      ~ (__ \ "assessment").format[String]
      ~ (__ \ "curationStatus").format[CurationStatus]
      ~ (__ \ "lastReviewed").format[Date]
      ~ (__ \ "ticket").format[String]
      )(apply, unlift(unapply))
  }
}

case class Date(
                 date: Instant
               )

object Date {
  val reads = {
    ( (__ \ "$date").format[Instant]).inmap(Date.apply, unlift(Date.unapply))
  }
}
