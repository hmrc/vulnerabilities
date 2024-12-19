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

package uk.gov.hmrc.vulnerabilities.model

import play.api.libs.functional.syntax.toFunctionalBuilderOps
import play.api.libs.json.{Format, __}
import uk.gov.hmrc.mongo.play.json.formats.MongoJavatimeFormats

import java.time.Instant

case class TimelineEvent(
  id            : String,
  service       : String,
  weekBeginning : Instant,
  teams         : Seq[TeamName],
  curationStatus: CurationStatus
)

object TimelineEvent:
  private def format(using Format[Instant]): Format[TimelineEvent] =
    ( (__ \ "id"            ).format[String]
    ~ (__ \ "service"       ).format[String]
    ~ (__ \ "weekBeginning" ).format[Instant]
    ~ (__ \ "teams"         ).format[Seq[TeamName]]
    ~ (__ \ "curationStatus").format[CurationStatus]
    )(apply, pt => Tuple.fromProductTyped(pt))

  val apiFormat   = format(using summon[Format[Instant]])
  val mongoFormat = format(using MongoJavatimeFormats.instantFormat)

case class VulnerabilitiesTimelineCount(
  weekBeginning       : Instant,
  count               : Int
)

object VulnerabilitiesTimelineCount:
  val mongoFormat: Format[VulnerabilitiesTimelineCount] =
    ( (__ \ "_id"  ).format[Instant](MongoJavatimeFormats.instantFormat)
    ~ (__ \ "count").format[Int]
    )(apply, pt => Tuple.fromProductTyped(pt))

  val apiFormat: Format[VulnerabilitiesTimelineCount] =
    ( (__ \ "weekBeginning").format[Instant]
    ~ (__ \ "count"        ).format[Int]
    )(apply, pt => Tuple.fromProductTyped(pt))
