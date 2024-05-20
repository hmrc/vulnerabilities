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

import play.api.libs.functional.syntax.{toFunctionalBuilderOps, unlift}
import play.api.libs.json.__
import uk.gov.hmrc.mongo.play.json.formats.MongoJavatimeFormats
import uk.gov.hmrc.vulnerabilities.model.CurationStatus

import java.time.Instant

case class Assessment(
  id            : String,
  assessment    : String,
  curationStatus: CurationStatus,
  lastReviewed  : Instant,
  ticket        : String
)

object Assessment {
  val apiFormat =
    ( (__ \ "id"            ).format[String]
    ~ (__ \ "assessment"    ).format[String]
    ~ (__ \ "curationStatus").format[CurationStatus](CurationStatus.format)
    ~ (__ \ "lastReviewed"  ).format[Instant]
    ~ (__ \ "ticket"        ).format[String]
    )(apply, unlift(unapply))

  val mongoFormat =
    ( (__ \ "id"            ).format[String]
    ~ (__ \ "assessment"    ).format[String]
    ~ (__ \ "curationStatus").format[CurationStatus](CurationStatus.format)
    ~ (__ \ "lastReviewed"  ).format[Instant](MongoJavatimeFormats.instantFormat)
    ~ (__ \ "ticket"        ).format[String]
    )(apply, unlift(unapply))
}
