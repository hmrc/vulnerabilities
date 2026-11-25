/*
 * Copyright 2026 HM Revenue & Customs
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

package uk.gov.hmrc.vulnerabilities.v2.model.api

import play.api.libs.functional.syntax.*
import play.api.libs.json.{Reads, __}

case class AddGuidanceRequest(
  guidance: Option[String],
  comment : Option[String],
  author  : String
  )

object AddGuidanceRequest:
  val reads: Reads[AddGuidanceRequest] =
    ( (__ \ "guidance").readNullable[String]
    ~ (__ \ "comment" ).readNullable[String]
    ~ (__ \ "author"  ).read[String]
    )(AddGuidanceRequest.apply)
