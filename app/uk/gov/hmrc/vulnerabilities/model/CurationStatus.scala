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

import play.api.libs.json.{Format, JsError, JsResult, JsString, JsSuccess, JsValue}

sealed trait CurationStatus { def asString: String}

object CurationStatus:
  case object InvestigationOngoing extends CurationStatus { override val asString = "INVESTIGATION_ONGOING"}
  case object NoActionRequired     extends CurationStatus { override val asString = "NO_ACTION_REQUIRED"}
  case object ActionRequired       extends CurationStatus { override val asString = "ACTION_REQUIRED"}
  case object Uncurated            extends CurationStatus { override val asString = "UNCURATED"}

  val values: List[CurationStatus] = List(InvestigationOngoing, NoActionRequired, ActionRequired, Uncurated)

  def parse(s: String): Either[String, CurationStatus] =
    values
      .find(_.asString.equalsIgnoreCase(s))
      .toRight(s"Invalid CurationStatus, should be one of: ${values.map(_.asString).mkString(", ")}")

  val format: Format[CurationStatus] = new Format[CurationStatus]:
    override def reads(json: JsValue): JsResult[CurationStatus] =
      json match {
        case JsString(s) =>
          parse(s).fold(msg => JsError(msg), cs => JsSuccess(cs))
        case _ => JsError("String value expected")
      }

    override def writes(cs: CurationStatus): JsValue =
      JsString(cs.asString)
