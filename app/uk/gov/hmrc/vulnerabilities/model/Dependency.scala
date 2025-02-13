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

package uk.gov.hmrc.vulnerabilities.model

  import play.api.libs.functional.syntax._
  import play.api.libs.json.{__, Format}

case class ImportedBy(
  group   : String,
  artefact: String,
  version : Version
)

object ImportedBy:
  val format: Format[ImportedBy] =
  ( (__ \ "group"   ).format[String]
  ~ (__ \ "artefact").format[String]
  ~ (__ \ "version" ).format[Version]
  )(ImportedBy.apply, pt => Tuple.fromProductTyped(pt))

case class Dependency(
  group       : String
, artefact    : String
, scalaVersion: Option[Version]    = None
, version     : Version
, importedBy  : Option[ImportedBy] = None
)
