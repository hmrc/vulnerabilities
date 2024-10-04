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

import play.api.libs.json.{Reads, Writes}
import play.api.mvc.{PathBindable, QueryStringBindable}
import uk.gov.hmrc.vulnerabilities.util.{FromString, FromStringEnum, Parser}

import FromStringEnum._

given Parser[SlugInfoFlag] = Parser.parser(SlugInfoFlag.values)

enum SlugInfoFlag(
  override val asString: String
) extends FromString
  derives Ordering, Reads, Writes, PathBindable, QueryStringBindable:
  case Latest       extends SlugInfoFlag(asString = "latest"      )
  case Development  extends SlugInfoFlag(asString = "development" )
  case Integration  extends SlugInfoFlag(asString = "integration" )
  case QA           extends SlugInfoFlag(asString = "qa"          )
  case Staging      extends SlugInfoFlag(asString = "staging"     )
  case ExternalTest extends SlugInfoFlag(asString = "externaltest")
  case Production   extends SlugInfoFlag(asString = "production"  )
