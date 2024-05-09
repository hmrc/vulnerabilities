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
import play.api.mvc.{PathBindable, QueryStringBindable}

sealed trait SlugInfoFlag { def asString: String }

object SlugInfoFlag {
  case object Latest       extends SlugInfoFlag { val asString = "latest"      }
  case object Development  extends SlugInfoFlag { val asString = "development" }
  case object Integration  extends SlugInfoFlag { val asString = "integration" }
  case object QA           extends SlugInfoFlag { val asString = "qa"          }
  case object Staging      extends SlugInfoFlag { val asString = "staging"     }
  case object ExternalTest extends SlugInfoFlag { val asString = "externaltest"}
  case object Production   extends SlugInfoFlag { val asString = "production"  }

  val values: List[SlugInfoFlag] =
  // this list is sorted
    List(Latest, Integration, Development, QA, Staging, ExternalTest, Production)

  def parse(s: String): Option[SlugInfoFlag] =
    values.find(_.asString == s)

  val format: Format[SlugInfoFlag] = new Format[SlugInfoFlag] {
    override def writes(o: SlugInfoFlag): JsValue = JsString(o.asString)
    override def reads(json: JsValue): JsResult[SlugInfoFlag] =
      json.validate[String].flatMap(s => SlugInfoFlag.parse(s).map(e => JsSuccess(e)).getOrElse(JsError("invalid SlugInfoFlag")))
  }

  implicit val pathBindable: PathBindable[SlugInfoFlag] =
    new PathBindable[SlugInfoFlag] {
      override def bind(key: String, value: String): Either[String, SlugInfoFlag] =
        parse(value).toRight(s"Invalid SlugInfoFlag '$value'")

      override def unbind(key: String, value: SlugInfoFlag): String =
        value.asString
    }

  import cats.data.EitherT
  implicit def queryStringBindable(implicit stringBinder: QueryStringBindable[String]): QueryStringBindable[SlugInfoFlag] =
    new QueryStringBindable[SlugInfoFlag] {
      override def bind(key: String, params: Map[String, Seq[String]]): Option[Either[String, SlugInfoFlag]] =
        ( for {
            x <- EitherT.apply(stringBinder.bind(key, params))
            y <- EitherT.fromOption[Option](SlugInfoFlag.parse(x), s"Invalid SlugInfoFlag '$x'")
          } yield y
        ).value

      override def unbind(key: String, value: SlugInfoFlag): String =
        stringBinder.unbind(key, value.toString)
    }
}

