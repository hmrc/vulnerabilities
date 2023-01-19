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

sealed trait Environment { def asString: String }

object Environment {
  case object Development  extends Environment { val asString = "development" }
  case object Integration  extends Environment { val asString = "integration" }
  case object QA           extends Environment { val asString = "qa"          }
  case object Staging      extends Environment { val asString = "staging"     }
  case object ExternalTest extends Environment { val asString = "externaltest"}
  case object Production   extends Environment { val asString = "production"  }

  val values: List[Environment] =
  // this list is sorted
    List(Integration, Development, QA, Staging, ExternalTest, Production)

  def parse(s: String): Option[Environment] =
    values.find(_.asString == s)

  val format: Format[Environment] = new Format[Environment] {
    override def writes(o: Environment): JsValue = JsString(o.asString)
    override def reads(json: JsValue): JsResult[Environment] =
      json.validate[String].flatMap(s => Environment.parse(s).map(e => JsSuccess(e)).getOrElse(JsError("invalid environment")))
  }

  implicit val pathBindable: PathBindable[Environment] =
    new PathBindable[Environment] {
      override def bind(key: String, value: String): Either[String, Environment] =
        parse(value).toRight(s"Invalid Environment '$value'")

      override def unbind(key: String, value: Environment): String =
        value.asString
    }

  implicit val queryStringBindable: QueryStringBindable[Environment] =
    new QueryStringBindable[Environment] {
      private val Name = "environment"

      override def bind(key: String, params: Map[String, Seq[String]]): Option[Either[String, Environment]] =
        params.get(Name).map { values =>
          values.toList match {
            case Nil         => Left("missing environment value")
            case head :: Nil => pathBindable.bind(key, head)
            case _           => Left("too many environment values")
          }
        }

      override def unbind(key: String, value: Environment): String =
        s"$Name=${value.asString}"
    }
}

