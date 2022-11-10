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

package uk.gov.hmrc.vulnerabilities.model

import play.api.libs.functional.syntax.{toFunctionalBuilderOps, unlift}
import play.api.libs.json.__
import uk.gov.hmrc.mongo.play.json.formats.MongoJavatimeFormats

import java.time.Instant

case class WhatsRunningWhere(
  serviceName: String,
  deployments: Seq[Deployment]
)

object WhatsRunningWhere {

  val apiFormat = {
    implicit val df = Deployment.apiFormat
    ( (__ \ "applicationName"  ).format[String]
      ~ (__ \ "versions"       ).format[Seq[Deployment]]
    )(apply, unlift(unapply))
  }
}

case class Deployment(
   environment: String,
   version    : String
)

object Deployment {
  val apiFormat = {
    ( (__ \ "environment"     ).format[String]
      ~ (__ \ "versionNumber" ).format[String]
    )(apply, unlift(unapply))
  }
}

case class ServiceVersionDeployments(
  serviceName : String,
  version     : String,
  environments: Seq[String]
)



