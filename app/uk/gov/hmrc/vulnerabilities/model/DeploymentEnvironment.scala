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

package uk.gov.hmrc.vulnerabilities.model

import play.api.libs.json.{Format, JsError, JsString, JsSuccess, Reads, Writes}


enum DeploymentEnvironment(identifier: String) {
  case Development  extends DeploymentEnvironment("development")
  case Integration  extends DeploymentEnvironment("integration")
  case QA           extends DeploymentEnvironment("qa")
  case Staging      extends DeploymentEnvironment("staging")
  case ExternalTest extends DeploymentEnvironment("externaltest")
  case Production   extends DeploymentEnvironment("production")
}

object DeploymentEnvironment {

  given Format[DeploymentEnvironment] = Format(
    Reads { json =>
      json.validate[String].flatMap {
        case "development"  => JsSuccess(Development)
        case "integration"  => JsSuccess(Integration)
        case "qa"           => JsSuccess(QA)
        case "staging"      => JsSuccess(Staging)
        case "externaltest" => JsSuccess(ExternalTest)
        case "production"   => JsSuccess(Production)
        case value =>
          JsError(s"Unknown deployment environment: $value")
      }
    },
    Writes {
      case Development  => JsString("development")
      case Integration  => JsString("integration")
      case QA           => JsString("qa")
      case Staging      => JsString("staging")
      case ExternalTest => JsString("externaltest")
      case Production   => JsString("production")
    }
    )
}