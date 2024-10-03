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

package uk.gov.hmrc.vulnerabilities.connectors

import play.api.Logging
import play.api.libs.json._
import play.api.libs.functional.syntax.{toFunctionalBuilderOps}
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, StringContextOps}
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class BuildDeployApiConnector @Inject()(
  servicesConfig: ServicesConfig
, httpClientV2 : HttpClientV2
)(implicit
  ec          : ExecutionContext
) extends Logging {

  import HttpReads.Implicits._

  private val baseUrl = servicesConfig.baseUrl("platops-bnd-api")

  implicit private val rd: Reads[BuildDeployApiConnector.Result] =
    BuildDeployApiConnector.Result.reads

  def triggerXrayScanNow(path: String)(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      res <- httpClientV2
              .post(url"$baseUrl/trigger-xray-scan-now")
              .withBody(Json.obj("repo_path" -> path))
              .execute[BuildDeployApiConnector.Result]
      _   <- if (res.success) Future.unit else Future.failed(new Throwable(s"Failed to trigger Xray scan now for $path: ${res.message}"))
    } yield ()
}

object BuildDeployApiConnector {

  case class Result(
    success: Boolean
  , message: String
  )

  object Result {
    val reads: Reads[Result] =
      ( (__ \ "success").read[Boolean]
      ~ (__ \ "message").read[String]
      ) (Result.apply _)
  }
}
