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

import play.api.libs.json.Reads
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, HttpResponse, StringContextOps}
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

object TeamsAndRepositoriesConnector {
  case class Repo(name: String)

  import play.api.libs.json.Reads._
  import play.api.libs.json._

  val readsRepo: Reads[Repo] =
    (__ \ "name").read[String].map(Repo)
}

@Singleton
class TeamsAndRepositoriesConnector @Inject()(
  servicesConfig: ServicesConfig,
  httpClientV2  : HttpClientV2
)(implicit
  ec            : ExecutionContext)
{
  import HttpReads.Implicits._

  private val url = servicesConfig.baseUrl("teams-and-repositories")

  def repositoryTeams()(implicit hc: HeaderCarrier): Future[Map[String, Seq[String]]] =
    httpClientV2
      .get(url"$url/api/repository_teams")
      .execute[HttpResponse]
      .map(_.json.as[Map[String, Seq[String]]])

  implicit private val rd: Reads[TeamsAndRepositoriesConnector.Repo] =
    TeamsAndRepositoriesConnector.readsRepo

  def repositories(teamName: Option[String])(implicit hc: HeaderCarrier): Future[Seq[TeamsAndRepositoriesConnector.Repo]] =
    httpClientV2
      .get(url"$url/api/v2/repositories?team=$teamName")
      .execute[Seq[TeamsAndRepositoriesConnector.Repo]]
}
