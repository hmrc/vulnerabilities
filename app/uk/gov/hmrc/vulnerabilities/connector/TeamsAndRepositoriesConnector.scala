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

package uk.gov.hmrc.vulnerabilities.connector

import play.api.cache.AsyncCacheApi
import play.api.libs.json.{Reads, __}
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, StringContextOps}
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

object TeamsAndRepositoriesConnector:
  import play.api.libs.functional.syntax._

  case class Repo(
    name     : String,
    teamNames: Seq[String]
  )

  private val repoReads: Reads[Repo] =
    ( (__ \ "name"     ).read[String]
    ~ (__ \ "teamNames").read[Seq[String]]
    )(Repo.apply _)

  opaque type DeletedGitRepository = String

  object DeletedGitRepository:
    def apply(name: String): DeletedGitRepository =
      name

  private val deletedRepoReads: Reads[DeletedGitRepository] =
    (__ \ "name").read[String]


@Singleton
class TeamsAndRepositoriesConnector @Inject()(
  servicesConfig: ServicesConfig,
  httpClientV2  : HttpClientV2,
  cache         : AsyncCacheApi
)(using
  ExecutionContext
):
  import TeamsAndRepositoriesConnector._
  import HttpReads.Implicits._

  private val url = servicesConfig.baseUrl("teams-and-repositories")

  def repositories(teamName: Option[String])(using HeaderCarrier): Future[Seq[Repo]] =
    given Reads[Repo] = repoReads
    httpClientV2
      .get(url"$url/api/v2/repositories?team=$teamName")
      .execute[Seq[TeamsAndRepositoriesConnector.Repo]]

  private def getAllRepositories()(using HeaderCarrier): Future[Seq[Repo]] =
    repositories(teamName = None)

  private val cacheDuration =
    servicesConfig.getDuration("microservice.services.teams-and-repositories.cache.expiration")

  def cachedTeamToReposMap()(using HeaderCarrier): Future[Map[String, Seq[String]]] =
    cache.getOrElseUpdate("teams-for-services", cacheDuration):
      getAllRepositories()
        .map:
          _.map(x => (x.name, x.teamNames))
           .toMap
