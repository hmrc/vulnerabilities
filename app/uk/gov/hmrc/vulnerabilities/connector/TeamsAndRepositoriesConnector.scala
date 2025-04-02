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

import play.api.libs.json.{Reads, __}
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, StringContextOps}
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig
import uk.gov.hmrc.vulnerabilities.model.{DigitalService, RepoName, TeamName}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

object TeamsAndRepositoriesConnector:
  import play.api.libs.functional.syntax._

  case class Repo(
    name     : RepoName,
    teamNames: Seq[TeamName]
  )

  private val repoReads: Reads[Repo] =
    ( (__ \ "name"     ).read[RepoName]
    ~ (__ \ "teamNames").read[Seq[TeamName]]
    )(Repo.apply _)

@Singleton
class TeamsAndRepositoriesConnector @Inject()(
  servicesConfig: ServicesConfig,
  httpClientV2  : HttpClientV2
)(using
  ExecutionContext
):
  import TeamsAndRepositoriesConnector._
  import HttpReads.Implicits._

  private val url = servicesConfig.baseUrl("teams-and-repositories")

  def repositories(
    teamName      : Option[TeamName]       = None,
    digitalService: Option[DigitalService] = None
  )(using HeaderCarrier): Future[Seq[Repo]] =
    given Reads[Repo] = repoReads
    httpClientV2
      .get(url"$url/api/v2/repositories?organisation=mdtp&team=${teamName.map(_.asString)}&digitalServiceName=${digitalService.map(_.asString)}")
      .execute[Seq[TeamsAndRepositoriesConnector.Repo]]

  def repoToTeams()(using HeaderCarrier): Future[Map[RepoName, Seq[TeamName]]] =
    repositories()
      .map:
        _.map(x => (x.name, x.teamNames))
         .toMap
