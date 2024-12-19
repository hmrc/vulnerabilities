/*
 * Copyright 2024 HM Revenue & Customs
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

package uk.gov.hmrc.vulnerabilities.service

import play.api.Configuration
import play.api.cache.AsyncCacheApi
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.vulnerabilities.model.{ArtefactName, ServiceName, TeamName}
import uk.gov.hmrc.vulnerabilities.connector.{ServiceConfigsConnector, TeamsAndRepositoriesConnector}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{Future, ExecutionContext}
import scala.concurrent.duration.Duration


@Singleton()
class TeamService @Inject() (
  config                       : Configuration,
  teamsAndRepositoriesConnector: TeamsAndRepositoriesConnector,
  serviceConfigsConnector      : ServiceConfigsConnector,
  cache                        : AsyncCacheApi
)(using
  ExecutionContext
):
  private val cacheDuration =
    config.get[Duration]("microservice.services.teams-and-repositories.cache.expiration")

  def artefactToTeams()(using HeaderCarrier): Future[Map[ArtefactName, Seq[TeamName]]] =
    cache.getOrElseUpdate("artefact-to-teams", cacheDuration):
      for
        repoWithTeams          <- teamsAndRepositoriesConnector.repoToTeams()
        artefactToRepos        <- serviceConfigsConnector.artefactToRepos()
        defaultArtefactToTeams =  // assume repos and artefacts have the same name
                                  repoWithTeams.map((k, v) => ArtefactName(k.asString) -> v)
      yield
        // and augment with known exceptions
        artefactToRepos.foldLeft(defaultArtefactToTeams): (acc, artefactToRepo) =>
          acc ++ Map(artefactToRepo.artefactName -> acc.getOrElse(ArtefactName(artefactToRepo.repoName.asString), Seq.empty))

  def services(team: Option[TeamName])(using HeaderCarrier): Future[Seq[ServiceName]] =
    teamsAndRepositoriesConnector.repositories(team).map(_.map(x => ServiceName(x.name.asString)))
