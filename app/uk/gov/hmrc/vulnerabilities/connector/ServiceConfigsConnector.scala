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

import play.api.libs.functional.syntax._
import play.api.libs.json.{Reads, __}
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, StringContextOps}
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig
import uk.gov.hmrc.vulnerabilities.model.{ArtefactName, RepoName}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class ServiceConfigsConnector @Inject()(
  servicesConfig: ServicesConfig,
  httpClientV2  : HttpClientV2
)(using
  ExecutionContext
):
  import HttpReads.Implicits._

  private val url = servicesConfig.baseUrl("service-configs")

  def artefactToRepos()(using HeaderCarrier): Future[Seq[ArtefactToRepo]] =
    given Reads[ArtefactToRepo] = ArtefactToRepo.reads
    httpClientV2
      .get(url"$url/service-configs/service-repo-names")
      .execute[Seq[ArtefactToRepo]]

case class ArtefactToRepo(
  artefactName: ArtefactName,
  repoName    : RepoName
)

object ArtefactToRepo:
  val reads: Reads[ArtefactToRepo] =
    ( (__ \ "artefactName").read[ArtefactName]
    ~ (__ \ "repoName"    ).read[RepoName]
    )(apply)
