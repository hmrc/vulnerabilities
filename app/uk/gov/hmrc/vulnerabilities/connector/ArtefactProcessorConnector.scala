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

import com.google.inject.{Inject, Singleton}
import play.api.libs.json._
import play.api.libs.functional.syntax.{toFunctionalBuilderOps}
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, StringContextOps}
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, RepoName, Version}

import scala.concurrent.{ExecutionContext, Future}

@Singleton
class ArtefactProcessorConnector @Inject()(
  servicesConfig: ServicesConfig
, httpClientV2  : HttpClientV2
)(using
  ExecutionContext
):
  import HttpReads.Implicits._

  private val baseUrl = servicesConfig.baseUrl("artefact-processor")

  def getSlugInfo(slugName: ServiceName, version: Version)(using HeaderCarrier): Future[Option[ArtefactProcessorConnector.SlugInfo]] =
    given Reads[ArtefactProcessorConnector.SlugInfo] =
      ArtefactProcessorConnector.SlugInfo.reads
    httpClientV2
      .get(url"$baseUrl/result/slug/${slugName.asString}/${version.original}")
      .execute[Option[ArtefactProcessorConnector.SlugInfo]]

  def getMetaArtefact(repoName: RepoName, version: Version)(using hc: HeaderCarrier): Future[Option[ArtefactProcessorConnector.MetaArtefact]] =
    given Reads[ArtefactProcessorConnector.MetaArtefact] = ArtefactProcessorConnector.MetaArtefact.reads
    httpClientV2
      .get(url"$baseUrl/result/meta/${repoName.asString}/${version.original}")
      .execute[Option[ArtefactProcessorConnector.MetaArtefact]]

object ArtefactProcessorConnector:
  case class SlugInfo(
    name   : ServiceName
  , version: Version
  , uri    : String
  )

  object SlugInfo:
    val reads: Reads[SlugInfo] =
      ( (__ \ "name"   ).read[String].map(ServiceName.apply)
      ~ (__ \ "version").read[String].map(Version.apply)
      ~ (__ \ "uri"    ).read[String]
      ) (SlugInfo.apply _)

  case class MetaArtefact(modules: Seq[MetaArtefact.Module])

  object MetaArtefact:
    case class Module(dependencyDotCompile: Option[String])

    val reads: Reads[MetaArtefact] =
      given Reads[Module] = (__ \ "dependencyDotCompile").readNullable[String].map(Module.apply)

      (__ \ "modules").read[Seq[Module]].map(MetaArtefact.apply)
