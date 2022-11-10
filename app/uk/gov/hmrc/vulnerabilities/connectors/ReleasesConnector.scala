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

package uk.gov.hmrc.vulnerabilities.connectors

import uk.gov.hmrc.http.{HeaderCarrier, StringContextOps}
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig
import uk.gov.hmrc.vulnerabilities.model.WhatsRunningWhere

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class ReleasesConnector @Inject()(
   servicesConfig: ServicesConfig,
   httpClientV2: HttpClientV2
)(implicit ec: ExecutionContext)
{
  private implicit val hc: HeaderCarrier = HeaderCarrier()
  private val url = servicesConfig.baseUrl("releases-api")

  def getCurrentReleases(implicit ec: ExecutionContext): Future[Seq[WhatsRunningWhere]] = {
    implicit val fmt = WhatsRunningWhere.apiFormat

    httpClientV2.get(url"$url/releases-api/whats-running-where")
      .execute[Seq[WhatsRunningWhere]]
  }


}
