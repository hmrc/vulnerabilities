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

package uk.gov.hmrc.vulnerabilities.connector

import java.net.URI
import javax.inject.{Inject, Singleton}
import play.api.libs.json.{Json, JsSuccess}
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, StringContextOps, UpstreamErrorResponse}
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.LocalXrayCoverageV2
import scala.concurrent.{ExecutionContext, Future}
import scala.util.Try

@Singleton
class LocalXrayCoverageConnectorV2 @Inject()(config: ServicesConfig, http: HttpClientV2)(using ExecutionContext):
  private val baseUrl = config.baseUrl("xray-v2")

  def isLoopback: Boolean =
    Try(URI.create(baseUrl)).toOption.exists(uri =>
      uri.getScheme == "http" && Set("127.0.0.1", "localhost", "[::1]").contains(uri.getHost) &&
        uri.getUserInfo == null && uri.getQuery == null && uri.getFragment == null &&
        Option(uri.getPath).forall(p => p.isEmpty || p == "/"))

  private given HttpReads[LocalXrayCoverageV2] = (_, _, response) =>
    response.status match
      case 200 =>
        Try(Json.parse(response.body)).toOption.map(_.validate[LocalXrayCoverageV2]) match
          case Some(JsSuccess(value, _)) => value
          case _ => throw InvalidXrayResponseV2("Invalid local synthetic coverage response")
      case status => throw UpstreamErrorResponse(s"Local synthetic coverage returned HTTP $status", status)

  def coverage(reportId: Int)(using HeaderCarrier): Future[LocalXrayCoverageV2] =
    require(isLoopback && reportId > 0, "Synthetic coverage requires a loopback endpoint and positive report ID")
    http.get(url"$baseUrl/__synthetic__/reports/$reportId/coverage").execute[LocalXrayCoverageV2]
