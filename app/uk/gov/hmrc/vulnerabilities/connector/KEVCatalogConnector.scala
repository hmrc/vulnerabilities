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

import play.api.{Configuration, Logging}
import play.api.libs.json.{Json, Reads}
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, StringContextOps, UpstreamErrorResponse}
import uk.gov.hmrc.http.client.HttpClientV2

import javax.inject.{Inject, Singleton}
import java.time.{Instant, LocalDate}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class KEVCatalogConnector(
  @Inject() configuration: Configuration,
  httpClientV2: HttpClientV2
)(using ExecutionContext)
  extends Logging:

  import HttpReads.Implicits.*

  private val kevJsonDownloadUrl = configuration.get[String]("kev.downloadUrl")

  def downloadLatestReport()(using HeaderCarrier): Future[KEVReport] =
    given Reads[KEVReport] = KEVReport.reads
    httpClientV2
      .get(url"$kevJsonDownloadUrl")
      .withProxy
      .execute[KEVReport]
      .recoverWith {
        case error: UpstreamErrorResponse =>
          logger.error(s"Upstream error downloading KEV catalog: ${error.message}")
          Future.failed(error)
        case error: Throwable =>
          logger.error(s"Error downloading or deserializing KEV catalog: ${error.getMessage}", error)
          Future.failed(error)
      }

case class KEVReport(
  title: String,
  catalogVersion: String,
  dateReleased: Instant,
  count: Int,
  vulnerabilities: Seq[KevEntry]
)

case class KevEntry(
  cveID: String,
  vendorProject: String,
  product: String,
  vulnerabilityName: String,
  dateAdded: LocalDate,
  shortDescription: String,
  requiredAction: String,
  dueDate: LocalDate,
  knownRansomwareCampaignUse: String,
  forensicTriage: String,
  notes: String,
  cwes: Seq[String]
)

object KEVReport:
  val reads: Reads[KEVReport] = Json.reads[KEVReport]

object KevEntry:
  given Reads[KevEntry] = Json.reads[KevEntry]
