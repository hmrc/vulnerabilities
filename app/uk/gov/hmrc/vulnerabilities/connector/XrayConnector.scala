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

import org.apache.pekko.stream.Materializer
import org.apache.pekko.stream.scaladsl.{Source, StreamConverters}
import org.apache.pekko.util.ByteString
import play.api.{Configuration, Logging}
import play.api.libs.json.{Json, Reads, __}
import play.api.libs.ws.writeableOf_JsValue
import uk.gov.hmrc.http.{HeaderCarrier, HttpReads, StringContextOps, UpstreamErrorResponse}
import uk.gov.hmrc.http.client.{HttpClientV2, readEitherSource}
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}

import java.io.InputStream
import java.time.{Clock, Instant}
import java.time.temporal.ChronoUnit
import javax.inject.{Inject, Singleton}
import scala.concurrent.duration.FiniteDuration
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class XrayConnector @Inject() (
  configuration: Configuration,
  httpClientV2 : HttpClientV2,
  clock        : Clock
)(using
  ExecutionContext,
  Materializer
) extends Logging:
  import HttpReads.Implicits._
  import XrayConnector._

  private val xrayBaseUrl         : String         = configuration.get[String]("xray.url")
  private val xrayToken           : String         = configuration.get[String]("xray.token")
  private val xrayUsername        : String         = configuration.get[String]("xray.username")
  private val xrayReportsRetention: FiniteDuration = configuration.get[FiniteDuration]("xray.reports.retention")

  private def toReportName(serviceName: ServiceName, version: Version): String =
    s"AppSec-report-${serviceName.asString}_${version.original.replaceAll("\\.", "_")}"

  // https://jfrog.com/help/r/xray-rest-apis/generate-vulnerabilities-report
  def generateReport(serviceName: ServiceName, version: Version, path: String)(using HeaderCarrier): Future[ReportResponse] =
    given Reads[ReportResponse] = ReportResponse.reads
    // Search does not work with slug path - just */artefact-name
    // Search is fuzzy when including * in filename e.g. $service_$version*.tgz and returns .tgz.sig files
    // Needs to be full name and include the slug runner version too but start with */
    val artefactName = path.split("/").lastOption.getOrElse(sys.error(s"invalid path for $path"))
    httpClientV2
      .post(url"${xrayBaseUrl}/vulnerabilities")
      .setHeader(
        "Authorization" -> s"Bearer $xrayToken",
        "Content-Type"  -> "application/json"
      ).withBody(Json.parse(
        s"""{"name":"${toReportName(serviceName, version)}","resources":{"repositories":[{"name":"webstore-local"}]},"filters":{"impacted_artifact":"*/$artefactName"}}"""
      ))
      .execute[ReportResponse]

  // https://jfrog.com/help/r/xray-rest-apis/get-report-details-by-id
  def checkStatus(id: Int)(using HeaderCarrier): Future[ReportStatus] =
    given Reads[ReportStatus] = ReportStatus.reads
    httpClientV2
      .get(url"${xrayBaseUrl}/$id")
      .setHeader(
        "Authorization" -> s"Bearer $xrayToken",
        "Content-Type"  -> "application/json"
      )
      .execute[ReportStatus]

  def downloadAndUnzipReport(reportId: Int, serviceName: ServiceName, version: Version)(using HeaderCarrier): Future[Option[(Instant, Seq[Vulnerability])]] =
    given Reads[Vulnerability] = Vulnerability.reads
    for
      zip    <- downloadReport(reportId, serviceName, version)
      result =  unzipReport(zip)
                  .map(Json.parse)
                  .map: json =>
                    val date = (json \ "generatedDate").asOpt[Instant].getOrElse(Instant.now())
                    val rows = (json \ "rows"         ).as[Seq[Vulnerability]]
                    (date, rows)
    yield result

  private def unzipReport(inputStream: InputStream): Option[String] =
    val zip = java.util.zip.ZipInputStream(inputStream)
    try
      Iterator
        .continually(zip.getNextEntry)
        .takeWhile(_ != null)
        .foldLeft(Option.empty[String])((found, entry) => Some(scala.io.Source.fromInputStream(zip).mkString))
    finally
      zip.close()

  // https://jfrog.com/help/r/xray-rest-apis/export
  private def downloadReport(reportId: Int, serviceName: ServiceName, version: Version)(using HeaderCarrier): Future[InputStream] =
    val fileName = toReportName(serviceName, version)
    val url = url"${xrayBaseUrl}/export/$reportId?file_name=${fileName}&format=json"
    httpClientV2
      .get(url)
      .setHeader(
        "Authorization" -> s"Bearer $xrayToken",
        "Content-Type"  -> "application/json"
      )
      .stream[Either[UpstreamErrorResponse, Source[ByteString, _]]]
      .flatMap {
        case Right(source) =>
          logger.info(s"Successfully downloaded the zipped report for $fileName with id $reportId from Xray")
          Future.successful(source.runWith(StreamConverters.asInputStream()))
        case Left(error) =>
          logger.error(s"Could not download zip for: $url", error)
          throw error
      }

  // https://jfrog.com/help/r/xray-rest-apis/delete
  def deleteReportFromXray(reportId: Int)(using HeaderCarrier): Future[Unit] =
    httpClientV2
      .delete(url"${xrayBaseUrl}/$reportId")
      .setHeader(
        "Authorization" -> s"Bearer $xrayToken",
        "Content-Type"  -> "application/json"
      ).execute[Unit](throwOnFailure(summon[HttpReads[Either[UpstreamErrorResponse, Unit]]]), summon[ExecutionContext])

  // https://jfrog.com/help/r/xray-rest-apis/get-reports-list
  def getStaleReportIds()(using HeaderCarrier): Future[Seq[ReportId]] =
    given Reads[Seq[ReportId]] =
      (__ \ "reports")
        .read(Reads.seq[ReportId](ReportId.reads))

    val cutOff = Instant.now(clock).minus(xrayReportsRetention.toMillis, ChronoUnit.MILLIS)
    httpClientV2
      .post(url"${xrayBaseUrl}?page_num=1&num_of_rows=100")
      .setHeader(
        "Authorization" -> s"Bearer $xrayToken",
        "Content-Type"  -> "application/json"
      ).withBody(Json.parse(
        s"""{"filters":{"author":"${xrayUsername}","start_time_range":{"start":"2023-06-01T00:00:00Z","end":"$cutOff"}}}"""
      ))
      .execute[Seq[ReportId]]

object XrayConnector:
  import play.api.libs.functional.syntax.toFunctionalBuilderOps

  case class ReportResponse(
    reportID: Int,
    status  : String,
  )

  object ReportResponse:
    val reads =
    ( (__ \ "report_id").read[Int]
    ~ (__ \ "status"   ).read[String]
    )(apply)

  case class ReportId(id: Int) extends AnyVal

  object ReportId:
    val reads = (__ \ "id").read[Int].map(ReportId.apply)

  case class ReportStatus(
    status        : String,
    numberOfRows  : Int,
    totalArtefacts: Int
  )

  object ReportStatus:
    val reads =
      ( (__ \ "status"         ).read[String]
      ~ (__ \ "number_of_rows" ).read[Int]
      ~ (__ \ "total_artifacts").read[Int]
      )(apply)

  case class Vulnerability(
    cves                 : Seq[CVE],
    cvss3MaxScore        : Option[Double],
    summary              : String,
    severity             : String,
    severitySource       : String,
    vulnerableComponent  : String,
    componentPhysicalPath: String,
    impactedArtefact     : String,
    impactPath           : Seq[String],
    path                 : String,
    fixedVersions        : Seq[String],
    published            : Instant,
    artefactScanTime     : Instant,
    issueId              : String,
    packageType          : String,
    provider             : String,
    description          : String,
    references           : Seq[String],
    projectKeys          : Seq[String],
  )

  object Vulnerability:
    val reads =
      given Reads[CVE] = CVE.reads
      ( (__ \ "cves"                   ).read[Seq[CVE]]
      ~ (__ \ "cvss3_max_score"        ).readNullable[Double]
      ~ (__ \ "summary"                ).read[String]
      ~ (__ \ "severity"               ).read[String]
      ~ (__ \ "severity_source"        ).read[String]
      ~ (__ \ "vulnerable_component"   ).read[String]
      ~ (__ \ "component_physical_path").read[String]
      ~ (__ \ "impacted_artifact"      ).read[String]
      ~ (__ \ "impact_path"            ).read[Seq[String]]
      ~ (__ \ "path"                   ).read[String]
      ~ (__ \ "fixed_versions"         ).read[Seq[String]]
      ~ (__ \ "published"              ).read[Instant]
      ~ (__ \ "artifact_scan_time"     ).read[Instant]
      ~ (__ \ "issue_id"               ).read[String]
      ~ (__ \ "package_type"           ).read[String]
      ~ (__ \ "provider"               ).read[String]
      ~ (__ \ "description"            ).read[String]
      ~ (__ \ "references"             ).read[Seq[String]]
      ~ (__ \ "project_keys"           ).read[Seq[String]]
      )(apply)

  case class CVE(
    cveId      : Option[String],
    cveV3Score : Option[Double],
    cveV3Vector: Option[String]
  )

  object CVE:
    val reads =
      ( (__ \ "cve"           ).readNullable[String]
      ~ (__ \ "cvss_v3_score" ).readNullable[Double]
      ~ (__ \ "cvss_v3_vector").readNullable[String]
      )(apply)
