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

import org.apache.pekko.stream.Materializer
import org.apache.pekko.stream.scaladsl.{Compression, Framing, Source}
import org.apache.pekko.util.ByteString
import play.api.{Configuration, Logging}
import uk.gov.hmrc.http.client.{HttpClientV2, readEitherSource}
import uk.gov.hmrc.http.{HeaderCarrier, StringContextOps, UpstreamErrorResponse}

import java.time.{LocalDate, ZoneOffset}
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class EpssScoreConnector @Inject() (
  configuration: Configuration,
  httpClientV2: HttpClientV2
)(using ExecutionContext, Materializer)
  extends Logging:

  private val epssScoreBaseUrl = configuration.get[String]("epss.downloadUrl")

  private def recentEpssUrl: String =
    val utcTodayIso = LocalDate.now(ZoneOffset.UTC).minusDays(1).toString
    val url         = s"${epssScoreBaseUrl.stripSuffix("/")}/epss_scores-$utcTodayIso.csv.gz"
    logger.info(s"URL for recent EPSS report: $url")
    url

  def downloadLatestReport()(using hc: HeaderCarrier): Future[GzippedDownloadResponse] =
    // report downloaded is in gzip format
    httpClientV2
      .get(url"$recentEpssUrl")
      .withProxy
      .stream[Either[UpstreamErrorResponse, Source[ByteString, _]]]
      .flatMap {
        case Left(error: UpstreamErrorResponse) => 
          logger.error(s"Upstream error downloading EPSS CSV: ${error.message}")
          Future.failed(error)
        case Left(error: Throwable) =>
          logger.error(s"Unknown error downloading EPSS CSV: ${error.getMessage}", error)
          Future.failed(error)
        case Right(source) =>
          // the response doesn't include headers to indicate gzip so we need to assume it is
          Future.successful(GzippedDownloadResponse(source, gzip = true))
      }

  def getLatestReportEpssScores()(using hc: HeaderCarrier): Future[EpssReport] =
    downloadLatestReport().filter(_.gzip)
                          .map(_.source)
                          .flatMap {
                            _
                              .via(Compression.gunzip())
                              .map { bytes =>
                                // Replace all Windows '\r' bytes with empty elements on the fly
                                bytes.filterNot(_ == '\r'.toByte)
                              }
                              .via(Framing.delimiter(ByteString("\n"), maximumFrameLength = 4096, allowTruncation = true))
                              .map(_.utf8String.trim)
                              .filterNot(_.isEmpty)
                              .drop(1) // drop header row
                              .map(_.split(",", 3).toList)
                              .map(EpssScore.fromCsvRow)
                              .runFold(EpssReport(Vector.empty, 0, Vector.empty)) {
                                case (report, Right(Some(epssScore))) =>
                                  report.copy(scores = report.scores :+ epssScore)
                                case (report, Right(None)) =>
                                  report
                                case (report, Left(error)) =>
                                  report.copy(
                                    errorCount = report.errorCount + 1,
                                    errors = report.errors :+ error
                                  )
                              }
                          }
                          .map { report =>
                            report.errors.groupBy(_.message).foreach { case (message, errors) =>
                              logger.warn(s"$message: ${errors.size} occurrences")
                            }
                            logger.info(
                              s"Imported EPSS report: ${report.scores.size} successful rows, ${report.errorCount} errors"
                            )
                            report
                          }


case class GzippedDownloadResponse(
  source: Source[ByteString, _],
  gzip: Boolean
) {

  def readLines(using Materializer): Future[Seq[String]] = {

    source
      .via(Compression.gunzip())
      .via(Framing.delimiter(ByteString("\n"), maximumFrameLength = 4096, allowTruncation = true))
      .map(_.utf8String)
      .runFold(Seq.empty[String])(_ :+ _)
  }
}

case class EpssReport(
  scores: Vector[EpssScore],
  errorCount: Int,
  errors: Vector[SkippedEpssRow]
)

case class EpssScore(cveId: String, score: Double, percentile: Double)

case class SkippedEpssRow(message: String, cause: Exception)

object EpssScore:

  def fromCsvRow(fields: List[String]): Either[SkippedEpssRow, Option[EpssScore]] =
    fields match {
      case initial :: _ if initial.trim.startsWith("#") => Right(None)
      case cveId :: epssStr :: percentileStr :: Nil =>
        try {
          Right(Some(EpssScore(cveId, epssStr.toDouble, percentileStr.toDouble)))
        } catch {
          case err: NumberFormatException =>
            Left(SkippedEpssRow("Unexpected number format in row import", err))
        }
      case fields =>
        Left(SkippedEpssRow(
          s"Malformed EPSS CSV Row: Expected 3 fields, found ${fields.size}",
          IllegalArgumentException(s"Malformed EPSS CSV Row: $fields")
        ))
    }
