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

package uk.gov.hmrc.vulnerabilities.v2.connector

import play.api.libs.json.{JsError, JsSuccess, Json, Reads}
import scala.util.{Try, Using}
import uk.gov.hmrc.http.UpstreamErrorResponse
import com.fasterxml.jackson.core.JsonProcessingException
import uk.gov.hmrc.vulnerabilities.v2.model.xray.XrayReport
import org.apache.pekko.util.ByteString
import java.util.zip.ZipInputStream
import java.io.{ByteArrayInputStream, IOException}

object XrayResponseDecoder:  

  private def invalidResponse(message: String): UpstreamErrorResponse =
    InvalidXrayResponse(s"Invalid Xray v2 response: $message")

  def parseJson[A: Reads](bytes: Array[Byte]): A =
    val json = Try(Json.parse(bytes)).recover:
      case _: JsonProcessingException => throw invalidResponse("invalid JSON")
    json.get.validate[A] match
      case JsSuccess(value, _) => value
      case JsError(_)         => throw invalidResponse("invalid report schema")

  def unzipReport(bytes: ByteString, maxExportBytes: Int): XrayReport =
    Try {
      Using.resource(new ZipInputStream(new ByteArrayInputStream(bytes.toArray))): zip =>
        var expandedBytes = 0
        var report = Option.empty[XrayReport]
        var entry = zip.getNextEntry
        while entry != null do
          val content = zip.readNBytes(maxExportBytes - expandedBytes + 1)
          expandedBytes += content.length
          if expandedBytes > maxExportBytes then
            throw invalidResponse("expanded export exceeds size limit")
          if !entry.isDirectory then
            if report.nonEmpty then throw invalidResponse("export contains multiple data files")
            report = Some(parseJson[XrayReport](content))
          zip.closeEntry()
          entry = zip.getNextEntry
        report.getOrElse(throw invalidResponse("export contains no data file"))
    }.recover {
      case _: IOException | _: IllegalArgumentException => throw invalidResponse("malformed ZIP export")
    }.get
