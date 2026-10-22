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

package uk.gov.hmrc.vulnerabilities.model.v2.xray

import java.time.Instant
import play.api.libs.json.{Json, JsonValidationError, Reads}

/** Wire data, not proof that a particular report covers an artefact revision.
  * Status strings are preserved, including unknown values; decoding cannot authorise publication.
  */
final case class XrayArtifactStatusV2(
  overall: XrayArtifactStatusV2.Status,
  details: Option[XrayArtifactStatusV2.Details]
)

object XrayArtifactStatusV2:
  final case class Status(status: String, time: Option[Instant])
  object Status:
    given Reads[Status] = Json.reads[Status].filter(JsonValidationError("Blank scan status"))(!_.status.isBlank)

  // Only SCA details are needed by this boundary; unrelated scan products do not establish SCA coverage.
  final case class Details(sca: Option[Status])
  object Details:
    given Reads[Details] = Json.reads[Details]

  given Reads[XrayArtifactStatusV2] = Json.reads[XrayArtifactStatusV2]
