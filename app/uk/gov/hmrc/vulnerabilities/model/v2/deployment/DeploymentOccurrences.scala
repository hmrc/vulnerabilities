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

package uk.gov.hmrc.vulnerabilities.model.v2.deployment

import java.time.Instant
import play.api.libs.json.*

enum Priority:
  case immediate, expedite, schedule, monitor

object Priority:
  given Format[Priority] = stringEnum(Priority.valueOf)

enum OccurrenceState:
  case actionable, notApplicable, noFixAvailable, riskAccepted, resolved

object OccurrenceState:
  given Format[OccurrenceState] = stringEnum(OccurrenceState.valueOf)

private def stringEnum[A](parse: String => A): Format[A] = Format(
  Reads.StringReads.flatMap(s =>
    scala.util.Try(parse(s)).fold(_ => Reads(_ => JsError("Unknown enum value")), Reads.pure)
  ),
  Writes(a => JsString(a.toString))
)

case class ImportedBy(group: String, artefact: String, version: String)
object ImportedBy:
  given OFormat[ImportedBy] = Json.format[ImportedBy]

case class DeploymentSla(
  deadline: Option[Instant],
  breached: Boolean,
  nearBreach: Boolean,
  status: Option[String] = None,
  clockStartedAt: Option[Instant] = None,
  breachedAt: Option[Instant] = None
)
object DeploymentSla:
  given OFormat[DeploymentSla] = Json.format[DeploymentSla]
  val apiWrites: OWrites[DeploymentSla] = OWrites(s =>
    Json.toJsObject(s) ++ Json.obj("deadline" -> s.deadline)
  )

case class DeploymentOccurrence(
  occurrenceId: String,
  vulnerabilityId: String,
  component: String,
  fixedVersions: Seq[String],
  priority: Priority,
  state: OccurrenceState,
  sla: DeploymentSla,
  summary: String,
  componentVersion: Option[String] = None,
  importedBy: Seq[ImportedBy] = Seq.empty,
  cvss: Option[Double] = None,
  epss: Option[Double] = None,
  kev: Option[Boolean] = None,
  serviceName: String,
  appVersion: String
)
object DeploymentOccurrence:
  given OFormat[DeploymentOccurrence] = Json.format[DeploymentOccurrence]
  val apiWrites: OWrites[DeploymentOccurrence] = OWrites(o =>
    Json.toJsObject(o) ++ Json.obj("sla" -> DeploymentSla.apiWrites.writes(o.sla))
  )

case class Page(limit: Int, offset: Int, total: Int)
object Page:
  given OFormat[Page] = Json.format[Page]

case class DeploymentOccurrences(
  serviceName: String,
  appVersion: String,
  scanStatus: String,
  lastSuccessfulScan: Option[Instant],
  results: Seq[DeploymentOccurrence],
  page: Page
)
object DeploymentOccurrences:
  given OWrites[DeploymentOccurrences] = OWrites(r => Json.obj(
    "serviceName" -> r.serviceName,
    "appVersion" -> r.appVersion,
    "scanStatus" -> r.scanStatus,
    "lastSuccessfulScan" -> r.lastSuccessfulScan,
    "results" -> JsArray(r.results.map(DeploymentOccurrence.apiWrites.writes)),
    "page" -> r.page
  ))

class V2ResourceLimit(message: String) extends RuntimeException(message)
class InconsistentV2Data(message: String) extends RuntimeException(message)
