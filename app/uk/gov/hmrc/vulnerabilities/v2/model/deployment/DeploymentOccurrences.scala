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

package uk.gov.hmrc.vulnerabilities.v2.model.deployment

import java.time.Instant
import play.api.libs.functional.syntax.*
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

case class ImportedBy(
  group   : String,
  artefact: String,
  version : String,
  scope   : Option[String] = None
)

object ImportedBy:
  val format: OFormat[ImportedBy] =
    ( (__ \ "group"   ).format[String]
    ~ (__ \ "artefact").format[String]
    ~ (__ \ "version" ).format[String]
    ~ (__ \ "scope"   ).formatNullable[String]
    )(ImportedBy.apply, Tuple.fromProductTyped)

case class DeploymentSla(
  deadline: Option[Instant],
  breached: Boolean,
  nearBreach: Boolean,
  status: Option[String] = None,
  clockStartedAt: Option[Instant] = None,
  breachedAt: Option[Instant] = None
)
object DeploymentSla:
  val apiWrites: OWrites[DeploymentSla] =
    ( (__ \ "deadline"      ).write[Option[Instant]]
    ~ (__ \ "breached"      ).write[Boolean]
    ~ (__ \ "nearBreach"    ).write[Boolean]
    ~ (__ \ "status"        ).writeNullable[String]
    ~ (__ \ "clockStartedAt").writeNullable[Instant]
    ~ (__ \ "breachedAt"    ).writeNullable[Instant]
    )((d: DeploymentSla) => Tuple.fromProductTyped(d))

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
  private val parentWrites: OWrites[ImportedBy] =
    ( (__ \ "group"   ).write[String]
    ~ (__ \ "artefact").write[String]
    ~ (__ \ "version" ).write[String]
    )(parent => (parent.group, parent.artefact, parent.version))

  val apiWrites: OWrites[DeploymentOccurrence] =
    ( (__ \ "occurrenceId"    ).write[String]
    ~ (__ \ "vulnerabilityId" ).write[String]
    ~ (__ \ "component"       ).write[String]
    ~ (__ \ "fixedVersions"   ).write[Seq[String]]
    ~ (__ \ "priority"        ).write[Priority]
    ~ (__ \ "state"           ).write[OccurrenceState]
    ~ (__ \ "sla"             ).write[DeploymentSla](DeploymentSla.apiWrites)
    ~ (__ \ "summary"         ).write[String]
    ~ (__ \ "componentVersion").writeNullable[String]
    ~ (__ \ "importedBy"      ).write[Seq[ImportedBy]](Writes.seq(parentWrites))
    ~ (__ \ "cvss"            ).writeNullable[Double]
    ~ (__ \ "epss"            ).writeNullable[Double]
    ~ (__ \ "kev"             ).writeNullable[Boolean]
    ~ (__ \ "serviceName"     ).write[String]
    ~ (__ \ "appVersion"      ).write[String]
    )((d: DeploymentOccurrence) => Tuple.fromProductTyped(d))

case class Page(limit: Int, offset: Int, total: Int)
object Page:
  val writes: OWrites[Page] =
    ( (__ \ "limit" ).write[Int]
    ~ (__ \ "offset").write[Int]
    ~ (__ \ "total" ).write[Int]
    )((p: Page) => Tuple.fromProductTyped(p))

case class DeploymentOccurrences(
  serviceName: String,
  appVersion: String,
  scanStatus: String,
  lastSuccessfulScan: Option[Instant],
  results: Seq[DeploymentOccurrence],
  page: Page
)
object DeploymentOccurrences:
  val writes: OWrites[DeploymentOccurrences] = OWrites(r => Json.obj(
    "serviceName"        -> r.serviceName,
    "appVersion"         -> r.appVersion,
    "scanStatus"         -> r.scanStatus,
    "lastSuccessfulScan" -> r.lastSuccessfulScan,
    "results"            -> JsArray(r.results.map(DeploymentOccurrence.apiWrites.writes)),
    "page"               -> Json.toJson(r.page)(Page.writes)
  ))

class ResourceLimit(message: String) extends RuntimeException(message)
class InconsistentData(message: String) extends RuntimeException(message)
