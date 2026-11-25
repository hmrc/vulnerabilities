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

package uk.gov.hmrc.vulnerabilities.v2.persistence

import java.time.Instant
import play.api.libs.functional.syntax.*
import play.api.libs.json.*
import uk.gov.hmrc.mongo.play.json.formats.MongoJavatimeFormats
import uk.gov.hmrc.vulnerabilities.v2.model.deployment.{DeploymentSla, ImportedBy, OccurrenceState, Priority}
import uk.gov.hmrc.vulnerabilities.v2.model.ingestion.{EvidenceChanges, ScanPublicationReceipt, XrayFindingSource}

case class VulnerabilityRecord(
  vuln_id: String,
  summary: String,
  vuln_component: String,
  fixed_version: Seq[String],
  cvss_score: Option[Double],
  epss: Option[Double],
  kev: Option[Boolean],
  published_date: Instant,
  references: Option[Seq[String]] = None,
  scanner_revision: Option[Long] = None,
  guidance: Seq[Guidance] = Seq.empty
)
object VulnerabilityRecord:
  private val guidanceFormat = Format(Reads.seq(Guidance.format), Writes.seq(Guidance.format))
  val mongoFormat: OFormat[VulnerabilityRecord] =
    ( (__ \ "vuln_id"         ).format[String]
    ~ (__ \ "summary"         ).format[String]
    ~ (__ \ "vuln_component"  ).format[String]
    ~ (__ \ "fixed_version"   ).format[Seq[String]]
    ~ (__ \ "cvss_score"      ).formatNullable[Double]
    ~ (__ \ "epss"            ).formatNullable[Double]
    ~ (__ \ "kev"             ).formatNullable[Boolean]
    ~ (__ \ "published_date"  ).format[Instant](MongoJavatimeFormats.instantFormat)
    ~ (__ \ "references"      ).formatNullable[Seq[String]]
    ~ (__ \ "scanner_revision").formatNullable[Long]
    ~ (__ \ "guidance"        ).formatWithDefault[Seq[Guidance]](Seq.empty)(guidanceFormat)
    )(VulnerabilityRecord.apply, Tuple.fromProductTyped)

private val importedByFormat = Format(Reads.seq(ImportedBy.format), Writes.seq(ImportedBy.format))

case class SlugOccurrenceRecord(
  vuln_id: String,
  service: String,
  service_version: String,
  imported_by: Seq[ImportedBy],
  component_version: Option[String],
  scanner_observation: Option[ScannerObservation] = None,
  observations: Seq[ComponentObservation] = Seq.empty
)
object SlugOccurrenceRecord:
  private val observationsFormat = Format(Reads.seq(ComponentObservation.format), Writes.seq(ComponentObservation.format))
  val mongoFormat: OFormat[SlugOccurrenceRecord] =
    ( (__ \ "vuln_id"             ).format[String]
    ~ (__ \ "service"             ).format[String]
    ~ (__ \ "service_version"     ).format[String]
    ~ (__ \ "imported_by"         ).format[Seq[ImportedBy]](importedByFormat)
    ~ (__ \ "component_version"   ).formatNullable[String]
    ~ (__ \ "scanner_observation" ).formatNullable[ScannerObservation]
    ~ (__ \ "observations"        ).formatWithDefault[Seq[ComponentObservation]](Seq.empty)(observationsFormat)
    )(SlugOccurrenceRecord.apply, Tuple.fromProductTyped)

case class ServiceOccurrenceRecord(
  vuln_id: String,
  service: String,
  occurrence_id: String,
  first_detected: Instant,
  priority: Priority,
  state: OccurrenceState,
  sla: DeploymentSla,
  synthetic_initialisation: Option[Boolean] = None
)
object ServiceOccurrenceRecord:
  private given Format[Instant] = MongoJavatimeFormats.instantFormat
  private given OFormat[DeploymentSla] = Json.format[DeploymentSla]
  val mongoFormat: OFormat[ServiceOccurrenceRecord] = Json.format[ServiceOccurrenceRecord]

case class ScanRecord(
  service_name: String,
  service_version: String,
  scan_date: Instant,
  status: String,
  last_successful_scan: Option[Instant],
  run_id: Option[String] = None,
  generation: Option[Long] = None,
  source_report_generated: Option[Instant] = None
)
object ScanRecord:
  private given Format[Instant] = MongoJavatimeFormats.instantFormat
  val mongoFormat: OFormat[ScanRecord] = Json.format[ScanRecord]

case class HistoryActor(`type`: String, id: String)
object HistoryActor:
  given OFormat[HistoryActor] = Json.format[HistoryActor]

case class HistoryRecord(
  event_id: String,
  vuln_id: String,
  service: Option[String],
  event_type: String,
  occurred_at: Instant,
  actor: HistoryActor,
  changes: JsObject,
  reason: String,
  sources: Seq[JsObject]
)
object HistoryRecord:
  private given Format[Instant] = MongoJavatimeFormats.instantFormat
  val mongoFormat: OFormat[HistoryRecord] = Json.format[HistoryRecord]

case class DeploymentRecords(
  scan: ScanRecord,
  evidence: Seq[SlugOccurrenceRecord],
  vulnerabilities: Seq[VulnerabilityRecord],
  workflows: Seq[ServiceOccurrenceRecord]
)

case class ScannerObservation(
  run_id: String,
  summary: String,
  component: String,
  fixed_versions: Seq[String],
  cvss: Option[Double],
  references: Seq[String],
  sources: Seq[XrayFindingSource],
  source_report_generated: Option[Instant]
)
object ScannerObservation:
  private given Format[Instant] = MongoJavatimeFormats.instantFormat
  private given OFormat[XrayFindingSource] = Json.format[XrayFindingSource]
  given OFormat[ScannerObservation] = Json.format[ScannerObservation]

case class ComponentObservation(
  component: String,
  component_version: String,
  package_type: String,
  fixed_versions: Seq[String],
  imported_by: Seq[ImportedBy],
  scanner_observation: ScannerObservation
)
object ComponentObservation:
  private given OFormat[XrayFindingSource] = Json.format[XrayFindingSource]
  private val scannerFormat: OFormat[ScannerObservation] = Json.format[ScannerObservation]
  val format: OFormat[ComponentObservation] =
    ( (__ \ "component"           ).format[String]
    ~ (__ \ "component_version"   ).format[String]
    ~ (__ \ "package_type"        ).format[String]
    ~ (__ \ "fixed_versions"      ).format[Seq[String]]
    ~ (__ \ "imported_by"         ).format[Seq[ImportedBy]](importedByFormat)
    ~ (__ \ "scanner_observation" ).format[ScannerObservation](scannerFormat)
    )(ComponentObservation.apply, Tuple.fromProductTyped)

case class ScanAttemptRecord(
  run_id: String,
  service_name: String,
  service_version: String,
  generation: Long,
  admitted_at: Instant,
  digest: Option[String] = None,
  receipt: Option[ScanPublicationReceipt] = None,
  fingerprint_version: Option[Int] = None
)
object ScanAttemptRecord:
  private given Format[Instant] = MongoJavatimeFormats.instantFormat
  private given OFormat[EvidenceChanges] = Json.format[EvidenceChanges]
  given receiptFormat: OFormat[ScanPublicationReceipt] = Json.format[ScanPublicationReceipt]
  val mongoFormat: OFormat[ScanAttemptRecord] = Json.format[ScanAttemptRecord]

case class Guidance(
  id: String,
  guidance: Option[String],
  comment: Option[String],
  author: String,
  createdAt: Instant
)
object Guidance:
  val format: OFormat[Guidance] =
    ( (__ \ "id"       ).format[String]
    ~ (__ \ "guidance" ).formatNullable[String]
    ~ (__ \ "comment"  ).formatNullable[String]
    ~ (__ \ "author"   ).format[String]
    ~ (__ \ "createdAt").format[Instant]
    )(Guidance.apply, Tuple.fromProductTyped)
