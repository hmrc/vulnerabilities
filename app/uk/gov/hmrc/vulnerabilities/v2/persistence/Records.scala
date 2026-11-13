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
  references: Option[Seq[String]] = None,
  scanner_revision: Option[Long] = None
)
object VulnerabilityRecord:
  val mongoFormat: OFormat[VulnerabilityRecord] = Json.format[VulnerabilityRecord]

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
  val mongoFormat: OFormat[SlugOccurrenceRecord] = Json.format[SlugOccurrenceRecord]

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
  private given OFormat[ScannerObservation] = Json.format[ScannerObservation]
  given OFormat[ComponentObservation] = Json.format[ComponentObservation]

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
