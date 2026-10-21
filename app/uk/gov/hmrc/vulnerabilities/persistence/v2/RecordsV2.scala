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

package uk.gov.hmrc.vulnerabilities.persistence.v2

import java.time.Instant
import play.api.libs.json.*
import uk.gov.hmrc.mongo.play.json.formats.MongoJavatimeFormats
import uk.gov.hmrc.vulnerabilities.model.v2.deployment.{DeploymentSla, ImportedBy, OccurrenceState, Priority}
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.{EvidenceChangesV2, ScanPublicationReceiptV2, XrayFindingSourceV2}

// Partial projections: scanner updates must not replace documents containing other owners' fields.
case class VulnerabilityRecordV2(
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
object VulnerabilityRecordV2:
  val mongoFormat: OFormat[VulnerabilityRecordV2] = Json.format[VulnerabilityRecordV2]

case class SlugOccurrenceRecordV2(
  vuln_id: String,
  service: String,
  service_version: String,
  imported_by: Seq[ImportedBy],
  component_version: Option[String],
  scanner_observation: Option[ScannerObservationV2] = None
)
object SlugOccurrenceRecordV2:
  val mongoFormat: OFormat[SlugOccurrenceRecordV2] = Json.format[SlugOccurrenceRecordV2]

case class ServiceOccurrenceRecordV2(
  vuln_id: String,
  service: String,
  occurrence_id: String,
  first_detected: Instant,
  priority: Priority,
  state: OccurrenceState,
  sla: DeploymentSla,
  synthetic_initialisation: Option[Boolean] = None
)
object ServiceOccurrenceRecordV2:
  private given Format[Instant] = MongoJavatimeFormats.instantFormat
  private given OFormat[DeploymentSla] = Json.format[DeploymentSla]
  val mongoFormat: OFormat[ServiceOccurrenceRecordV2] = Json.format[ServiceOccurrenceRecordV2]

/** Last published success. Admission/failure must not change this deployment's visible state. */
case class ScanRecordV2(
  service_name: String,
  service_version: String,
  scan_date: Instant,
  status: String,
  last_successful_scan: Option[Instant],
  run_id: Option[String] = None,
  generation: Option[Long] = None,
  source_report_generated: Option[Instant] = None
)
object ScanRecordV2:
  private given Format[Instant] = MongoJavatimeFormats.instantFormat
  val mongoFormat: OFormat[ScanRecordV2] = Json.format[ScanRecordV2]

case class HistoryActorV2(`type`: String, id: String)
object HistoryActorV2:
  given OFormat[HistoryActorV2] = Json.format[HistoryActorV2]

case class HistoryRecordV2(
  event_id: String,
  vuln_id: String,
  service: Option[String],
  event_type: String,
  occurred_at: Instant,
  actor: HistoryActorV2,
  changes: JsObject,
  reason: String,
  sources: Seq[JsObject]
)
object HistoryRecordV2:
  private given Format[Instant] = MongoJavatimeFormats.instantFormat
  val mongoFormat: OFormat[HistoryRecordV2] = Json.format[HistoryRecordV2]

case class DeploymentRecordsV2(
  scan: ScanRecordV2,
  evidence: Seq[SlugOccurrenceRecordV2],
  vulnerabilities: Seq[VulnerabilityRecordV2],
  workflows: Seq[ServiceOccurrenceRecordV2]
)

case class ScannerObservationV2(
  run_id: String,
  summary: String,
  component: String,
  fixed_versions: Seq[String],
  cvss: Option[Double],
  references: Seq[String],
  sources: Seq[XrayFindingSourceV2],
  source_report_generated: Option[Instant]
)
object ScannerObservationV2:
  private given Format[Instant] = MongoJavatimeFormats.instantFormat
  private given OFormat[XrayFindingSourceV2] = Json.format[XrayFindingSourceV2]
  given OFormat[ScannerObservationV2] = Json.format[ScannerObservationV2]

case class ScanAttemptRecordV2(
  run_id: String,
  service_name: String,
  service_version: String,
  generation: Long,
  admitted_at: Instant,
  digest: Option[String] = None,
  receipt: Option[ScanPublicationReceiptV2] = None
)
object ScanAttemptRecordV2:
  private given Format[Instant] = MongoJavatimeFormats.instantFormat
  private given OFormat[EvidenceChangesV2] = Json.format[EvidenceChangesV2]
  given receiptFormat: OFormat[ScanPublicationReceiptV2] = Json.format[ScanPublicationReceiptV2]
  val mongoFormat: OFormat[ScanAttemptRecordV2] = Json.format[ScanAttemptRecordV2]
