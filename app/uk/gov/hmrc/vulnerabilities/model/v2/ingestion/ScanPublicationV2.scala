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

package uk.gov.hmrc.vulnerabilities.model.v2.ingestion

import java.time.Instant
import uk.gov.hmrc.vulnerabilities.model.v2.deployment.{DeploymentSla, OccurrenceState, Priority}

/** Assertions from a trusted caller, not facts that mapping alone can establish. */
final case class ScanCompletionV2(reportSucceeded: Boolean, artefactCoverageVerified: Boolean)
final case class ImportedDependencyV2(group: String, artefact: String, version: String)

enum WorkflowInitialisationV2:
  case ExistingOnly, UsePolicy

/** These are already shared persisted value types, not the Catalogue response envelope. */
final case class InitialWorkflowValuesV2(
  priority: Priority,
  state: OccurrenceState,
  sla: DeploymentSla,
  synthetic: Boolean = false
)

final case class InitialWorkflowContextV2(context: ScanContextV2, finding: ScannerFindingV2, observedAt: Instant)

final case class PublishScanV2(
  runId: String,
  findings: ScannerFindingsV2,
  completion: ScanCompletionV2,
  importedBy: Map[String, Seq[ImportedDependencyV2]],
  workflowInitialisation: WorkflowInitialisationV2
)

final case class ScanAdmissionV2(runId: String, context: ScanContextV2, generation: Long)
final case class EvidenceChangesV2(added: Seq[String], changed: Seq[String], removed: Seq[String])
final case class ScanPublicationReceiptV2(
  runId: String,
  generation: Long,
  publishedAt: Instant,
  evidenceChanges: EvidenceChangesV2
)

enum ScanPublicationErrorV2:
  case InvalidInput(reason: String)
  case UnverifiedScan
  case UnknownRun(runId: String)
  case RunIdentityConflict(runId: String)
  case Superseded(runId: String, publishedGeneration: Long)
  case AdoptionRequired(vulnerabilityId: String)
  case ScannerConflict(vulnerabilityId: String, fields: Seq[String], deployments: Seq[ScanContextV2])
  case InitialisationRequired(vulnerabilityId: String)
  case WorkflowPolicyUnavailable(vulnerabilityId: String)
  case UnsupportedFingerprintVersion(version: Int)
  case MissingImportedBy(vulnerabilityId: String)
  case ResourceLimit(reason: String)
  /** Retry/reconcile with the same run ID. A database error is not proof that commit rolled back. */
  case StorageFailure(cause: Throwable, commitMayHaveSucceeded: Boolean)
