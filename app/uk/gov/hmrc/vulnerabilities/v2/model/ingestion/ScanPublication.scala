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

package uk.gov.hmrc.vulnerabilities.v2.model.ingestion

import java.time.Instant
import uk.gov.hmrc.vulnerabilities.v2.model.deployment.{DeploymentSla, OccurrenceState, Priority}

/** Assertions from a trusted caller, not facts that mapping alone can establish. */
final case class ScanCompletion(reportSucceeded: Boolean, artefactCoverageVerified: Boolean)
final case class ImportedDependency(group: String, artefact: String, version: String)

enum WorkflowInitialisation:
  case ExistingOnly, UsePolicy

/** These are already shared persisted value types, not the Catalogue response envelope. */
final case class InitialWorkflowValues(
  priority: Priority,
  state: OccurrenceState,
  sla: DeploymentSla,
  synthetic: Boolean = false
)

final case class InitialWorkflowContext(context: ScanContext, finding: ScannerFinding, observedAt: Instant)

final case class PublishScan(
  runId: String,
  findings: ScannerFindings,
  completion: ScanCompletion,
  importedBy: Map[String, Seq[ImportedDependency]],
  workflowInitialisation: WorkflowInitialisation
)

final case class ScanAdmission(runId: String, context: ScanContext, generation: Long)
final case class EvidenceChanges(added: Seq[String], changed: Seq[String], removed: Seq[String])
final case class ScanPublicationReceipt(
  runId: String,
  generation: Long,
  publishedAt: Instant,
  evidenceChanges: EvidenceChanges
)

enum ScanPublicationError:
  case InvalidInput(reason: String)
  case UnverifiedScan
  case UnknownRun(runId: String)
  case RunIdentityConflict(runId: String)
  case Superseded(runId: String, publishedGeneration: Long)
  case AdoptionRequired(vulnerabilityId: String)
  case ScannerConflict(vulnerabilityId: String, fields: Seq[String], deployments: Seq[ScanContext])
  case InitialisationRequired(vulnerabilityId: String)
  case WorkflowPolicyUnavailable(vulnerabilityId: String)
  case UnsupportedFingerprintVersion(version: Int)
  case MissingImportedBy(vulnerabilityId: String)
  case ResourceLimit(reason: String)
  /** Retry/reconcile with the same run ID. A database error is not proof that commit rolled back. */
  case StorageFailure(cause: Throwable, commitMayHaveSucceeded: Boolean)
