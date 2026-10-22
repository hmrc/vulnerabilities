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

package uk.gov.hmrc.vulnerabilities.support

import java.time.Instant
import scala.collection.concurrent.TrieMap
import scala.concurrent.Future
import uk.gov.hmrc.vulnerabilities.model.v2.deployment.{DeploymentSla, OccurrenceState, Priority}
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.*
import uk.gov.hmrc.vulnerabilities.service.v2.*

object FixtureInitialWorkflowPolicyV2 extends InitialWorkflowPolicyV2:
  override def initialValues(context: InitialWorkflowContextV2): Either[ScanPublicationErrorV2, InitialWorkflowValuesV2] =
    Right(InitialWorkflowValuesV2(Priority.immediate, OccurrenceState.actionable,
      DeploymentSla(Some(Instant.parse("2026-09-15T10:00:00Z")), breached = true, nearBreach = true,
        status = Some("running"), clockStartedAt = Some(Instant.parse("2026-09-01T10:00:00Z")),
        breachedAt = Some(Instant.parse("2026-09-15T10:00:00Z"))), synthetic = true))

class FixtureDependencyEvidenceServiceV2 extends DependencyEvidenceServiceV2:
  var values: Map[String, Seq[ImportedDependencyV2]] = Map("CVE-2026-0001" -> Seq.empty)
  override def importedBy(findings: ScannerFindingsV2): Future[Either[IngestionFailureV2, Map[String, Seq[ImportedDependencyV2]]]] =
    val ids = findings.findings.map(_.vulnerabilityId).toSet
    Future.successful:
      if !ids.subsetOf(values.keySet) then
        Left(IngestionFailureV2.DependencyEvidenceUnavailable("No explicit dependency fixture for every finding"))
      else Right(values.view.filterKeys(ids.contains).toMap)

/** Controlled evidence supplied by a test, not a claim about the deployed JFrog API. */
final case class ControlledReportEvidenceV2(context: ScanContextV2, artefact: String, rawRows: Int, scannedArtefacts: Int = 1)

class ControlledArtifactCoverageVerifierV2 extends ArtifactCoverageVerifierV2:
  private val reports = TrieMap.empty[Int, ControlledReportEvidenceV2]
  def register(id: Int, evidence: ControlledReportEvidenceV2): Unit = reports.put(id, evidence): Unit
  def clear(): Unit = reports.clear()
  override def verify(input: ArtifactCoverageInputV2): Either[IngestionFailureV2, ScanCompletionV2] =
    val matches = reports.get(input.reportId).exists: proof =>
      input.request.context == proof.context && input.request.expectedArtefact == proof.artefact &&
      input.reportStatus.status == "completed" && proof.scannedArtefacts == 1 &&
      input.reportStatus.totalArtefacts == proof.scannedArtefacts &&
      input.reportStatus.numberOfRows == proof.rawRows && input.report.rows.size == proof.rawRows &&
      input.artifactStatus.overall.status == "DONE" &&
      input.artifactStatus.details.flatMap(_.sca).exists(_.status == "DONE") &&
      input.report.rows.forall(row =>
        row.path == proof.artefact && row.impactedArtefact == proof.artefact.split("/").last)
    if matches then Right(ScanCompletionV2(true, true))
    else Left(IngestionFailureV2.CoverageRejected("Controlled report identity, artefact, lifecycle or raw-row evidence does not agree"))
