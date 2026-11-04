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

package uk.gov.hmrc.vulnerabilities.v2.support

import scala.collection.concurrent.TrieMap
import scala.concurrent.Future
import uk.gov.hmrc.vulnerabilities.v2.model.ingestion.*
import uk.gov.hmrc.vulnerabilities.v2.service.*

class FixtureDependencyEvidenceService extends DependencyEvidenceService:
  var values: Map[String, Seq[ImportedDependency]] = Map("CVE-2026-0001" -> Seq.empty)
  override def importedBy(findings: ScannerFindings): Future[Either[IngestionFailure, Map[String, Seq[ImportedDependency]]]] =
    def valueFor(finding: ScannerFinding): Option[Seq[ImportedDependency]] =
      values.get(finding.observationKey).orElse(
        values.collectFirst { case (key, value) if key.startsWith(s"${finding.vulnerabilityId}|") => value }
      )
    Future.successful:
      if !findings.findings.groupBy(_.vulnerabilityId).forall { case (id, observations) =>
        observations.size == 1 && values.contains(id) || observations.forall(f => valueFor(f).nonEmpty)
      } then
        Left(IngestionFailure.DependencyEvidenceUnavailable("No explicit dependency fixture for every finding"))
      else Right(
        findings.findings.groupBy(_.vulnerabilityId).toSeq.flatMap { case (id, observations) =>
          if observations.size == 1 then Seq(id -> values(id))
          else observations.map(f => f.observationKey -> valueFor(f).get)
        }.toMap
      )

/** Controlled evidence supplied by a test, not a claim about the deployed JFrog API. */
final case class ControlledReportEvidence(context: ScanContext, artefact: String, rawRows: Int, scannedArtefacts: Int = 1)

class ControlledArtifactCoverageVerifier extends ArtifactCoverageVerifier:
  private val reports = TrieMap.empty[Int, ControlledReportEvidence]
  def register(id: Int, evidence: ControlledReportEvidence): Unit = reports.put(id, evidence): Unit
  def clear(): Unit = reports.clear()
  override def verify(input: ArtifactCoverageInput): Either[IngestionFailure, ScanCompletion] =
    val matches = reports.get(input.reportId).exists: proof =>
      input.request.context == proof.context && input.request.expectedArtefact == proof.artefact &&
      input.reportStatus.status == "completed" && proof.scannedArtefacts == 1 &&
      input.reportStatus.totalArtefacts == proof.scannedArtefacts &&
      input.reportStatus.numberOfRows == proof.rawRows && input.report.rows.size == proof.rawRows &&
      input.artifactStatus.overall.status == "DONE" &&
      input.artifactStatus.details.flatMap(_.sca).exists(_.status == "DONE") &&
      input.report.rows.forall(row =>
        row.path == proof.artefact && row.impactedArtefact == proof.artefact.split("/").last)
    if matches then Right(ScanCompletion(true, true))
    else Left(IngestionFailure.CoverageRejected("Controlled report identity, artefact, lifecycle or raw-row evidence does not agree"))
