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

package uk.gov.hmrc.vulnerabilities.v2.service

import javax.inject.Singleton
import uk.gov.hmrc.vulnerabilities.v2.model.ingestion.*
import scala.concurrent.Future

trait DependencyEvidenceService:
  def importedBy(findings: ScannerFindings): Future[Either[IngestionFailure, Map[String, Seq[ImportedDependency]]]]

@Singleton
class UnavailableDependencyEvidenceService extends DependencyEvidenceService:
  // BDOG-3994: likely source: ArtefactProcessorConnector.getMetaArtefact -> dependencyDotCompile
  // -> DependencyGraphParser -> ImportedDependency. Confirm authoritative repo/source, GAV/Scala suffixes,
  // direct/transitive/multiple importers, scopes, incomplete data, freshness and replacement semantics first.
  // V1's missing-data, JAR fallback and single-shortest-path choices are not approved V2 rules.
  override def importedBy(findings: ScannerFindings): Future[Either[IngestionFailure, Map[String, Seq[ImportedDependency]]]] =
    Future.successful:
      if findings.findings.isEmpty then Right(Map.empty)
      else Left(IngestionFailure.DependencyEvidenceUnavailable("Dependency source and interpretation are not approved"))
