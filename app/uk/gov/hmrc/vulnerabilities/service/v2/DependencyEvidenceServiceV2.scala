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

package uk.gov.hmrc.vulnerabilities.service.v2

import javax.inject.Singleton
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.*
import scala.concurrent.Future

trait DependencyEvidenceServiceV2:
  def importedBy(findings: ScannerFindingsV2): Future[Either[IngestionFailureV2, Map[String, Seq[ImportedDependencyV2]]]]

@Singleton
class UnavailableDependencyEvidenceServiceV2 extends DependencyEvidenceServiceV2:
  // BDOG-3994: likely source: ArtefactProcessorConnector.getMetaArtefact -> dependencyDotCompile
  // -> DependencyGraphParser -> ImportedDependencyV2. Confirm authoritative repo/source, GAV/Scala suffixes,
  // direct/transitive/multiple importers, scopes, incomplete data, freshness and replacement semantics first.
  // V1's missing-data, JAR fallback and single-shortest-path choices are not approved V2 rules.
  override def importedBy(findings: ScannerFindingsV2): Future[Either[IngestionFailureV2, Map[String, Seq[ImportedDependencyV2]]]] =
    Future.successful:
      if findings.findings.isEmpty then Right(Map.empty)
      else Left(IngestionFailureV2.DependencyEvidenceUnavailable("Dependency source and interpretation are not approved"))
