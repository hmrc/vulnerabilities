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

trait ArtifactCoverageVerifierV2:
  def verify(input: ArtifactCoverageInputV2): Either[IngestionFailureV2, ScanCompletionV2]

@Singleton
class JfrogArtifactCoverageVerifierV2 extends ArtifactCoverageVerifierV2:
  // BDOG-3994: production verification outstanding. DONE is not report/revision correlation.
  // Replace this rejection only after HMRC path/scope, SCA freshness, count and safe-empty semantics
  // are confirmed; do not infer coverage from a basename filter, HTTP success or scan timestamps alone.
  override def verify(input: ArtifactCoverageInputV2): Either[IngestionFailureV2, ScanCompletionV2] =
    Left(IngestionFailureV2.CoverageUnverified(
      "HMRC artefact revision, freshness and completed-report correlation contract is unverified"))
