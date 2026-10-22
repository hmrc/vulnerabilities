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

trait InitialWorkflowPolicyV2:
  /** Must remain pure and deterministic: Mongo may retry preparation with the same observation time. */
  def initialValues(context: InitialWorkflowContextV2): Either[ScanPublicationErrorV2, InitialWorkflowValuesV2]

@Singleton
class UnavailableInitialWorkflowPolicyV2 extends InitialWorkflowPolicyV2:
  // BDOG-3994: initial priority/state and SLA start/duration/pause/breach rules are not approved.
  // Implement here once approved inputs and rules exist; no fixture or clock-based fallback is safe.
  override def initialValues(context: InitialWorkflowContextV2): Either[ScanPublicationErrorV2, InitialWorkflowValuesV2] =
    Left(ScanPublicationErrorV2.WorkflowPolicyUnavailable(context.finding.vulnerabilityId))
