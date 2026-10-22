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

import java.nio.charset.StandardCharsets.UTF_8
import java.security.MessageDigest
import play.api.libs.json.*
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.*

private[vulnerabilities] object ScanPublicationFingerprintV2:
  val currentVersion = 2

  def observation(input: PublishScanV2, finding: ScannerFindingV2): ScannerObservationV2 =
    ScannerObservationV2(input.runId, finding.summary, finding.component.identity, finding.fixedVersions,
      finding.cvss, finding.references, finding.sources, input.findings.generatedDate)

  // Keep field order and Mongo instant encoding exactly as committed in 73a6e72.
  // The old label is compatibility data only, never a workflow creation option.
  def legacy(input: PublishScanV2): String =
    hash(payload(input, input.workflowInitialisation match
      case WorkflowInitialisationV2.ExistingOnly => "ExistingOnly"
      case WorkflowInitialisationV2.UsePolicy => "SyntheticSeed"))

  def current(input: PublishScanV2): String =
    val intent = input.workflowInitialisation match
      case WorkflowInitialisationV2.ExistingOnly => "existing-only"
      case WorkflowInitialisationV2.UsePolicy => "configured-policy"
    hash(canonical(Json.obj("format" -> currentVersion, "payload" -> payload(input, intent))))

  private def payload(input: PublishScanV2, intent: String): JsObject =
    Json.obj(
      "run" -> input.runId,
      "service" -> input.findings.context.serviceName.asString,
      "version" -> input.findings.context.appVersion.original,
      "initialisation" -> intent,
      "findings" -> input.findings.findings.sortBy(_.vulnerabilityId).map { finding =>
        Json.obj("id" -> finding.vulnerabilityId, "installed" -> finding.component.installedVersion,
          "observation" -> observation(input, finding),
          "importedBy" -> input.importedBy.get(finding.vulnerabilityId).map(_.map(d =>
            Json.obj("group" -> d.group, "artefact" -> d.artefact, "version" -> d.version))))
      },
      "generated" -> input.findings.generatedDate
    )

  private def canonical(value: JsValue): JsValue = value match
    case obj: JsObject => JsObject(obj.fields.sortBy(_._1).map((key, item) => key -> canonical(item)))
    case JsArray(items) => JsArray(items.map(canonical))
    case other => other

  private def hash(value: JsValue): String =
    MessageDigest.getInstance("SHA-256").digest(Json.stringify(value).getBytes(UTF_8))
      .map(b => f"${b & 0xff}%02x").mkString
