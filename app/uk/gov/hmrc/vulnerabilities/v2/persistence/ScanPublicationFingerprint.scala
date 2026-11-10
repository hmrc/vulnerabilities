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

package uk.gov.hmrc.vulnerabilities.v2.persistence

import java.nio.charset.StandardCharsets.UTF_8
import java.security.MessageDigest
import play.api.libs.json.*
import uk.gov.hmrc.vulnerabilities.v2.model.ingestion.*

private[vulnerabilities] object ScanPublicationFingerprint:
  val currentVersion = 2

  def observation(input: PublishScan, finding: ScannerFinding): ScannerObservation =
    ScannerObservation(input.runId, finding.summary, finding.component.identity, finding.fixedVersions,
      finding.cvss, finding.references, finding.sources, input.findings.generatedDate)

  def legacy(input: PublishScan): String =
    hash(payload(input, input.workflowInitialisation match
      case WorkflowInitialisation.ExistingOnly => "ExistingOnly"
      case WorkflowInitialisation.UsePolicy => "SyntheticSeed"))

  def current(input: PublishScan): String =
    val intent = input.workflowInitialisation match
      case WorkflowInitialisation.ExistingOnly => "existing-only"
      case WorkflowInitialisation.UsePolicy => "configured-policy"
    val importedBy = JsObject(input.importedBy.toSeq.map{ case (key, dependencies) => 
      key -> JsArray(dependencies.map(d => 
        Json.obj(
          "group" -> d.group,
          "artefact" -> d.artefact, 
          "version" -> d.version
          )
        )
      )
    })
    hash(canonical(Json.obj(
      "format" -> currentVersion, 
      "payload" -> payload(input, intent),
      "importedBy" -> importedBy
    )))

  private def payload(input: PublishScan, intent: String): JsObject =
    Json.obj(
      "run" -> input.runId,
      "service" -> input.findings.context.serviceName.asString,
      "version" -> input.findings.context.appVersion.original,
      "initialisation" -> intent,
      "findings" -> input.findings.findings.sortBy(f => (f.vulnerabilityId, f.observationKey)).map { finding =>
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
