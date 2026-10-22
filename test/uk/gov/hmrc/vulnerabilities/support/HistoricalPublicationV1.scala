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

import java.nio.charset.StandardCharsets.UTF_8
import java.security.MessageDigest
import play.api.libs.json.*
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.*
import uk.gov.hmrc.vulnerabilities.persistence.v2.ScannerObservationV2

/** Frozen fingerprint algorithm from 73a6e72 ScanPublisherV2:144-158, independent of the new codec. */
object HistoricalPublicationV1:
  private enum Initialisation:
    case ExistingOnly, SyntheticSeed

  def fingerprint(input: PublishScanV2): String =
    val oldMode = input.workflowInitialisation match
      case WorkflowInitialisationV2.ExistingOnly => Initialisation.ExistingOnly
      case WorkflowInitialisationV2.UsePolicy => Initialisation.SyntheticSeed
    val json = Json.obj(
      "run" -> input.runId,
      "service" -> input.findings.context.serviceName.asString,
      "version" -> input.findings.context.appVersion.original,
      "initialisation" -> oldMode.toString,
      "findings" -> input.findings.findings.sortBy(_.vulnerabilityId).map { finding =>
        val observation = ScannerObservationV2(input.runId, finding.summary, finding.component.identity,
          finding.fixedVersions, finding.cvss, finding.references, finding.sources, input.findings.generatedDate)
        Json.obj("id" -> finding.vulnerabilityId, "installed" -> finding.component.installedVersion,
          "observation" -> observation,
          "importedBy" -> input.importedBy.get(finding.vulnerabilityId).map(_.map(d =>
            Json.obj("group" -> d.group, "artefact" -> d.artefact, "version" -> d.version))))
      },
      "generated" -> input.findings.generatedDate
    )
    MessageDigest.getInstance("SHA-256").digest(Json.stringify(json).getBytes(UTF_8)).map(b => f"${b & 0xff}%02x").mkString
