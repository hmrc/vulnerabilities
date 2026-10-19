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

import javax.inject.{Inject, Singleton}
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.model.v2.deployment.*
import uk.gov.hmrc.vulnerabilities.persistence.v2.{DeploymentRecordsV2, DeploymentStoreV2}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class DeploymentOccurrencesService @Inject()(store: DeploymentStoreV2)(using ExecutionContext):
  def get(service: ServiceName, version: Version): Future[Option[DeploymentOccurrences]] =
    store.read(service.asString, version.original).map(_.map(assemble))

  private def assemble(records: DeploymentRecordsV2): DeploymentOccurrences =
    val scan = records.scan
    def inconsistent(message: String): Nothing = throw InconsistentV2Data(s"Inconsistent V2 deployment: $message")
    if scan.status.trim.isEmpty then inconsistent("empty scan status")
    if scan.status == "succeeded" && scan.last_successful_scan.isEmpty then
      inconsistent("successful scan has no last successful scan timestamp")
    val details = records.vulnerabilities.map(v => v.vuln_id -> v).toMap
    val workflows = records.workflows.map(w => w.vuln_id -> w).toMap
    val ids = records.evidence.map(_.vuln_id)
    if ids.distinct.size != ids.size || details.size != records.vulnerabilities.size ||
      workflows.size != records.workflows.size then inconsistent("duplicate join keys")
    val rows = records.evidence.map: e =>
      val d = details.getOrElse(e.vuln_id, inconsistent("missing vulnerability details"))
      val w = workflows.getOrElse(e.vuln_id, inconsistent("missing service workflow"))
      if w.occurrence_id.trim.isEmpty then inconsistent("empty occurrence identifier")
      DeploymentOccurrence(
        occurrenceId = w.occurrence_id, vulnerabilityId = d.vuln_id, component = d.vuln_component,
        fixedVersions = d.fixed_version, priority = w.priority, state = w.state, sla = w.sla,
        summary = d.summary, componentVersion = e.component_version, importedBy = e.imported_by,
        cvss = d.cvss_score, epss = d.epss, kev = d.kev,
        serviceName = scan.service_name, appVersion = scan.service_version
      )
    DeploymentOccurrences(scan.service_name, scan.service_version, scan.status, scan.last_successful_scan,
      rows, Page(rows.size, 0, rows.size))
