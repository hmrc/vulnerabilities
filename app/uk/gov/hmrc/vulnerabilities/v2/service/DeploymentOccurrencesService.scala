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

import javax.inject.{Inject, Singleton}
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.v2.model.deployment.*
import uk.gov.hmrc.vulnerabilities.v2.persistence.ScannerObservation
import uk.gov.hmrc.vulnerabilities.v2.persistence.{ComponentObservation, DeploymentRecords, DeploymentStore}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class DeploymentOccurrencesService @Inject()(store: DeploymentStore)(using ExecutionContext):
  def get(service: ServiceName, version: Version): Future[Option[DeploymentOccurrences]] =
    store.read(service.asString, version.original).map(_.map(assemble))

  private def assemble(records: DeploymentRecords): DeploymentOccurrences =
    val scan = records.scan
    def inconsistent(message: String): Nothing = throw InconsistentData(s"Inconsistent V2 deployment: $message")
    if scan.status.trim.isEmpty then inconsistent("empty scan status")
    if scan.status == "succeeded" && scan.last_successful_scan.isEmpty then
      inconsistent("successful scan has no last successful scan timestamp")
    val details = records.vulnerabilities.map(v => v.vuln_id -> v).toMap
    val workflows = records.workflows.map(w => w.vuln_id -> w).toMap
    val ids = records.evidence.map(_.vuln_id)
    if ids.distinct.size != ids.size || details.size != records.vulnerabilities.size ||
      workflows.size != records.workflows.size then inconsistent("duplicate join keys")
    val rows = records.evidence.flatMap: e =>
      val d = details.getOrElse(e.vuln_id, inconsistent("missing vulnerability details"))
      val w = workflows.getOrElse(e.vuln_id, inconsistent("missing service workflow"))
      if w.occurrence_id.trim.isEmpty then inconsistent("empty occurrence identifier")
      val observations =
        if e.observations.nonEmpty then e.observations
        else e.scanner_observation match
          case Some(observation) =>
            Seq(ComponentObservation(observation.component, e.component_version.getOrElse(""), "maven",
              observation.fixed_versions, e.imported_by, observation))
          case None if e.component_version.nonEmpty =>
            Seq(ComponentObservation(d.vuln_component, e.component_version.get, "maven",
              d.fixed_version, e.imported_by,
              ScannerObservation("", d.summary, d.vuln_component, d.fixed_version, d.cvss_score,
                d.references.getOrElse(Seq.empty), Seq.empty, None)))
          case None => Seq.empty
      observations.map: observation =>
        DeploymentOccurrence(
          occurrenceId = w.occurrence_id, vulnerabilityId = d.vuln_id, component = observation.component,
          fixedVersions = observation.fixed_versions, priority = w.priority, state = w.state, sla = w.sla,
          summary = d.summary, componentVersion = Some(observation.component_version), importedBy = observation.imported_by,
          cvss = d.cvss_score, epss = d.epss, kev = d.kev,
          serviceName = scan.service_name, appVersion = scan.service_version
        )
    DeploymentOccurrences(scan.service_name, scan.service_version, scan.status, scan.last_successful_scan,
      rows, Page(rows.size, 0, rows.size))
