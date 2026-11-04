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

package uk.gov.hmrc.vulnerabilities.v2.model.ingestion

import java.time.Instant
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}

final case class ScanContext(serviceName: ServiceName, appVersion: Version)

final case class MavenComponent(group: String, artefact: String, installedVersion: String):
  def identity: String = s"gav://$group:$artefact"
  def packageType: String = "maven"

/** Source evidence only: descriptions, vectors and project keys do not establish guidance or ownership. */
final case class XrayFindingSource(
  issueId: String,
  cvssVector: Option[String],
  rowMaxCvss: Option[Double],
  severity: String,
  severitySource: Option[String],
  componentPhysicalPath: String,
  impactedArtefact: String,
  impactPath: Seq[String],
  path: String,
  published: Instant,
  artefactScanTime: Instant,
  provider: Option[String],
  description: Option[String],
  projectKeys: Seq[String]
)

final case class ScannerFinding(
  vulnerabilityId: String,
  summary: String,
  cvss: Option[Double],
  component: MavenComponent,
  fixedVersions: Seq[String],
  references: Seq[String],
  sources: Seq[XrayFindingSource]
):
  def observationKey: String =
    s"$vulnerabilityId|${component.identity}|${component.installedVersion}|${fixedVersions.sorted.mkString("\u0000")}"

/** Mapping validity is not proof of completed report status or coverage of the requested artefact. */
final case class ScannerFindings(
  context: ScanContext,
  generatedDate: Option[Instant],
  findings: Seq[ScannerFinding]
)

enum ConflictingFindingField:
  case component, installedVersion, fixedVersions, summary, cvss

enum XrayFindingMappingError:
  case InvalidContext(field: String, value: String)
  case UnsupportedCve(row: Int, issueId: String, cveIndex: Option[Int], value: Option[String])
  case InvalidCvss(row: Int, issueId: String, vulnerabilityId: Option[String], score: Double)
  case UnsupportedPackageType(row: Int, issueId: String, packageType: String)
  case UnsupportedCoordinateScheme(row: Int, issueId: String, coordinates: String)
  case MalformedComponentCoordinates(row: Int, issueId: String, coordinates: String)
  case ConflictingFindings(
    vulnerabilityId: String,
    rows: Seq[Int],
    fields: Seq[ConflictingFindingField],
    evidence: Seq[ScannerFinding]
  )
