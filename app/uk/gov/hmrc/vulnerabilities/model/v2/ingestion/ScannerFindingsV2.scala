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

package uk.gov.hmrc.vulnerabilities.model.v2.ingestion

import java.time.Instant
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}

final case class ScanContextV2(serviceName: ServiceName, appVersion: Version)

final case class MavenComponentV2(group: String, artefact: String, installedVersion: String):
  def identity: String = s"gav://$group:$artefact"

/** Source evidence only: descriptions, vectors and project keys do not establish guidance or ownership. */
final case class XrayFindingSourceV2(
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

final case class ScannerFindingV2(
  vulnerabilityId: String,
  summary: String,
  cvss: Option[Double],
  component: MavenComponentV2,
  fixedVersions: Seq[String],
  references: Seq[String],
  sources: Seq[XrayFindingSourceV2]
)

/** Mapping validity is not proof of completed report status or coverage of the requested artefact. */
final case class ScannerFindingsV2(
  context: ScanContextV2,
  generatedDate: Option[Instant],
  findings: Seq[ScannerFindingV2]
)

enum ConflictingFindingFieldV2:
  case component, installedVersion, fixedVersions, summary, cvss

enum XrayFindingMappingErrorV2:
  case InvalidContext(field: String, value: String)
  case UnsupportedCve(row: Int, issueId: String, cveIndex: Option[Int], value: Option[String])
  case InvalidCvss(row: Int, issueId: String, vulnerabilityId: Option[String], score: Double)
  case UnsupportedPackageType(row: Int, issueId: String, packageType: String)
  case UnsupportedCoordinateScheme(row: Int, issueId: String, coordinates: String)
  case MalformedComponentCoordinates(row: Int, issueId: String, coordinates: String)
  case ConflictingFindings(
    vulnerabilityId: String,
    rows: Seq[Int],
    fields: Seq[ConflictingFindingFieldV2],
    evidence: Seq[ScannerFindingV2]
  )
