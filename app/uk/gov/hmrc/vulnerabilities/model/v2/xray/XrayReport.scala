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

package uk.gov.hmrc.vulnerabilities.model.v2.xray

import java.time.Instant
import play.api.libs.functional.syntax.*
import play.api.libs.json.{Json, OFormat, __}

final case class XrayReport(
  generatedDate: Option[Instant],
  rows         : Seq[XrayReport.Vulnerability]
)

object XrayReport:
  final case class ReportRequest(reportId: Int, status: String)

  object ReportRequest:
    given format: OFormat[ReportRequest] =
      ( (__ \ "report_id").format[Int]
      ~ (__ \ "status"   ).format[String]
      )(apply, r => (r.reportId, r.status))

  final case class ReportStatus(status: String, numberOfRows: Int, totalArtefacts: Int)

  object ReportStatus:
    given format: OFormat[ReportStatus] =
      ( (__ \ "status"         ).format[String]
      ~ (__ \ "number_of_rows" ).format[Int]
      ~ (__ \ "total_artifacts").format[Int]
      )(apply, r => (r.status, r.numberOfRows, r.totalArtefacts))

  final case class CVE(
    cveId      : Option[String],
    cveV3Score : Option[Double],
    cveV3Vector: Option[String]
  )

  object CVE:
    given format: OFormat[CVE] =
      ( (__ \ "cve"           ).formatNullable[String]
      ~ (__ \ "cvss_v3_score" ).formatNullable[Double]
      ~ (__ \ "cvss_v3_vector").formatNullable[String]
      )(apply, c => (c.cveId, c.cveV3Score, c.cveV3Vector))

  final case class Vulnerability(
    cves                 : Seq[CVE],
    cvss3MaxScore        : Option[Double],
    summary              : String,
    severity             : String,
    severitySource       : Option[String],
    vulnerableComponent  : String,
    componentPhysicalPath: String,
    impactedArtefact     : String,
    impactPath           : Seq[String],
    path                 : String,
    fixedVersions        : Seq[String],
    published            : Instant,
    artefactScanTime     : Instant,
    issueId              : String,
    packageType          : String,
    provider             : Option[String],
    description          : Option[String],
    references           : Seq[String],
    projectKeys          : Seq[String]
  )

  object Vulnerability:
    given format: OFormat[Vulnerability] =
      ( (__ \ "cves"                   ).format[Seq[CVE]]
      ~ (__ \ "cvss3_max_score"         ).formatNullable[Double]
      ~ (__ \ "summary"                ).format[String]
      ~ (__ \ "severity"               ).format[String]
      ~ (__ \ "severity_source"        ).formatNullable[String]
      ~ (__ \ "vulnerable_component"   ).format[String]
      ~ (__ \ "component_physical_path").format[String]
      ~ (__ \ "impacted_artifact"      ).format[String]
      ~ (__ \ "impact_path"            ).format[Seq[String]]
      ~ (__ \ "path"                   ).format[String]
      ~ (__ \ "fixed_versions"         ).format[Seq[String]]
      ~ (__ \ "published"              ).format[Instant]
      ~ (__ \ "artifact_scan_time"     ).format[Instant]
      ~ (__ \ "issue_id"               ).format[String]
      ~ (__ \ "package_type"           ).format[String]
      ~ (__ \ "provider"               ).formatNullable[String]
      ~ (__ \ "description"            ).formatNullable[String]
      ~ (__ \ "references"             ).formatWithDefault[Seq[String]](Nil)
      ~ (__ \ "project_keys"           ).format[Seq[String]]
      )(apply, v => Tuple.fromProductTyped(v))

  given format: OFormat[XrayReport] = Json.format[XrayReport]
