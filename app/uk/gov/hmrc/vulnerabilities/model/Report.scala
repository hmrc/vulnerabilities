/*
 * Copyright 2023 HM Revenue & Customs
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

package uk.gov.hmrc.vulnerabilities.model

import play.api.libs.functional.syntax.toFunctionalBuilderOps
import play.api.libs.json.{Format, OFormat, Reads, Writes, OWrites, __}
import uk.gov.hmrc.mongo.play.json.formats.MongoJavatimeFormats

import java.time.Instant

case class Report(
  serviceName   : ServiceName,
  serviceVersion: Version,
  slugUri       : String,
  rows          : Seq[Report.Vulnerability],
  generatedDate : Instant,
  scanned       : Boolean,
  latest        : Boolean,
  production    : Boolean,
  qa            : Boolean,
  staging       : Boolean,
  development   : Boolean,
  externalTest  : Boolean,
  integration   : Boolean
)

object Report:
  private def format(using Format[Vulnerability], Format[Instant]): Format[Report] =
    ( (__ \ "serviceName"   ).format[ServiceName]
    ~ (__ \ "serviceVersion").format[Version]
    ~ (__ \ "slugUri"       ).format[String]
    ~ (__ \ "rows"          ).format[Seq[Report.Vulnerability]]
    ~ (__ \ "generatedDate" ).format[Instant]
    ~ (__ \ "scanned"       ).format[Boolean]
    ~ (__ \ "latest"        ).formatWithDefault[Boolean](false)
    ~ (__ \ "production"    ).formatWithDefault[Boolean](false)
    ~ (__ \ "qa"            ).formatWithDefault[Boolean](false)
    ~ (__ \ "staging"       ).formatWithDefault[Boolean](false)
    ~ (__ \ "development"   ).formatWithDefault[Boolean](false)
    ~ (__ \ "externaltest"  ).formatWithDefault[Boolean](false)
    ~ (__ \ "integration"   ).formatWithDefault[Boolean](false)
    )(apply, pt => Tuple.fromProductTyped(pt))

  val apiFormat   = format(using Report.Vulnerability.apiFormat  , summon[Format[Instant]]) // For Integration Test
  val mongoFormat = format(using Report.Vulnerability.mongoFormat, MongoJavatimeFormats.instantFormat)

  case class Vulnerability(
    cves                 : Seq[CVE],
    cvss3MaxScore        : Option[Double],
    summary              : String,
    severity             : String,
    severitySource       : String,
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
    provider             : String,
    description          : String,
    references           : Seq[String],
    projectKeys          : Seq[String],
    importedBy           : Option[ImportedBy]
  )

  object Vulnerability:
    import uk.gov.hmrc.vulnerabilities.connector.XrayConnector.{Vulnerability as XrayVulnerability}
    def apply(xrayVulnerability: XrayVulnerability, importedBy: Option[ImportedBy]): Vulnerability =
      Vulnerability(
        cves                  = xrayVulnerability.cves.map(x => CVE(cveId = x.cveId, cveV3Score = x.cveV3Score, cveV3Vector = x.cveV3Vector))
      , cvss3MaxScore         = xrayVulnerability.cvss3MaxScore
      , summary               = xrayVulnerability.summary
      , severity              = xrayVulnerability.severity
      , severitySource        = xrayVulnerability.severitySource
      , vulnerableComponent   = xrayVulnerability.vulnerableComponent
      , componentPhysicalPath = xrayVulnerability.componentPhysicalPath
      , impactedArtefact      = xrayVulnerability.impactedArtefact
      , impactPath            = xrayVulnerability.impactPath
      , path                  = xrayVulnerability.path
      , fixedVersions         = xrayVulnerability.fixedVersions
      , published             = xrayVulnerability.published
      , artefactScanTime      = xrayVulnerability.artefactScanTime
      , issueId               = xrayVulnerability.issueId
      , packageType           = xrayVulnerability.packageType
      , provider              = xrayVulnerability.provider
      , description           = xrayVulnerability.description
      , references            = xrayVulnerability.references
      , projectKeys           = xrayVulnerability.projectKeys
      , importedBy            = importedBy
      )

    val apiFormat   =
      given Format[CVE]        = CVE.format
      given Format[ImportedBy] = ImportedBy.format
      ( (__ \ "cves"                   ).format[Seq[CVE]]
      ~ (__ \ "cvss3_max_score"        ).formatNullable[Double]
      ~ (__ \ "summary"                ).format[String]
      ~ (__ \ "severity"               ).format[String]
      ~ (__ \ "severity_source"        ).format[String]
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
      ~ (__ \ "provider"               ).format[String]
      ~ (__ \ "description"            ).format[String]
      ~ (__ \ "references"             ).format[Seq[String]]
      ~ (__ \ "project_keys"           ).format[Seq[String]]
      ~ (__ \ "importedBy"             ).formatNullable[ImportedBy]
      )(apply, pt => Tuple.fromProductTyped(pt))

    val mongoFormat =
      given Format[Instant]    = MongoJavatimeFormats.instantFormat
      given Format[CVE]        = CVE.format
      given Format[ImportedBy] = ImportedBy.format
      ( (__ \ "cves"                   ).format[Seq[CVE]]
      ~ (__ \ "cvss3_max_score"        ).formatNullable[Double]
      ~ (__ \ "summary"                ).format[String]
      ~ (__ \ "severity"               ).format[String]
      ~ (__ \ "severity_source"        ).format[String]
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
      ~ (__ \ "provider"               ).format[String]
      ~ (__ \ "description"            ).format[String]
      ~ (__ \ "references"             ).format[Seq[String]]
      ~ (__ \ "project_keys"           ).format[Seq[String]]
      ~ (__ \ "importedBy"             ).formatNullable[ImportedBy]
      )(apply, pt => Tuple.fromProductTyped(pt))

  case class CVE(
    cveId      : Option[String],
    cveV3Score : Option[Double],
    cveV3Vector: Option[String]
  )

  object CVE:
    val format =
      ( (__ \ "cve"           ).formatNullable[String]
      ~ (__ \ "cvss_v3_score" ).formatNullable[Double]
      ~ (__ \ "cvss_v3_vector").formatNullable[String]
      )(apply, pt => Tuple.fromProductTyped(pt))
