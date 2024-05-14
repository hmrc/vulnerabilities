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

import play.api.libs.functional.syntax.{toFunctionalBuilderOps, toInvariantFunctorOps, unlift}
import play.api.libs.json.{OFormat, __}
import uk.gov.hmrc.mongo.play.json.formats.MongoJavatimeFormats

import java.time.Instant

case class ReportResponse(
  reportID: Int,
  status  : String,
)

object ReportResponse {
  val apiFormat =
  ( (__ \ "report_id").format[Int]
  ~ (__ \ "status"   ).format[String]
  )(apply, unlift(unapply))
}

case class ReportId(id: Int) extends AnyVal

object ReportId {
  val reads = (__ \ "id").read[Int].map(ReportId.apply)
}

case class ReportStatus(
 status  : String,
 rowCount: Option[Int]
)

object ReportStatus {
  val apiFormat =
    ( (__ \ "status" ).format[String]
    ~ (__ \ "number_of_rows").formatNullable[Int]
    )(apply, unlift(unapply))
}

case class Report(
  serviceName   : ServiceName,
  serviceVersion: Version,
  rows          : Seq[RawVulnerability],
  generatedDate : Instant,
  latest        : Boolean,
  production    : Boolean,
  qa            : Boolean,
  staging       : Boolean,
  development   : Boolean,
  externalTest  : Boolean,
  integration   : Boolean
)

object Report {
  private def generateDateTime(): Instant = Instant.now()
  def apiFormat(
    serviceName  : ServiceName,
    version      : Version,
    latest       : Boolean,
    production   : Boolean,
    qa           : Boolean,
    staging      : Boolean,
    development  : Boolean,
    externalTest : Boolean,
    integration  : Boolean
  ) = {
    implicit val rvf = RawVulnerability.apiFormat
    ( (__ \ "rows"          ).format[Seq[RawVulnerability]]
    ~ (__ \ "generatedDate" ).formatNullable[Instant].inmap[Instant](_.getOrElse(generateDateTime()), Some(_))
    )(apply(serviceName, version, _, _, latest, production, qa, staging, development, externalTest, integration),  (r: Report) => (r.rows, r.generatedDate))
  }

  val mongoFormat = {
    implicit val instf = MongoJavatimeFormats.instantFormat
    implicit val rvf   = RawVulnerability.mongoFormat
    implicit val snf   = ServiceName.format
    implicit val vf    = Version.format
    ( (__ \ "serviceName"   ).format[ServiceName]
    ~ (__ \ "serviceVersion").format[Version]
    ~ (__ \ "rows"          ).format[Seq[RawVulnerability]]
    ~ (__ \ "generatedDate" ).formatNullable[Instant].inmap[Instant](_.getOrElse(generateDateTime()), Some(_))
    ~ (__ \ "latest"        ).formatWithDefault[Boolean](false)
    ~ (__ \ "production"    ).formatWithDefault[Boolean](false)
    ~ (__ \ "qa"            ).formatWithDefault[Boolean](false)
    ~ (__ \ "staging"       ).formatWithDefault[Boolean](false)
    ~ (__ \ "development"   ).formatWithDefault[Boolean](false)
    ~ (__ \ "external test" ).formatWithDefault[Boolean](false)
    ~ (__ \ "integration"   ).formatWithDefault[Boolean](false)
    )(apply, unlift(unapply))
  }
}

case class RawVulnerability(
  cves                 : Seq[CVE],
  cvss3MaxScore        : Option[Double],
  summary              : String,
  severity             : String,
  severitySource       : String,
  vulnerableComponent  : String,
  componentPhysicalPath: String,
  impactedArtifact     : String,
  impactPath           : Seq[String],
  path                 : String,
  fixedVersions        : Seq[String],
  published            : Instant,
  artifactScanTime     : Instant,
  issueId              : String,
  packageType          : String,
  provider             : String,
  description          : String,
  references           : Seq[String],
  projectKeys          : Seq[String]
)

object RawVulnerability {
  val mongoFormat: OFormat[RawVulnerability] = {
    implicit val cvef          = CVE.apiFormat
    implicit val instantFormat = MongoJavatimeFormats.instantFormat
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
    )(apply, unlift(unapply))
  }

  val apiFormat: OFormat[RawVulnerability] = {
    implicit val cvef = CVE.apiFormat
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
    )(apply, unlift(unapply))
  }
}

case class CVE(
  cveId: Option[String],
  cveV3Score: Option[Double],
  cveV3Vector: Option[String]
)

object CVE {
  val apiFormat =
    ( (__ \ "cve"           ).formatNullable[String]
    ~ (__ \ "cvss_v3_score" ).formatNullable[Double]
    ~ (__ \ "cvss_v3_vector").formatNullable[String]
    )(apply, unlift(unapply))
}
