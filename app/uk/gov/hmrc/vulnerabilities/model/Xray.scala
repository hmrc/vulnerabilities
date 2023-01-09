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

case class ReportRequestPayload(
 name: String,
 resources: Resource,
 filters: Filter
)

object ReportRequestPayload {
  val apiFormat = {
    implicit val rf = Resource.apiFormat
    implicit val ff = Filter.apiFormat

    ( (__ \ "name").format[String]
      ~ (__ \ "resources").format[Resource]
      ~ (__ \ "filters").format[Filter]
      )(apply, unlift(unapply))

  }
}

case class Resource(
  repositories: Seq[XrayRepo]
)

object Resource {
  val apiFormat = {
    implicit val xrf = XrayRepo.apiFormat
    //Single field case classes require invariant map to format.
    ((__ \ "repositories").format[Seq[XrayRepo]]).inmap(Resource.apply, unlift(Resource.unapply))
  }
}

case class XrayRepo(
  name: String
)

object XrayRepo {
  val apiFormat = {
    ((__ \ "name").format[String]).inmap(XrayRepo.apply, unlift(XrayRepo.unapply))
  }
}

case class Filter(
  impactedArtifact: String
)

object Filter {
  val apiFormat = {
    ( (__ \ "impacted_artifact" ).format[String]).inmap(Filter.apply, unlift(Filter.unapply))
  }
}

case class ReportRequestResponse(
  reportID: Int,
  status: String,
)

object ReportRequestResponse {

  val apiFormat = {
    ( (__ \ "report_id").format[Int]
      ~ (__ \ "status").format[String]
      )(apply, unlift(unapply))
  }
}

case class ReportStatus(
 status  : String,
 rowCount: Option[Int]
)

object ReportStatus {
  val apiFormat = {
    ( (__ \ "status" ).format[String]
    ~ (__ \ "number_of_rows").formatNullable[Int]
    )(apply, unlift(unapply))
  }
}

case class ReportDelete(
 info: String
)

object ReportDelete {
  val apiFormat = {
    ((__ \ "info").format[String].inmap(ReportDelete.apply, unlift(ReportDelete.unapply)))
  }
}

case class Report(
 rows         : Seq[RawVulnerability],
 generatedDate: Instant
){
  def serviceName()   : String = rows.headOption.map(_.path.split("/")(2)).getOrElse("")
  def serviceVersion(): String = rows.headOption.map(_.path.split("_")(1)).getOrElse("")
  def nameAndVersion(): String = serviceName() + "_" + serviceVersion()
}

object Report {
  def generateDateTime: Instant = Instant.now()

  val apiFormat = {
    implicit val rvf = RawVulnerability.apiFormat
    ((__ \ "rows").format[Seq[RawVulnerability]]
      ~ (__ \ "generatedDate").formatNullable[Instant].inmap[Instant](_.getOrElse(generateDateTime), Some(_))
      )(apply, unlift(unapply))
  }

  val mongoFormat = {
    implicit val instantFormat = MongoJavatimeFormats.instantFormat
    implicit val rvf = RawVulnerability.mongoFormat
    ((__ \ "rows").format[Seq[RawVulnerability]]
      ~ (__ \ "generatedDate").formatNullable[Instant].inmap[Instant](_.getOrElse(generateDateTime), Some(_))
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

    ( (__ \ "cves"                     ).format[Seq[CVE]]
      ~ (__ \ "cvss3_max_score"        ).formatNullable[Double]
      ~ (__ \ "summary"                ).format[String]
      ~ (__ \ "severity"               ).format[String]
      ~ (__ \ "severity_source"        ).format[String]
      ~ (__ \ "vulnerable_component"   ).format[String]
      ~ (__ \ "component_physical_path").format[String]
      ~ (__ \ "impacted_artifact"      ).format[String]
      ~ (__ \ "impact_path"            ).format[Seq[String]]
      ~ (__ \ "path"                   ).format[String]
      ~ (__ \ "fixed_versions"          ).format[Seq[String]]
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

    ( (__ \ "cves"                     ).format[Seq[CVE]]
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
  val apiFormat = {
    ( (__ \ "cve"             ).formatNullable[String]
      ~ (__ \ "cvss_v3_score" ).formatNullable[Double]
      ~ (__ \ "cvss_v3_vector").formatNullable[String]
      )(apply, unlift(unapply))
  }
}