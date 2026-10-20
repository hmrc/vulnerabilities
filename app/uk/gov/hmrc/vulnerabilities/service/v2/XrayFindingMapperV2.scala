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

import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.*
import uk.gov.hmrc.vulnerabilities.model.v2.xray.XrayReport

/** Pure, report-wide validation. Mongo publication must additionally check existing global CVE/component evidence. */
object XrayFindingMapperV2:
  import XrayFindingMappingErrorV2.*

  private val cveIdPattern = "CVE-[0-9]{4}-[0-9]{4,}".r

  def map(report: XrayReport, context: ScanContextV2): Either[Seq[XrayFindingMappingErrorV2], ScannerFindingsV2] =
    val contextErrors = Seq(
      Option.when(context.serviceName.asString.isBlank)(InvalidContext("serviceName", context.serviceName.asString)),
      Option.when(context.appVersion.original.isBlank)(InvalidContext("appVersion", context.appVersion.original))
    ).flatten
    val rows = report.rows.zipWithIndex.map: (row, index) =>
      val number = index + 1
      val component = parseComponent(row, number)
      val cveErrors =
        if row.cves.isEmpty then Seq(UnsupportedCve(number, row.issueId, None, None))
        else row.cves.zipWithIndex.flatMap: (cve, cveIndex) =>
          val idErrors = Option.when(!cve.cveId.exists(id => cveIdPattern.matches(id)))(
            UnsupportedCve(number, row.issueId, Some(cveIndex + 1), cve.cveId)
          ).toSeq
          val scoreErrors = cve.cveV3Score.toSeq.collect:
            case score if !score.isFinite || score < 0 || score > 10 =>
              InvalidCvss(number, row.issueId, cve.cveId, score)
          idErrors ++ scoreErrors
      val errors = component.left.toOption.toSeq ++ cveErrors
      val findings = component.toOption.toSeq.flatMap: parsed =>
        row.cves.flatMap: cve =>
          cve.cveId.filter(id => cveIdPattern.matches(id)).map: id =>
            number -> ScannerFindingV2(
              vulnerabilityId = id,
              summary = row.summary,
              cvss = cve.cveV3Score,
              component = parsed,
              fixedVersions = row.fixedVersions,
              references = row.references,
              sources = Seq(XrayFindingSourceV2(
                issueId = row.issueId,
                cvssVector = cve.cveV3Vector,
                rowMaxCvss = row.cvss3MaxScore,
                severity = row.severity,
                severitySource = row.severitySource,
                componentPhysicalPath = row.componentPhysicalPath,
                impactedArtefact = row.impactedArtefact,
                impactPath = row.impactPath,
                path = row.path,
                published = row.published,
                artefactScanTime = row.artefactScanTime,
                provider = row.provider,
                description = row.description,
                projectKeys = row.projectKeys
              ))
            )
      (errors, findings)

    val indexedFindings = rows.flatMap(_._2)
    val byId = indexedFindings.groupBy(_._2.vulnerabilityId)
    val grouped = indexedFindings.map(_._2.vulnerabilityId).distinct.map(id => id -> byId(id))
    val conflicts = grouped.flatMap: (id, entries) =>
      val findings = entries.map(_._2)
      val fields = conflictingFields(findings)
      Option.when(fields.nonEmpty)(ConflictingFindings(id, entries.map(_._1).distinct, fields, findings))
    val errors = contextErrors ++ rows.flatMap(_._1) ++ conflicts
    if errors.nonEmpty then Left(errors)
    else
      val findings = grouped.map: (_, entries) =>
        val all = entries.map(_._2)
        all.head.copy(
          references = all.flatMap(_.references).distinct,
          sources = all.flatMap(_.sources).distinct
        )
      Right(ScannerFindingsV2(context, report.generatedDate, findings))

  private def parseComponent(
    row: XrayReport.Vulnerability,
    number: Int
  ): Either[XrayFindingMappingErrorV2, MavenComponentV2] =
    val coordinates = row.vulnerableComponent
    if !row.packageType.equalsIgnoreCase("maven") then
      Left(UnsupportedPackageType(number, row.issueId, row.packageType))
    else if !coordinates.startsWith("gav://") then
      Left(UnsupportedCoordinateScheme(number, row.issueId, coordinates))
    else
      def valid(part: String): Boolean =
        part.nonEmpty && !part.exists(c => c.isWhitespace || c.isSpaceChar || ":/?#".contains(c))
      coordinates.stripPrefix("gav://").split(":", -1).toSeq match
        case Seq(group, artefact, version) if Seq(group, artefact, version).forall(valid) =>
          Right(MavenComponentV2(group, artefact, version))
        case _ => Left(MalformedComponentCoordinates(number, row.issueId, coordinates))

  private def conflictingFields(findings: Seq[ScannerFindingV2]): Seq[ConflictingFindingFieldV2] =
    import ConflictingFindingFieldV2.*
    Seq(
      Option.when(findings.map(_.component.identity).distinct.size > 1)(component),
      Option.when(findings.map(_.component.installedVersion).distinct.size > 1)(installedVersion),
      Option.when(findings.map(_.fixedVersions.toSet).distinct.size > 1)(fixedVersions),
      Option.when(findings.map(_.summary).distinct.size > 1)(summary),
      Option.when(findings.map(_.cvss).distinct.size > 1)(cvss)
    ).flatten
