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

import uk.gov.hmrc.vulnerabilities.v2.model.ingestion.*
import uk.gov.hmrc.vulnerabilities.v2.model.xray.XrayReport

/** Pure, report-wide validation. Mongo publication must additionally check existing global CVE/component evidence. */
object XrayFindingMapper:
  import XrayFindingMappingError.*

  private val cveIdPattern = "CVE-[0-9]{4}-[0-9]{4,}".r

  def map(report: XrayReport, context: ScanContext): Either[Seq[XrayFindingMappingError], ScannerFindings] =
    val contextErrors = Seq(
      Option.when(context.serviceName.asString.isBlank)(InvalidContext("serviceName", context.serviceName.asString)),
      Option.when(context.appVersion.original.isBlank)(InvalidContext("appVersion", context.appVersion.original))
    ).flatten
    val rows = report.rows.zipWithIndex.map(mapRow)
    val indexedFindings = rows.flatMap(_._2)
    val grouped = groupFindings(indexedFindings)
    val conflicts = findConflicts(grouped)
    val errors = contextErrors ++ rows.flatMap(_._1) ++ conflicts
    if errors.nonEmpty then Left(errors)
    else
      Right(ScannerFindings(context, report.generatedDate, mergeFindings(grouped)))

  private def mapRow(
    rowAndIndex: (XrayReport.Vulnerability, Int)
  ): (Seq[XrayFindingMappingError], Seq[(Int, ScannerFinding)]) =
    val (row, index) = rowAndIndex
    val number = index + 1
    val component = parseComponent(row, number)
    val cveErrors = validateCves(row, number)
    val errors = component.left.toOption.toSeq ++ cveErrors
    val findings = component.toOption.toSeq.flatMap(parsed => buildFindings(row, number, parsed))
    (errors, findings)

  private def validateCves(
    row: XrayReport.Vulnerability,
    number: Int
  ): Seq[XrayFindingMappingError] =
    if row.cves.isEmpty then Seq(UnsupportedCve(number, row.issueId, None, None))
    else row.cves.zipWithIndex.flatMap: (cve, cveIndex) =>
      val idErrors = Option.when(!cve.cveId.exists(id => cveIdPattern.matches(id)))(
        UnsupportedCve(number, row.issueId, Some(cveIndex + 1), cve.cveId)
      ).toSeq
      val scoreErrors = cve.cveV3Score.toSeq.collect:
        case score if !score.isFinite || score < 0 || score > 10 =>
          InvalidCvss(number, row.issueId, cve.cveId, score)
      idErrors ++ scoreErrors

  private def buildFindings(
    row: XrayReport.Vulnerability,
    number: Int,
    component: MavenComponent
  ): Seq[(Int, ScannerFinding)] =
    row.cves.flatMap: cve =>
      cve.cveId.filter(id => cveIdPattern.matches(id)).map: id =>
        number -> ScannerFinding(
          vulnerabilityId = id,
          summary = row.summary,
          cvss = cve.cveV3Score,
          component = component,
          fixedVersions = row.fixedVersions,
          references = row.references,
          sources = Seq(XrayFindingSource(
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

  private def groupFindings(
    indexedFindings: Seq[(Int, ScannerFinding)]
  ): Seq[(String, Seq[(Int, ScannerFinding)])] =
    val byId = indexedFindings.groupBy(_._2.vulnerabilityId)
    indexedFindings.map(_._2.vulnerabilityId).distinct.map(id => id -> byId(id))

  private def findConflicts(
    grouped: Seq[(String, Seq[(Int, ScannerFinding)])]
  ): Seq[ConflictingFindings] =
    grouped.flatMap: (id, entries) =>
      val findings = entries.map(_._2)
      val fields = conflictingFields(findings)
      Option.when(fields.nonEmpty)(ConflictingFindings(id, entries.map(_._1).distinct, fields, findings))

  private def mergeFindings(
    grouped: Seq[(String, Seq[(Int, ScannerFinding)])]
  ): Seq[ScannerFinding] =
    grouped.map: (_, entries) =>
      entries.groupBy(_._2.observationKey).toSeq.sortBy(_._1).map: (_, duplicates) =>
        val all = duplicates.map(_._2)
        all.head.copy(
          references = all.flatMap(_.references).distinct,
          sources = all.flatMap(_.sources).distinct
        )
    .flatten

  private def parseComponent(
    row: XrayReport.Vulnerability,
    number: Int
  ): Either[XrayFindingMappingError, MavenComponent] =
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
          Right(MavenComponent(group, artefact, version))
        case _ => Left(MalformedComponentCoordinates(number, row.issueId, coordinates))

  private def conflictingFields(findings: Seq[ScannerFinding]): Seq[ConflictingFindingField] =
    import ConflictingFindingField.*
    Seq(
      Option.when(findings.map(_.summary).distinct.size > 1)(summary),
      Option.when(findings.map(_.cvss).distinct.size > 1)(cvss)
    ).flatten
