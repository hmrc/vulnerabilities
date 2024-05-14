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

package uk.gov.hmrc.vulnerabilities.controllers

import play.api.Logging
import play.api.libs.json.{Json, OFormat, Writes}
import play.api.mvc.{Action, AnyContent, ControllerComponents}
import uk.gov.hmrc.play.bootstrap.backend.controller.BackendController
import uk.gov.hmrc.vulnerabilities.model.{SlugInfoFlag, TotalVulnerabilityCount, Version, VulnerabilitySummary}
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.connectors.TeamsAndRepositoriesConnector
import uk.gov.hmrc.vulnerabilities.persistence.{AssessmentsRepository, RawReportsRepository, VulnerabilityAgeRepository}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{Future, ExecutionContext}

@Singleton()
class VulnerabilitiesController @Inject()(
  cc                           : ControllerComponents,
  assessmentsRepository        : AssessmentsRepository,
  rawReportsRepository         : RawReportsRepository,
  teamsAndRepositoriesConnector: TeamsAndRepositoriesConnector,
  vulnerabilityAgeRepository   : VulnerabilityAgeRepository
)(implicit ec: ExecutionContext)
  extends BackendController(cc)
     with Logging {

  def getSummaries(
    flag           : Option[SlugInfoFlag],
    service        : Option[ServiceName ]  ,
    version        : Option[Version]       ,
    team           : Option[String ]       ,
    curationStatus : Option[CurationStatus],
  ): Action[AnyContent] =
    Action.async { implicit request =>
      implicit val fmt: OFormat[VulnerabilitySummary] = VulnerabilitySummary.apiFormat
      for {
        serviceNames  <- (service, team) match {
                           case (None   , None   ) => Future.successful(None)
                           case (Some(s), _      ) => Future.successful(Some(Seq(s)))
                           case (_      , Some(_)) => teamsAndRepositoriesConnector.repositories(team).map(xs => Some(xs.map(x => ServiceName(x.name))))
                         }
        reports       <- rawReportsRepository.find(flag, serviceNames, version)
        repoWithTeams <- teamsAndRepositoriesConnector.repositoryTeams()
        firstDetected <- vulnerabilityAgeRepository.firstDetected()
        assessments   <- assessmentsRepository.getAssessments().map(_.map(a => a.id -> a).toMap)
        allSummaries  =  for {
                           report      <- reports
                           row         <- report.rows
                           cveId       =  row.cves.flatMap(_.cveId).headOption.getOrElse(row.issueId)
                           assessment  =  assessments.get(cveId)
                           if curationStatus.fold(true)(_ == assessment.map(_.curationStatus).getOrElse(CurationStatus.Uncurated))
                           compName    =  row.vulnerableComponent.split(":").dropRight(1).mkString(":")
                           compVersion =  row.vulnerableComponent.split(":").last
                         } yield
                           VulnerabilitySummary(
                            distinctVulnerability = DistinctVulnerability(
                                                      vulnerableComponentName    = compName,
                                                      vulnerableComponentVersion = compVersion,
                                                      vulnerableComponents       = Seq(VulnerableComponent(compName, compVersion)),
                                                      id                         = cveId,
                                                      score                      = row.cvss3MaxScore,
                                                      description                = row.description,
                                                      fixedVersions              = Some(row.fixedVersions),
                                                      references                 = row.references,
                                                      publishedDate              = row.published,
                                                      firstDetected              = firstDetected.get(cveId),
                                                      assessment                 = assessment.map(_.assessment),
                                                      curationStatus             = assessment.map(_.curationStatus).getOrElse(CurationStatus.Uncurated),
                                                      ticket                     = assessment.map(_.ticket),
                                                    ),
                             occurrences          = Seq(VulnerabilityOccurrence(
                                                      service                    = report.serviceName.asString,
                                                      serviceVersion             = report.serviceVersion.original,
                                                      componentPathInSlug        = row.componentPhysicalPath,
                                                      teams                      = repoWithTeams.getOrElse(report.serviceName.asString, Seq.empty).sorted,
                                                      envs                       = (  Option.when(report.development )(SlugInfoFlag.Development.asString ) ++
                                                                                      Option.when(report.integration )(SlugInfoFlag.Integration.asString ) ++
                                                                                      Option.when(report.qa          )(SlugInfoFlag.QA.asString          ) ++
                                                                                      Option.when(report.staging     )(SlugInfoFlag.Staging.asString     ) ++
                                                                                      Option.when(report.externalTest)(SlugInfoFlag.ExternalTest.asString) ++
                                                                                      Option.when(report.production  )(SlugInfoFlag.Production.asString  )
                                                                                   ).toSeq,
                                                      vulnerableComponentName    = compName,
                                                      vulnerableComponentVersion = compVersion,
                                                    )),
                             teams                = repoWithTeams.getOrElse(report.serviceName.asString, Seq.empty).sorted,
                             generatedDate        = report.generatedDate
                           )
        summaries     = allSummaries
                          .sortBy(_.generatedDate)
                          .groupBy(_.distinctVulnerability.id)
                          .collect {
                            case (_, x :: xs) => x.copy(
                                                   distinctVulnerability = x.distinctVulnerability.copy(vulnerableComponents = (x.distinctVulnerability.vulnerableComponents ++ xs.flatMap(_.distinctVulnerability.vulnerableComponents)).distinct.sortBy(o => (o.component, o.version)))
                                                 , occurrences           = x.occurrences ++ xs.flatMap(_.occurrences.headOption)
                                                 )
                            case (_, Seq(x))  => x
                          }
      } yield Ok(Json.toJson(summaries))
    }

  def getReportCounts(
    flag   : SlugInfoFlag,
    service: Option[ServiceName],
    team   : Option[String],
  ): Action[AnyContent] =
    Action.async { implicit request =>
      implicit val tvw: Writes[TotalVulnerabilityCount] = TotalVulnerabilityCount.writes
      for {
        serviceNames <- (service, team) match {
                          case (None   , None   ) => Future.successful(None)
                          case (Some(s), _      ) => Future.successful(Some(Seq(s)))
                          case (_      , Some(_)) => teamsAndRepositoriesConnector.repositories(team).map(xs => Some(xs.map(x => ServiceName(x.name))))
                        }
        reports      <- rawReportsRepository.find(Some(flag), serviceNames, version = None)
        assessments  <- assessmentsRepository.getAssessments()
        result       =  reports.map { report =>
                          val cves = report.rows.flatMap(_.cves.flatMap(_.cveId)).distinct
                          TotalVulnerabilityCount(
                            service              = report.serviceName
                          , actionRequired       = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.ActionRequired      )).size
                          , noActionRequired     = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.NoActionRequired    )).size
                          , investigationOngoing = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.InvestigationOngoing)).size
                          , uncurated            = cves.filterNot(cveId => assessments.exists(a => a.id == cveId                                                           )).size
                          )
                        }
      } yield Ok(Json.toJson(result))
    }

  // temp endpoint till we work out how to display vulnerabilities on the service page
  def getDeployedReportCount(
    service: ServiceName,
  ): Action[AnyContent] =
    Action.async { _ =>
      implicit val tvw: Writes[TotalVulnerabilityCount] = TotalVulnerabilityCount.writes
      for {
        reports     <- rawReportsRepository.findDeployed(service)
        assessments <- assessmentsRepository.getAssessments()
        cves        =  reports.flatMap(_.rows.flatMap(_.cves.flatMap(_.cveId))).distinct
        result      =  TotalVulnerabilityCount(
                         service              = service
                       , actionRequired       = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.ActionRequired      )).size
                       , noActionRequired     = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.NoActionRequired    )).size
                       , investigationOngoing = cves.filter   (cveId => assessments.exists(a => a.id == cveId && a.curationStatus == CurationStatus.InvestigationOngoing)).size
                       , uncurated            = cves.filterNot(cveId => assessments.exists(a => a.id == cveId                                                           )).size
                       )
      } yield if (reports.isEmpty) NotFound else Ok(Json.toJson(result))
    }

  def updateAssessments: Action[AnyContent] = Action.async {
    for {
      assessments <- Future.successful(AssessmentParser.getAssessments())
      insertCount <- assessmentsRepository.insertAssessments(assessments.values.toSeq)
    } yield Ok(s"Inserted ${insertCount} documents into the assessments collection")
  }
}

object AssessmentParser {

  def getAssessments(): Map[String, Assessment] = {
    implicit val fmt = Assessment.reads
    val stream = new java.io.FileInputStream("app/uk/gov/hmrc/vulnerabilities/assets/investigations-idx.json")
    try     { Json.parse(stream).as[Map[String, Assessment]] }
    finally { stream.close() }
  }
}
