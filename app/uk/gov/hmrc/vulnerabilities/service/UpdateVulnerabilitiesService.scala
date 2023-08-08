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

package uk.gov.hmrc.vulnerabilities.service

import play.api.Logging
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.vulnerabilities.connectors.{ReleasesConnector, TeamsAndRepositoriesConnector}
import uk.gov.hmrc.vulnerabilities.model.CurationStatus.Uncurated
import uk.gov.hmrc.vulnerabilities.model.{DistinctVulnerability, Report, ServiceVersionDeployments, UnrefinedVulnerabilitySummary, VulnerabilityOccurrence, VulnerabilitySummary, VulnerableComponent, WhatsRunningWhere}
import uk.gov.hmrc.vulnerabilities.persistence.{AssessmentsRepository, RawReportsRepository, VulnerabilitySummariesRepository}
import uk.gov.hmrc.vulnerabilities.utils.Assessment

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class UpdateVulnerabilitiesService @Inject()(
  releasesConnector               : ReleasesConnector,
  teamsAndRepositoriesConnector   : TeamsAndRepositoriesConnector,
  xrayService                     : XrayService,
  rawReportsRepository            : RawReportsRepository,
  assessmentsRepository           : AssessmentsRepository,
  vulnerabilitySummariesRepository: VulnerabilitySummariesRepository

)(implicit ec: ExecutionContext) extends
  Logging {

  def updateAllVulnerabilities()(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      svDeps          <- getCurrentServiceVersionDeployments()
      //Only download reports that don't exist in last 24 hours in our raw reports collection
      recentReports   <- rawReportsRepository.getReportsInLastXDays()
      svDepsToUpdate  =  svDeps.filterNot(svd => recentReports.exists(rep => rep.nameAndVersion().contains(svd.serviceName + "_" + svd.version)))
      _               <- xrayService.processReports(svDepsToUpdate)
      _               =  logger.info("Finished generating and inserting reports into the rawReports collection")
      _               <- updateVulnerabilitySummaries(svDeps)
    } yield ()


  def updateVulnerabilities(
    serviceName: String,
    version    : String,
    environment: String
  )(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      svDeps         <- getCurrentServiceVersionDeployments()
      svDepsToUpdate =  Seq(ServiceVersionDeployments(serviceName, version, Seq(environment)))
      _              <- xrayService.processReports(svDepsToUpdate)
      _              =  logger.info(s"Finished generating and inserting reports into the rawReports collection for $serviceName version $version in $environment")
      _              <- updateVulnerabilitySummaries(svDeps)
    } yield ()

  private def getCurrentServiceVersionDeployments()(implicit hc: HeaderCarrier): Future[Seq[ServiceVersionDeployments]] =
    for {
      currentReleases  <- releasesConnector.getCurrentReleases()
      cleansedReleases =  currentReleases.map(wrw => wrw.copy(deployments = wrw.deployments.filterNot(dep => (dep.environment.toLowerCase() == "integration" || dep.environment.toLowerCase() == "development"))))
      svDeps           =  getEnvsForServiceVersion(cleansedReleases)
    } yield svDeps

  private def getEnvsForServiceVersion(wrw: Seq[WhatsRunningWhere]): Seq[ServiceVersionDeployments] =
    wrw
      .flatMap(wrw =>
        wrw
          .deployments
          .groupMap(_.version)(_.environment)
          .map(versionAndEnvs =>
            ServiceVersionDeployments(
              wrw.serviceName,
              versionAndEnvs._1,
              versionAndEnvs._2
            )
          )
      )
      .filterNot(_.environments.isEmpty)    //Remove any SVDs that were only deployed in Int/Dev
      .sortBy(sd => (sd.serviceName, sd.version))


  private def updateVulnerabilitySummaries(allSvDeps: Seq[ServiceVersionDeployments])(implicit hc: HeaderCarrier) =
    for {
      //Transform raw reports to Vulnerability Summaries
      unrefined        <- rawReportsRepository.getNewDistinctVulnerabilities()
      _                =  logger.info(s"Retrieved ${unrefined.length} unrefined vulnerability summaries")
      reposWithTeams   <- teamsAndRepositoriesConnector.getCurrentReleases()
      refined          =  convertToVulnerabilitySummary(unrefined, reposWithTeams, allSvDeps)
      assessments      <- assessmentsRepository.getAssessments()
      finalAssessments =  assessments.map(a => a.id -> a).toMap
      finalSummaries   =  addInvestigationsToSummaries(refined, finalAssessments)
      _                =  logger.info("About to delete all documents from the vulnerabilitySummaries repository")
      //Update final Collection
      summariesCount   <- vulnerabilitySummariesRepository.deleteOldAndInsertNewSummaries(finalSummaries)
    } yield logger.info(s"Inserted ${summariesCount} documents into the vulnerabilitySummaries repository")

  private def addInvestigationsToSummaries(summaries: Seq[VulnerabilitySummary], investigations: Map[String, Assessment]): Seq[VulnerabilitySummary] =
    summaries.map { vs =>
      investigations.get(vs.distinctVulnerability.id) match {
        case Some(inv) => vs.copy(distinctVulnerability =
          vs.distinctVulnerability.copy(
            assessment            = Some(inv.assessment),
            curationStatus        = Some(inv.curationStatus),
            ticket                = Some(inv.ticket.trim).filter(_.nonEmpty)
          )
        )
        case None => vs.copy(distinctVulnerability =
          vs.distinctVulnerability.copy(curationStatus = Some(Uncurated)
          )
        )
      }
    }

  private def convertToVulnerabilitySummary(
    unrefined    : Seq[UnrefinedVulnerabilitySummary],
    repoWithTeams: Map[String, Seq[String]],
    svds         : Seq[ServiceVersionDeployments]
  ): Seq[VulnerabilitySummary] =
    unrefined.map { u =>
      val occs = u.occurrences.map { occ =>
        val service = occ.path.split("/")(2)
        val serviceVersion = occ.path.split("_")(1)
        VulnerabilityOccurrence(
          service                    = service,
          serviceVersion             = serviceVersion,
          componentPathInSlug        = occ.componentPhysicalPath,
          teams                      = repoWithTeams.getOrElse(service, Seq.empty).sorted,
          envs                       = svds
            .find(s => s.serviceName == service && s.version == serviceVersion)
            .getOrElse(ServiceVersionDeployments("", "", Seq.empty))
            .environments,
          vulnerableComponentName    = occ.vulnComponent.split(":").dropRight(1).mkString(":"),
          vulnerableComponentVersion = occ.vulnComponent.split(":").last
        )
      }

      VulnerabilitySummary(
        distinctVulnerability = DistinctVulnerability(
          vulnerableComponentName    = occs.head.vulnerableComponentName,
          vulnerableComponentVersion = occs.head.vulnerableComponentVersion,
          vulnerableComponents       = occs.map( o => VulnerableComponent(o.vulnerableComponentName, o.vulnerableComponentVersion)).distinct.sortBy(o => (o.component, o.version)),
          id                         = u.id,
          score                      = u.score,
          description                = u.distinctVulnerability.description,
          fixedVersions              = u.distinctVulnerability.fixedVersions,
          references                 = u.distinctVulnerability.references,
          publishedDate              = u.distinctVulnerability.publishedDate,
          assessment                 = None,
          curationStatus             = None,
          ticket                     = None,
        ),
        occurrences           = occs.sortBy(o => (o.service, o.serviceVersion)),
        teams                 = occs.flatMap(_.teams).distinct.sorted,
        generatedDate         = u.generatedDate
      )
    }
}
