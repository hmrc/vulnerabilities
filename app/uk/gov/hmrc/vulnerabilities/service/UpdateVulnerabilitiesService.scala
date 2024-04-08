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

import cats.implicits._
import play.api.Logging
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.vulnerabilities.connectors.{ReleasesConnector, TeamsAndRepositoriesConnector}
import uk.gov.hmrc.vulnerabilities.model.CurationStatus.Uncurated
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.persistence.{AssessmentsRepository, RawReportsRepository, VulnerabilityAgeRepository, VulnerabilitySummariesRepository}
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
  vulnerabilitySummariesRepository: VulnerabilitySummariesRepository,
  vulnerabilityAgeRepository      : VulnerabilityAgeRepository

)(implicit ec: ExecutionContext) extends
  Logging {

  def updateAllVulnerabilities()(implicit hc: HeaderCarrier): Future[Unit] =
    for {
      svDeps         <- getCurrentServiceVersionDeployments()
      //Only download reports that don't exist in last X hours in our raw reports collection. This allows the scheduler to pickup where it left off if it fails.
      //This is more resilient than the alternative approach where we always redownload everything on a scheduler freq set to 24 hours
      //as if something went wrong on a single run, we wouldn't retry for another 24 hours, at which point we could have missing data.
      recentReports  <- rawReportsRepository.getReportsInLastXDays()
      agesToUpdate   =  toVulnerabilityAge(recentReports)
      _              <- vulnerabilityAgeRepository.insertNonExisting(agesToUpdate)
      svDepsToUpdate =  svDeps.filterNot(svd => recentReports.exists(rep => rep.nameAndVersion.contains(svd.serviceName + "_" + svd.version)))
      _              <- xrayService.deleteStaleReports()
      _              <- xrayService.processReports(svDepsToUpdate)
      _              =  logger.info("Finished generating and inserting reports into the rawReports collection")
      _              <- updateVulnerabilitySummaries(isRebuild = true, svDeps)
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
      _              <- updateVulnerabilitySummaries(isRebuild = false, svDeps)
    } yield ()


  private def toVulnerabilityAge(reports: Seq[Report]): Seq[VulnerabilityAge] =
    reports.flatMap { rep =>
      rep.rows.map { raw =>
        VulnerabilityAge(
          service         = rep.serviceName,
          firstScanned    = rep.generatedDate,
          vulnerabilityId = raw.cves.flatMap(cve => cve.cveId).headOption.getOrElse(raw.issueId)
        )
      }
    }.groupBy(va => (va.service, va.vulnerabilityId))
      .map { case (_, group) => group.minBy(_.firstScanned) }
      .toSeq

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


  private def updateVulnerabilitySummaries(isRebuild: Boolean, allSvDeps: Seq[ServiceVersionDeployments])(implicit hc: HeaderCarrier) =
    for {
      //Transform raw reports to Vulnerability Summaries
      unrefined        <- rawReportsRepository.getNewDistinctVulnerabilities()
      _                =  logger.info(s"Retrieved ${unrefined.length} unrefined vulnerability summaries")
      reposWithTeams   <- teamsAndRepositoriesConnector.getCurrentReleases()
      refined          <- convertToVulnerabilitySummary(unrefined, reposWithTeams, allSvDeps)
      assessments      <- assessmentsRepository.getAssessments()
      finalAssessments =  assessments.map(a => a.id -> a).toMap
      finalSummaries   =  addInvestigationsToSummaries(refined, finalAssessments)
      _                =  logger.info("About to delete all documents from the vulnerabilitySummaries repository")
      //Update final Collection
      summariesCount   <- if (isRebuild) vulnerabilitySummariesRepository.putSummaries(finalSummaries)
                          else           vulnerabilitySummariesRepository.mergeNewSummaries(finalSummaries, allSvDeps)
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
  ): Future[Seq[VulnerabilitySummary]] =
    unrefined.foldLeftM[Future, Seq[Option[VulnerabilitySummary]]](Seq.empty){ (acc, u) =>
      for {
        optFirstDetected <- vulnerabilityAgeRepository.firstDetectedDate(u.id)
        occurrences      =  u.occurrences.map { occ =>
                              val service = occ.path.split("/")(2)
                              val serviceVersion = occ.path.split("_")(1)
                              VulnerabilityOccurrence(
                                service                    = service,
                                serviceVersion             = serviceVersion,
                                componentPathInSlug        = occ.componentPhysicalPath,
                                teams                      = repoWithTeams.getOrElse(service, Seq.empty).sorted,
                                vulnerableComponentName    = occ.vulnComponent.split(":").dropRight(1).mkString(":"),
                                vulnerableComponentVersion = occ.vulnComponent.split(":").last,
                                envs                       = svds.find(s => s.serviceName == service && s.version == serviceVersion)
                                                              //We don't filter out when this serviceVersion is not deployed in any env,
                                                              //as it would miss edge cases like forms-aem-publisher, which break our releases logic
                                                              .getOrElse(ServiceVersionDeployments("", "", Seq.empty))
                                                              .environments
                              )
                            }
        optSummary       = occurrences.headOption.map { o =>
                             VulnerabilitySummary(
                               DistinctVulnerability(
                                 vulnerableComponentName    = o.vulnerableComponentName,
                                 vulnerableComponentVersion = o.vulnerableComponentVersion,
                                 vulnerableComponents       = occurrences.map( o => VulnerableComponent(o.vulnerableComponentName, o.vulnerableComponentVersion)).distinct.sortBy(o => (o.component, o.version)),
                                 id                         = u.id,
                                 score                      = u.score,
                                 description                = u.distinctVulnerability.description,
                                 fixedVersions              = u.distinctVulnerability.fixedVersions,
                                 references                 = u.distinctVulnerability.references,
                                 publishedDate              = u.distinctVulnerability.publishedDate,
                                 firstDetected              = optFirstDetected.map(_.firstScanned),
                                 assessment                 = None,
                                 curationStatus             = None,
                                 ticket                     = None
                               ),
                               occurrences   = occurrences.sortBy(o => (o.service, o.serviceVersion)),
                               teams         = occurrences.flatMap(_.teams).distinct.sorted,
                               generatedDate = u.generatedDate
                             )
        }
      } yield acc :+ optSummary
    }.map(_.flatten)
}
