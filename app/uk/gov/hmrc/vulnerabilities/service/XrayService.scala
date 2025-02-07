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

import org.apache.pekko.actor.ActorSystem
import cats.data.EitherT
import play.api.{Configuration, Logging}
import uk.gov.hmrc.vulnerabilities.connector.{ArtefactProcessorConnector, BuildDeployApiConnector, XrayConnector}
import uk.gov.hmrc.vulnerabilities.model._
import uk.gov.hmrc.vulnerabilities.persistence.{RawReportsRepository, VulnerabilityAgeRepository}
import uk.gov.hmrc.vulnerabilities.util.DependencyGraphParser
import uk.gov.hmrc.http.HeaderCarrier

import cats.implicits._

import java.time.Instant
import javax.inject.{Inject, Singleton}
import scala.concurrent.duration._
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class XrayService @Inject()(
  configuration               : Configuration,
  buildAndDeployConnector     : BuildDeployApiConnector,
  artefactProcessorConnector  : ArtefactProcessorConnector,
  xrayConnector               : XrayConnector,
  system                      : ActorSystem,
  rawReportsRepository        : RawReportsRepository,
  vulnerabilityAgeRepository  : VulnerabilityAgeRepository
)(using
  ExecutionContext
) extends Logging:

  case class SlugInfo(
    serviceName: ServiceName,
    version    : Version,
    uri        : String,
    flags      : Seq[SlugInfoFlag]
  ):
    val path = uri.replaceAll(".*/(webstore|webstore-local)/", "webstore-local/")

  object SlugInfo:
    def fromReport(report: Report) =
      SlugInfo(
        serviceName = report.serviceName
      , version     = report.serviceVersion
      , uri         = report.slugUri
      , flags       = ( Option.when(report.latest      )(SlugInfoFlag.Latest      ) ++
                        Option.when(report.development )(SlugInfoFlag.Development ) ++
                        Option.when(report.integration )(SlugInfoFlag.Integration ) ++
                        Option.when(report.qa          )(SlugInfoFlag.QA          ) ++
                        Option.when(report.staging     )(SlugInfoFlag.Staging     ) ++
                        Option.when(report.externalTest)(SlugInfoFlag.ExternalTest) ++
                        Option.when(report.production  )(SlugInfoFlag.Production  )
                      ).toSeq
      )

  def firstScan(serviceName: ServiceName, version: Version, slugUri: String, flag: Option[SlugInfoFlag] = None)(using HeaderCarrier): Future[Unit] =
    for
      _ <- deleteStaleReports()
      _ <- processReports(Seq(SlugInfo(serviceName, version, slugUri, flag.toSeq)))
    yield ()

  def rescanLatestAndDeployed()(using HeaderCarrier): Future[Unit] =
    val start = System.currentTimeMillis()
    logger.info("Rescan of latest and deployed services started")
    (for
      _        <- deleteStaleReports()
      reports  <- rawReportsRepository.findFlagged()
      _        <- processReports(reports.map(SlugInfo.fromReport))
      duration =  System.currentTimeMillis() - start
    yield logger.info(s"Rescan of ${reports.length} latest and deployed services finished - took ${duration}ms")
    ).recover:
      case ex =>
        val duration = System.currentTimeMillis() - start
        logger.error(s"Rescan of latest and deployed services terminated after ${duration}ms", ex)
        throw ex

  def rescanStaleReports(reportsBefore: Instant)(using HeaderCarrier): Future[Unit] =
    for
      _       <- deleteStaleReports()
      reports <- rawReportsRepository.findGeneratedBefore(reportsBefore)
      _       <- processReports(reports.map(SlugInfo.fromReport))
    yield ()

  def fixNotScanned()(using HeaderCarrier): Future[Unit] =
    for
      _       <- deleteStaleReports()
      reports <- rawReportsRepository.findNotScanned()
      _       <- processReports(reports.map(SlugInfo.fromReport))
    yield ()

  enum XrayStatus:
    case ArtefactNotFound extends XrayStatus
    case Retry            extends XrayStatus

  private val maxRetries = 3
  private def processReports(slugs: Seq[SlugInfo])(using HeaderCarrier): Future[Unit] =
    slugs
      .foldLeftM(()): (_, slug) =>
        def go(count: Int): Future[Unit] =
          scan(slug).value.flatMap:
            case Left(XrayStatus.ArtefactNotFound)
              if count < maxRetries  =>
                                        for
                                          _ <- buildAndDeployConnector
                                                .triggerXrayScanNow(slug.path)
                                                .recover:
                                                  case ex => logger.error(s"Error calling B&D API ${ex.getMessage}", ex)
                                          _ <- org.apache.pekko.pattern.after(1000.millis, system.scheduler) { go(count + 1) }
                                        yield ()
            case Left(XrayStatus.Retry)
              if count < maxRetries  => go(count + 1)
            case Left(_)             => logger.warn(s"Tried to scan ${slug.serviceName.asString}:${slug.version.original} $count times.")
                                        for
                                          r <- toReport(slug, generatedDate = Instant.now(), rows = Nil, scanned = false)
                                          _ <- rawReportsRepository.put(report = r)
                                        yield ()
            case Right((date, rows)) => for
                                          r <- toReport(slug, generatedDate = date, rows = rows, scanned = true)
                                          _ <- vulnerabilityAgeRepository.insertNonExisting(report = r)
                                          _ <- rawReportsRepository.put(report = r)
                                        yield ()

        go(1)
      .map(x => logger.info(s"Finished processing ${slugs.size} reports."))

  private def toReport(slug: SlugInfo, generatedDate: Instant, rows: Seq[RawVulnerability], scanned: Boolean)(using HeaderCarrier): Future[Report] =
    for
      oSlugInfo <- artefactProcessorConnector.getSlugInfo(slug.serviceName, slug.version)
      deps      =  oSlugInfo.fold(Seq.empty[Dependency])(x => DependencyGraphParser.dependencies(x.dependencyDotCompile))
    yield Report(
      slug.serviceName
    , slug.version
    , slugUri       = slug.uri
    , latest        = slug.flags.contains(SlugInfoFlag.Latest)
    , production    = slug.flags.contains(SlugInfoFlag.Production)
    , qa            = slug.flags.contains(SlugInfoFlag.QA)
    , staging       = slug.flags.contains(SlugInfoFlag.Staging)
    , development   = slug.flags.contains(SlugInfoFlag.Development)
    , externalTest  = slug.flags.contains(SlugInfoFlag.ExternalTest)
    , integration   = slug.flags.contains(SlugInfoFlag.Integration)
    , generatedDate = generatedDate
    , rows          = rows.map: vuln =>
                        vuln.copy(
                          importedBy = deps
                                        .find: d =>
                                           vuln.vulnerableComponent == s"gav://${d.group}:${d.artefact}${d.scalaVersion.fold("")("_" + _.original)}:${d.version.original}"
                                        .flatMap:
                                          _.importedBy

                        )
    , scanned       = scanned
    )

  private def scan(slug: SlugInfo)(using HeaderCarrier): EitherT[Future, XrayStatus, (Instant, Seq[RawVulnerability])] =
    EitherT
      .liftF(xrayConnector.generateReport(slug.serviceName, slug.version, slug.path))
      .flatMap: resp =>
        logger.info(s"Began generating report for ${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")}. Report will have id ${resp.reportID}")
        val et =
          for
            status  <- EitherT(checkIfReportReady(slug, resp))
            tuple   <- if   status.numberOfRows > 0
                       then EitherT.fromOptionF(xrayConnector.downloadAndUnzipReport(resp.reportID, slug.serviceName, slug.version), XrayStatus.Retry)
                       else EitherT.rightT[Future, XrayStatus]((Instant.now(), Seq.empty[RawVulnerability]))
          yield tuple

        et.value.onComplete:
          case _ => xrayConnector
                      .deleteReportFromXray(resp.reportID)
                      .map: _ =>
                        logger.info(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - Report ${resp.reportID} has been deleted from the Xray UI")
                      .recover:
                        case ex => logger.error(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - Report ${resp.reportID} could not be deleted from the Xray UI", ex)

        et

  private val waitTimeSeconds: Long =
    configuration.get[FiniteDuration]("xray.reports.waitTime").toSeconds

  private [service] def checkIfReportReady(slug: SlugInfo, reportResponse: ReportResponse, counter: Int = 0)(using HeaderCarrier): Future[Either[XrayStatus, ReportStatus]] =
    xrayConnector
      .checkStatus(reportResponse.reportID)
      .flatMap:
        case rs if counter >= waitTimeSeconds =>
          logger.error(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - report was not ready in time: last status ${rs.status} for reportID: ${reportResponse.reportID}")
          Future.successful(Left(XrayStatus.Retry))
        case rs if rs.status == "completed" && rs.totalArtefacts == 0 =>
          logger.warn(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - no artefact scanned for reportID: ${reportResponse.reportID}")
          Future.successful(Left(XrayStatus.ArtefactNotFound))
        case rs if rs.status == "completed" =>
          logger.info(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - report status ${rs.status} number of rows ${rs.numberOfRows} total artefacts scanned ${rs.totalArtefacts} for reportID: ${reportResponse.reportID}")
          Future.successful(Right(rs))
        case rs =>
          org.apache.pekko.pattern.after(1000.millis, system.scheduler):
            logger.info(s"${slug.serviceName.asString}:${slug.version.original} flags: ${slug.flags.map(_.asString).mkString(", ")} - report status is ${rs.status} - rerunning for reportID: ${reportResponse.reportID}")
            checkIfReportReady(slug, reportResponse, counter + 1)

  private [service] def deleteStaleReports()(using HeaderCarrier): Future[Unit] =
    for
      ids   <- xrayConnector.getStaleReportIds()
      _     =  logger.info(s"Identified ${ids.size} stale reports to delete")
      count <- ids.foldLeftM[Future, Int](0): (acc, repId) =>
                 for
                   _ <- xrayConnector
                          .deleteReportFromXray(repId.id)
                          .recover {
                            case ex => logger.error(s"Report ${repId.id} could not be deleted from the Xray UI - this report should be deleted manually", ex)
                          }
                   _ =  logger.info(s"Deleted stale report with id: ${repId.id}")
                 yield acc + 1
      _     =  logger.info(s"Deleted $count stale reports")
    yield ()

  def addDependencyInfoScheduler()(using HeaderCarrier): Future[Unit] =
    def recursiveBatch(skip: Int): Future[Unit] =
      for
        xs <- rawReportsRepository.findAllForAddDependencyInfo(skip)
        _  <- xs.foldLeftM(()): (_, report) =>
                for
                  r <- toReport(SlugInfo.fromReport(report), generatedDate = report.generatedDate, rows = report.rows, scanned = true)
                  _ <- rawReportsRepository.put(report = r)
                yield ()
        _  <-
              if   xs.isEmpty
              then Future.unit
              else recursiveBatch(skip + xs.size)
      yield ()

    recursiveBatch(skip = 0)
