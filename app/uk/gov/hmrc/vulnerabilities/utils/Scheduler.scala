/*
 * Copyright 2022 HM Revenue & Customs
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

package uk.gov.hmrc.vulnerabilities.utils

import akka.actor.ActorSystem
import play.api.inject.ApplicationLifecycle
import play.api.{Configuration, Logger}
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.vulnerabilities.config.{SchedulerConfig, SchedulerConfigs}
import uk.gov.hmrc.vulnerabilities.persistence.{MongoLock, RawReportsRepository, VulnerabilitySummariesRepository}
import uk.gov.hmrc.vulnerabilities.service.UpdateVulnerabilitiesService

import java.time.temporal.ChronoUnit
import java.time.{Instant, LocalDateTime, ZoneOffset}
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import scala.concurrent.duration.{DAYS, DurationInt, FiniteDuration}
import scala.util.control.NonFatal

@Singleton
class Scheduler @Inject()(
   updateVulnerabilitiesService: UpdateVulnerabilitiesService,
   config: SchedulerConfigs,
   vulnerabilitySummariesRepository: VulnerabilitySummariesRepository,
   mongoLock:           MongoLock
)( implicit
   actorSystem         : ActorSystem,
   applicationLifecycle: ApplicationLifecycle,
   ec                  : ExecutionContext
) extends SchedulerUtils {

  private val logger= Logger(getClass)
  implicit val hc: HeaderCarrier = HeaderCarrier()

  private def getNow = LocalDateTime.now().toInstant(ZoneOffset.UTC)
  private def sevenDaysOld(latestData: Instant, now: Instant): Boolean = !latestData.isBefore(now.minus(7L, ChronoUnit.DAYS))

  scheduleWithLock("Vulnerabilities data Reloader", config.dataReloadScheduler, mongoLock.dataReloadLock) {
    for {
      latest <- vulnerabilitySummariesRepository.getMostRecent
      _      <- if (sevenDaysOld(latest, getNow)) {
                  logger.info("Data is older than 7 days - beginning data refresh")
                  updateVulnerabilitiesService.updateVulnerabilities()
                } else {
                  logger.info("Data has already been retrieved from Xray within the last 7 days. No need to update it.")
                  Future.unit
                }
    } yield ()
  }

  def manualReload: Future[Unit] = {
    mongoLock.dataReloadLock
      .withLock {
        logger.info("Data refresh has been manually triggered")
        updateVulnerabilitiesService.updateVulnerabilities()
      }
      .map(_.getOrElse(logger.debug(s"The Reload process is locked for ${mongoLock.dataReloadLock.lockId}")))
  }
}
