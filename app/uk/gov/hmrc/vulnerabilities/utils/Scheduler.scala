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

package uk.gov.hmrc.vulnerabilities.utils

import akka.actor.ActorSystem
import play.api.inject.ApplicationLifecycle
import play.api.{Configuration, Logger}
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.mongo.lock.{LockService, MongoLockRepository}
import uk.gov.hmrc.vulnerabilities.config.SchedulerConfigs
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitySummariesRepository
import uk.gov.hmrc.vulnerabilities.service.UpdateVulnerabilitiesService

import java.time.Instant
import javax.inject.{Inject, Singleton}
import scala.concurrent.duration.{DurationInt, FiniteDuration}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class Scheduler @Inject()(
  updateVulnerabilitiesService    : UpdateVulnerabilitiesService,
  config                          : SchedulerConfigs,
  vulnerabilitySummariesRepository: VulnerabilitySummariesRepository,
  mongoLockRepository             : MongoLockRepository,
  configuration                   : Configuration
)(implicit
  actorSystem         : ActorSystem,
  applicationLifecycle: ApplicationLifecycle,
  ec                  : ExecutionContext
) extends SchedulerUtils {

  private val logger = Logger(getClass)

  private val dataCutOff = configuration.get[FiniteDuration]("data.refresh-cutoff")
  private val dataReloadLock: LockService     = LockService(mongoLockRepository, "vuln-data-reload-lock", 165.minutes)

  def getNow: Instant = Instant.now()
  def sevenDaysOld(latestData: Instant, now: Instant): Boolean = latestData.isBefore(now.minusMillis(dataCutOff.toMillis))

  scheduleWithLock("Vulnerabilities data Reloader", config.dataReloadScheduler, dataReloadLock) {
    implicit val hc: HeaderCarrier = HeaderCarrier()
    for {
      latest <- vulnerabilitySummariesRepository.getMostRecent()
      _      <- if (sevenDaysOld(latest, getNow)) {
                  logger.info("Data is older than 7 days - beginning data refresh")
                  updateVulnerabilitiesService.updateVulnerabilities()
                } else {
                  logger.info("Data has already been retrieved from Xray within the last 7 days. No need to update it.")
                  Future.unit
                }
    } yield ()
  }

  def manualReload()(implicit hc: HeaderCarrier): Future[Unit] = {
    dataReloadLock
      .withLock {
        logger.info("Data refresh has been manually triggered")
        updateVulnerabilitiesService.updateVulnerabilities()
      }
      .map(_.getOrElse(logger.info(s"The Reload process is locked for ${dataReloadLock.lockId}")))
  }
}
