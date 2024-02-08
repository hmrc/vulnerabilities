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

package uk.gov.hmrc.vulnerabilities.scheduler

import org.apache.pekko.actor.ActorSystem
import play.api.inject.ApplicationLifecycle
import play.api.Logger
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.mongo.TimestampSupport
import uk.gov.hmrc.mongo.lock.{ScheduledLockService, MongoLockRepository}
import uk.gov.hmrc.vulnerabilities.config.SchedulerConfigs
import uk.gov.hmrc.vulnerabilities.service.UpdateVulnerabilitiesService

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class ReloadScheduler @Inject()(
  updateVulnerabilitiesService: UpdateVulnerabilitiesService,
  config                      : SchedulerConfigs,
  mongoLockRepository         : MongoLockRepository,
  timestampSupport            : TimestampSupport
)(implicit
  actorSystem         : ActorSystem,
  applicationLifecycle: ApplicationLifecycle,
  ec                  : ExecutionContext
) extends SchedulerUtils {

  private val logger = Logger(getClass)

  private val dataReloadLock: ScheduledLockService =
    ScheduledLockService(
      lockRepository    = mongoLockRepository,
      lockId            = "vuln-data-reload-lock",
      timestampSupport  = timestampSupport,
      schedulerInterval = config.dataReloadScheduler.frequency
    )

  scheduleWithLock("Vulnerabilities data Reloader", config.dataReloadScheduler, dataReloadLock) {
    implicit val hc: HeaderCarrier = HeaderCarrier()
    for {
      _ <- Future.successful(logger.info("Beginning data refresh"))
      _ <- updateVulnerabilitiesService.updateAllVulnerabilities()
    } yield ()
  }

  def manualReload()(implicit hc: HeaderCarrier): Future[Unit] =
    dataReloadLock
      .withLock {
        logger.info("Data refresh has been manually triggered")
        updateVulnerabilitiesService.updateAllVulnerabilities()
      }
      .map(_.getOrElse(logger.info(s"The Reload process is locked for ${dataReloadLock.lockId}")))
}
