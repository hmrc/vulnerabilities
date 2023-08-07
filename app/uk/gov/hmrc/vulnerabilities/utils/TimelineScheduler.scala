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
import play.api.Logger
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.mongo.lock.{LockService, MongoLockRepository}
import uk.gov.hmrc.vulnerabilities.config.SchedulerConfigs
import uk.gov.hmrc.vulnerabilities.service.VulnerabilitiesTimelineService

import javax.inject.{Inject, Singleton}
import scala.concurrent.duration.DurationInt
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class TimelineScheduler @Inject()(
  vulnerabilitiesTimelineService: VulnerabilitiesTimelineService,
  config                        : SchedulerConfigs,
  mongoLockRepository           : MongoLockRepository,
 )(implicit
  actorSystem         : ActorSystem,
  applicationLifecycle: ApplicationLifecycle,
  ec                  : ExecutionContext
 ) extends SchedulerUtils {

  private val timelineUpdateLock: LockService = LockService(mongoLockRepository, "vuln-timeline-update-lock", 60.minutes)

  private val logger = Logger(getClass)

  scheduleWithLock("Vulnerabilities timeline updater", config.timelineUpdateScheduler, timelineUpdateLock) {
    implicit val hc: HeaderCarrier = HeaderCarrier()
    logger.info("Starting to update the vulnerabilities timeline data")
    for {
      _      <- vulnerabilitiesTimelineService.updateTimelineData()
      _      = logger.info("Finished updating vulnerabilities timeline data")
    } yield ()
  }

  def manualReload()(implicit hc: HeaderCarrier): Future[Unit] =
    timelineUpdateLock
      .withLock {
        logger.info("vulnerabilitiesTimeline data update has been manually triggered")
        for {
          _      <- vulnerabilitiesTimelineService.updateTimelineData()
          _      = logger.info("Finished updating vulnerabilities timeline data")
        } yield ()
      }
      .map(_.getOrElse(logger.info(s"The vulnerabilitiesTimeline data update process is locked for ${timelineUpdateLock.lockId}")))
}
