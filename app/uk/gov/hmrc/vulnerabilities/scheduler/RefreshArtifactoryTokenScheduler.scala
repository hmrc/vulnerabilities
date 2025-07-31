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
import play.api.{Configuration, Logging}
import play.api.inject.ApplicationLifecycle
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.mongo.TimestampSupport
import uk.gov.hmrc.mongo.lock.{MongoLockRepository, ScheduledLockService}
import uk.gov.hmrc.vulnerabilities.service.XrayService

import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext


@Singleton
class RefreshArtifactoryTokenScheduler @Inject()(
  configuration       : Configuration,
  xrayService         : XrayService,
  mongoLockRepository : MongoLockRepository,
  timestampSupport    : TimestampSupport
)(implicit
  actorSystem         : ActorSystem,
  applicationLifecycle: ApplicationLifecycle,
  ec                  : ExecutionContext
) extends SchedulerUtils
     with Logging:

  private val schedulerConfig = SchedulerConfig(configuration, "scheduler.refreshArtifactoryToken")

  private given HeaderCarrier = HeaderCarrier()

  private val lock =
    ScheduledLockService(
      lockRepository    = mongoLockRepository,
      lockId            = "refreshArtifactoryToken",
      timestampSupport  = timestampSupport,
      schedulerInterval = schedulerConfig.interval
    )

  scheduleWithLock("Refresh Artifactory Token", schedulerConfig, lock):
    for
      _ <- xrayService.refreshToken()
      _ =  logger.info("Successfully refreshed Artifactory token")
    yield ()
