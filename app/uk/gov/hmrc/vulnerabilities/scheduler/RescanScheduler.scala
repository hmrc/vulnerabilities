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
import play.api.{Configuration, Logging}
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.mongo.TimestampSupport
import uk.gov.hmrc.mongo.lock.{ScheduledLockService, MongoLockRepository}
import uk.gov.hmrc.vulnerabilities.service.XrayService

import java.time.Instant
import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext
import scala.concurrent.duration.FiniteDuration

@Singleton
class ReloadScheduler @Inject()(
  configuration      : Configuration,
  xrayService        : XrayService,
  mongoLockRepository: MongoLockRepository,
  timestampSupport   : TimestampSupport
)(using
  ActorSystem,
  ApplicationLifecycle,
  ExecutionContext
) extends SchedulerUtils
    with Logging:

  private val schedulerConfigs =
    SchedulerConfig(configuration, "scheduler.rescan")

  private def reportsBefore() =
    Instant.now().minusMillis(configuration.get[FiniteDuration]("scheduler.rescan.stale-report").toMillis)

  private val lock: ScheduledLockService =
    ScheduledLockService(
      lockRepository    = mongoLockRepository,
      lockId            = "vuln-data-rescan-lock",
      timestampSupport  = timestampSupport,
      schedulerInterval = schedulerConfigs.interval
    )

  private given HeaderCarrier = HeaderCarrier()

  scheduleWithLock("Vulnerabilities data Reloader", schedulerConfigs, lock):
    xrayService.rescanStaleReports(reportsBefore())
