/*
 * Copyright 2026 HM Revenue & Customs
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
import uk.gov.hmrc.mongo.lock.{MongoLockRepository, ScheduledLockService}
import uk.gov.hmrc.vulnerabilities.service.ExploitInfoService

import java.time.{Clock, LocalDate, LocalDateTime, LocalTime, ZoneOffset}
import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext
import scala.concurrent.duration.FiniteDuration

@Singleton
class EpssKevUpdateScheduler @Inject()(
  configuration    : Configuration,
  exploitInfoService: ExploitInfoService,
  mongoLockRepository : MongoLockRepository,
  timestampSupport    : TimestampSupport,
  clock            : Clock
)(using
  ActorSystem,
  ApplicationLifecycle,
  ExecutionContext
) extends SchedulerUtils with Logging:

  private val configuredScheduler = SchedulerConfig(configuration, "scheduler.epss")
  private val schedulerConfig = configuredScheduler.copy(
    initialDelay = EpssKevUpdateScheduler.initialDelayUntilNextRun(clock)
  )

  private given HeaderCarrier = HeaderCarrier()

  logger.info("Starting EPSS score scheduler")
  private val schedulerConfigs =
    SchedulerConfig(configuration, "scheduler.timeline")

  private val lock: ScheduledLockService =
    ScheduledLockService(
      lockRepository = mongoLockRepository,
      lockId = "vuln-timeline-update-lock",
      timestampSupport = timestampSupport,
      schedulerInterval = schedulerConfigs.interval
      )

  schedule("EPSS score refresh", schedulerConfig):
    exploitInfoService.refreshExploitInfo()

object EpssKevUpdateScheduler:
  private val RunTime = LocalTime.of(23, 0)
  private val Utc = ZoneOffset.UTC

  def initialDelayUntilNextRun(clock: Clock): FiniteDuration =
    val now = LocalDateTime.ofInstant(clock.instant(), Utc)
    val todayAtRunTime = LocalDateTime.of(LocalDate.from(now), RunTime)
    val nextRun =
      if todayAtRunTime.isAfter(now) then todayAtRunTime
      else todayAtRunTime.plusDays(1)

    FiniteDuration(java.time.Duration.between(now, nextRun).toMillis, scala.concurrent.duration.MILLISECONDS)
