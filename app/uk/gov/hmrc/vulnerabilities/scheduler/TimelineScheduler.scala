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
import uk.gov.hmrc.vulnerabilities.model.ArtefactName
import uk.gov.hmrc.vulnerabilities.persistence.{RawReportsRepository, VulnerabilitiesTimelineRepository}
import uk.gov.hmrc.vulnerabilities.service.TeamService

import java.time.{DayOfWeek, LocalDate, ZoneOffset}
import java.time.temporal.TemporalAdjusters
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class TimelineScheduler @Inject()(
  configuration         : Configuration,
  teamService           : TeamService,
  rawReportsRepository  : RawReportsRepository,
  timelineRepository    : VulnerabilitiesTimelineRepository,
  mongoLockRepository   : MongoLockRepository,
  timestampSupport      : TimestampSupport
 )(using
  ActorSystem,
  ApplicationLifecycle,
  ExecutionContext
 ) extends SchedulerUtils with Logging:

  private val schedulerConfigs =
    SchedulerConfig(configuration, "scheduler.timeline")

  private val lock: ScheduledLockService =
    ScheduledLockService(
      lockRepository    = mongoLockRepository,
      lockId            = "vuln-timeline-update-lock",
      timestampSupport  = timestampSupport,
      schedulerInterval = schedulerConfigs.interval
    )

  given HeaderCarrier = HeaderCarrier()

  scheduleWithLock("Vulnerabilities timeline updater", schedulerConfigs, lock):
    val weekBeginning =
      LocalDate
        .now()
        .`with`(TemporalAdjusters.previousOrSame(DayOfWeek.MONDAY))
        .atStartOfDay()
        .toInstant(ZoneOffset.UTC)

    timelineRepository
      .getTimelineCounts(from = weekBeginning, to = weekBeginning)
      .flatMap:
        case xs if xs.nonEmpty  =>
          logger.info(s"Timeline scheduler week beginning: $weekBeginning detected weekly data has already been added - aborting run")
          Future.unit
        case _ =>
          for
            timeline          <- rawReportsRepository.getTimelineData(weekBeginning)
            artefactToTeams   <- teamService.artefactToTeams()
            timelineWithTeams =  timeline.map(sv => sv.copy(teams = artefactToTeams.getOrElse(ArtefactName(sv.service), Seq.empty)))
            _                 <- timelineRepository.replaceOrInsert(timelineWithTeams)
            _                 =  logger.info(s"Timeline scheduler week beginning: $weekBeginning has added the weekly data: ${timelineWithTeams.size} rows")
          yield ()
