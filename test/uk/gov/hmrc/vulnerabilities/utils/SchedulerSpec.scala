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
import org.mockito.MockitoSugar.mock
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.Configuration
import play.api.inject.ApplicationLifecycle
import uk.gov.hmrc.mongo.lock.MongoLockRepository
import uk.gov.hmrc.vulnerabilities.config.SchedulerConfigs
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitySummariesRepository
import uk.gov.hmrc.vulnerabilities.service.UpdateVulnerabilitiesService

import java.time.Instant
import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global


class SchedulerSpec extends AnyWordSpec with Matchers {

  implicit val as = mock[ActorSystem]
  implicit val al = mock[ApplicationLifecycle]
  val schedUtils = mock[SchedulerUtils]

  val configuration: Configuration = Configuration(
    "data.refresh-cutoff"             -> "7 days",
    "scheduler.initialDelay"          -> "10 seconds",
    "scheduler.interval"              -> "3 hours",
    "scheduler.enabled"               -> "false",
    "timeline.scheduler.initialDelay" -> "10 seconds",
    "timeline.scheduler.interval"     -> "3 hours",
    "timeline.scheduler.enabled"      -> "false",
  )

  val schedulerConfigs = new SchedulerConfigs(configuration)

  val scheduler = new Scheduler(mock[UpdateVulnerabilitiesService], schedulerConfigs, mock[VulnerabilitySummariesRepository], mock[MongoLockRepository], configuration)

}
