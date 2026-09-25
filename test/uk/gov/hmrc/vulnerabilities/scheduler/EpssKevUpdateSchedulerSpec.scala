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

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

import java.time.{Clock, Instant, ZoneOffset}
import scala.concurrent.duration.*

class EpssKevUpdateSchedulerSpec extends AnyWordSpec with Matchers:

  "EpssKevUpdateScheduler.initialDelayUntilNextRun" should:
    "return the time remaining until 23:00 UTC on the current day" in:
      initialDelay("2026-09-23T22:30:00Z") shouldBe 30.minutes

    "schedule the following day when the service starts at exactly 23:00 UTC" in:
      initialDelay("2026-09-23T23:00:00Z") shouldBe 24.hours

    "schedule the following day when the service starts after 23:00 UTC" in:
      initialDelay("2026-09-23T23:30:00Z") shouldBe 23.hours + 30.minutes

  private def initialDelay(value: String): FiniteDuration =
    EpssKevUpdateScheduler.initialDelayUntilNextRun(
      Clock.fixed(Instant.parse(value), ZoneOffset.UTC)
    )
