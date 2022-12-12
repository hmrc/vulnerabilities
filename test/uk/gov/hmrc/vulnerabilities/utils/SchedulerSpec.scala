package uk.gov.hmrc.vulnerabilities.utils

import akka.actor.ActorSystem
import org.mockito.MockitoSugar.mock
import org.scalatest.matchers.must.Matchers.convertToAnyMustWrapper
import org.scalatest.wordspec.AnyWordSpec
import play.api.Configuration
import play.api.inject.ApplicationLifecycle
import uk.gov.hmrc.vulnerabilities.config.SchedulerConfigs
import uk.gov.hmrc.vulnerabilities.persistence.{MongoLock, VulnerabilitySummariesRepository}
import uk.gov.hmrc.vulnerabilities.service.UpdateVulnerabilitiesService

import java.time.{LocalDateTime, ZoneOffset}
import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global


class SchedulerSpec extends AnyWordSpec{

  implicit val as = mock[ActorSystem]
  implicit val al = mock[ApplicationLifecycle]
  val schedUtils = mock[SchedulerUtils]

  val configuration: Configuration = Configuration(
    "data.refresh-cutoff"    -> "7 days",
    "scheduler.initialDelay" -> "10 seconds",
    "scheduler.interval"     -> "3 hours",
    "scheduler.enabled"      -> "false"
  )

  val schedulerConfigs = new SchedulerConfigs(configuration)

  val scheduler = new Scheduler(mock[UpdateVulnerabilitiesService], schedulerConfigs, mock[VulnerabilitySummariesRepository], mock[MongoLock])


  "sevenDaysOld" when {
    "given a date 6 days and 23 hours prior to it" should {
      "return false" in {
        val res = scheduler.sevenDaysOld(LocalDateTime.now().minus(167, ChronoUnit.HOURS).toInstant(ZoneOffset.UTC), scheduler.getNow)
        res mustBe false
      }
    }

    "given a date 7 days and 1 minute prior to it" should {
      "return true" in {
        val res = scheduler.sevenDaysOld(LocalDateTime.now()
          .minus(168, ChronoUnit.HOURS)
          .minus(1, ChronoUnit.MINUTES)
          .toInstant(ZoneOffset.UTC), scheduler.getNow)
        res mustBe true
      }
    }
  }
}
