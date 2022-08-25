package uk.gov.hmrc.vulnerabilities.persistence

import org.scalatest.concurrent.IntegrationPatience
import org.scalatest.matchers.must.Matchers
import org.scalatest.wordspec.AnyWordSpecLike
import uk.gov.hmrc.mongo.test.{CleanMongoCollectionSupport, PlayMongoRepositorySupport}
import uk.gov.hmrc.vulnerabilities.model.Vulnerability

import java.time.Instant
import java.time.temporal.ChronoUnit
import scala.concurrent.ExecutionContext.Implicits.global

class VulnerabilitiesRepositorySpec
  extends AnyWordSpecLike
    with Matchers
    with PlayMongoRepositorySupport[Vulnerability]
    with CleanMongoCollectionSupport
    with IntegrationPatience {

  override protected def repository = new VulnerabilitiesRepository(mongoComponent)

  private val now = Instant.now().truncatedTo(ChronoUnit.MILLIS)

  private val vulnerability1 =
    Vulnerability(
      service = "service1",
      serviceVersion = "1",
      vulnerableComponentName = "component1",
      vulnerableComponentVersion = "1.0",
      componentPathInSlug = "",
      id = "CVE-TEST-1",
      score = 1.0,
      description = "desc1",
      requiresAction = true,
      assessment = "",
      lastReviewed = now,
      teams = Seq("team1", "team2"),
      references = Seq("test", "test"),
      published = now,
      scanned = now
    )

  private val vulnerability2 =
    Vulnerability(
      service = "service2",
      serviceVersion = "2",
      vulnerableComponentName = "component2",
      vulnerableComponentVersion = "2.0",
      componentPathInSlug = "",
      id = "CVE-TEST-2",
      score = 2.0,
      description = "desc2",
      requiresAction = true,
      assessment = "",
      lastReviewed = now,
      teams = Seq("team1", "team2"),
      references = Seq("test", "test"),
      published = now,
      scanned = now
    )

  private val vulnerability3 =
    Vulnerability(
      service = "service3",
      serviceVersion = "3",
      vulnerableComponentName = "component3",
      vulnerableComponentVersion = "3.0",
      componentPathInSlug = "",
      id = "XRAY-TEST-1",
      score = 3.0,
      description = "desc3",
      requiresAction = false,
      assessment = "",
      lastReviewed = now,
      teams = Seq("team1"),
      references = Seq("test", "test"),
      published = now,
      scanned = now
    )

  "search" must {

    "find all vulnerabilities" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search().futureValue
      results must contain allOf(vulnerability1, vulnerability2, vulnerability3)
    }

    "find all vulnerabilities by team name" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search(team = Some("team2")).futureValue
      results must contain only (vulnerability1, vulnerability2)
    }

    "find all vulnerabilities for a service" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search(service = Some("service1")).futureValue
      results must contain only (vulnerability1)
    }

    "find all vulnerabilities by id" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search(id = Some("CVE-TEST-1")).futureValue
      results must contain only (vulnerability1)
    }

    "find all vulnerabilities by description" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search(description = Some("desc")).futureValue
      results must contain allOf(vulnerability1, vulnerability2, vulnerability3)
    }
  }
}
