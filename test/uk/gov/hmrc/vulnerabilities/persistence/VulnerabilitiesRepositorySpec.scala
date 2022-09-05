/*
 * Copyright 2022 HM Revenue & Customs
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
      score = Some(1.0),
      description = "desc1",
      requiresAction = Some(true),
      assessment = Some(""),
      lastReviewed = Some(now),
      teams = Some(Seq("team1", "team2")),
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
      score = Some(2.0),
      description = "desc2",
      requiresAction = Some(true),
      assessment = Some(""),
      lastReviewed = Some(now),
      teams = Some(Seq("team1", "team2")),
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
      score = None,
      description = "desc3",
      requiresAction = Some(false),
      assessment = Some(""),
      lastReviewed = Some(now),
      teams = Some(Seq("team1")),
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

    "find all vulnerabilities that requireAction" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search(requiresAction = Some(true)).futureValue
      results must contain theSameElementsAs(Seq(vulnerability1, vulnerability2))
    }

    "find all vulnerabilities that don't requireAction" in {
      repository.collection.insertMany(Seq(vulnerability1, vulnerability2, vulnerability3)).toFuture().futureValue
      val results = repository.search(requiresAction = Some(false)).futureValue
      results must contain only(vulnerability3)
    }
  }
}
