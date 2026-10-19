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

package uk.gov.hmrc.vulnerabilities

import java.time.Instant
import java.util.UUID
import org.mongodb.scala.{ObservableFuture, SingleObservableFuture}
import org.mongodb.scala.bson.BsonDocument
import org.mongodb.scala.model.{Filters, Updates}
import org.scalatest.BeforeAndAfterEach
import org.scalatest.concurrent.{IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.play.guice.GuiceOneServerPerSuite
import play.api.Application
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.json.*
import play.api.libs.ws.WSClient
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.test.CleanMongoCollectionSupport
import uk.gov.hmrc.vulnerabilities.model.v2.deployment.*
import uk.gov.hmrc.vulnerabilities.persistence.v2.*
import scala.concurrent.ExecutionContext.Implicits.global

class DeploymentOccurrencesControllerISpec
  extends AnyWordSpec
    with Matchers
    with ScalaFutures
    with IntegrationPatience
    with GuiceOneServerPerSuite
    with CleanMongoCollectionSupport
    with BeforeAndAfterEach:

  override def fakeApplication(): Application =
    GuiceApplicationBuilder()
      .configure(
        "mongodb.uri" -> mongoUri,
        "v2.read.max-findings" -> 60,
        "xray.url" -> "http://127.0.0.1:1",
        "aws.sqs.enabled" -> false
      ).build()

  private lazy val ws = app.injector.instanceOf[WSClient]
  private lazy val details = app.injector.instanceOf[VulnerabilityRepositoryV2]
  private lazy val evidence = app.injector.instanceOf[VulnerabilityOccurrenceRepositoryV2]
  private lazy val workflow = app.injector.instanceOf[ServiceOccurrenceRepositoryV2]
  private lazy val scans = app.injector.instanceOf[ScanRecordRepositoryV2]
  private lazy val mongo = app.injector.instanceOf[MongoComponent]
  private val service = "example-service"
  private val version = "1.8.0"
  private val scanned = Instant.parse("2026-09-11T10:00:00Z")
  private val deadline = Instant.parse("2026-09-15T10:00:00Z")
  private val occurrenceId = UUID.randomUUID().toString
  private def endpoint(s: String = service, v: String = version) =
    s"http://localhost:$port/vulnerabilities/api/v2/services/$s/app-versions/$v/occurrences"
  private def get(s: String = service, v: String = version) = ws.url(endpoint(s, v)).get().futureValue

  override def beforeEach(): Unit =
    super.beforeEach()
    details.collection.deleteMany(Filters.empty()).toFuture().futureValue
    evidence.collection.deleteMany(Filters.empty()).toFuture().futureValue
    workflow.collection.deleteMany(Filters.empty()).toFuture().futureValue
    scans.collection.deleteMany(Filters.empty()).toFuture().futureValue

  private def seedScan(s: String = service, v: String = version, status: String = "succeeded",
    last: Option[Instant] = Some(scanned)): Unit =
    scans.collection.insertOne(ScanRecordV2(s, v, scanned, status, last)).toFuture().futureValue

  private def seedFinding(id: String = "CVE-2026-0001", s: String = service, v: String = version,
    storedId: String = occurrenceId): Unit =
    details.collection.insertOne(VulnerabilityRecordV2(id, "Example dependency vulnerability",
      "gav://uk.gov.hmrc:example-lib", Seq("2.4.1"), Some(8.1), Some(0.14), Some(true))).toFuture().futureValue
    evidence.collection.insertOne(SlugOccurrenceRecordV2(id, s, v,
      Seq(ImportedBy("uk.gov.hmrc", "bootstrap-play", "10.1.0")), Some("2.4.0"))).toFuture().futureValue
    workflow.collection.insertOne(ServiceOccurrenceRecordV2(id, s, storedId, scanned,
      Priority.immediate, OccurrenceState.actionable,
      DeploymentSla(Some(deadline), true, true, Some("running"),
        Some(Instant.parse("2026-09-01T10:00:00Z")), Some(deadline)))).toFuture().futureValue

  "Deployment occurrences GET" should:
    "return 404 for no scan, even when unrelated collections contain records" in:
      seedFinding()
      get().status shouldBe 404

    "return succeeded with an empty array and zero totals for a successful empty scan" in:
      seedScan()
      val response = get()
      response.status shouldBe 200
      (response.json \ "scanStatus").as[String] shouldBe "succeeded"
      (response.json \ "lastSuccessfulScan").as[Instant] shouldBe scanned
      (response.json \ "results").as[Seq[JsValue]] shouldBe empty
      (response.json \ "page").as[JsObject] shouldBe Json.obj("limit" -> 0, "offset" -> 0, "total" -> 0)

    "project the full consumer shape from four collections, without any reachable upstream" in:
      seedScan()
      seedFinding()
      val response = get()
      response.status shouldBe 200
      val json = response.json
      (json \ "serviceName").as[String] shouldBe service
      (json \ "appVersion").as[String] shouldBe version
      val row = (json \ "results").as[Seq[JsObject]].head
      (row \ "occurrenceId").as[String] shouldBe occurrenceId
      (row \ "serviceName").as[String] shouldBe service
      (row \ "appVersion").as[String] shouldBe version
      (row \ "vulnerabilityId").as[String] shouldBe "CVE-2026-0001"
      (row \ "component").as[String] shouldBe "gav://uk.gov.hmrc:example-lib"
      (row \ "componentVersion").as[String] shouldBe "2.4.0"
      (row \ "fixedVersions").as[Seq[String]] shouldBe Seq("2.4.1")
      (row \ "cvss").as[Double] shouldBe 8.1
      (row \ "epss").as[Double] shouldBe 0.14
      (row \ "kev").as[Boolean] shouldBe true
      (row \ "importedBy").as[Seq[ImportedBy]] shouldBe Seq(ImportedBy("uk.gov.hmrc", "bootstrap-play", "10.1.0"))
      (row \ "priority").as[String] shouldBe "immediate"
      (row \ "state").as[String] shouldBe "actionable"
      (row \ "sla" \ "deadline").as[Instant] shouldBe deadline
      (row \ "sla" \ "breached").as[Boolean] shouldBe true
      (row \ "sla" \ "nearBreach").as[Boolean] shouldBe true
      (row \ "sla" \ "clockStartedAt").as[Instant] shouldBe Instant.parse("2026-09-01T10:00:00Z")
      (row \ "sla" \ "breachedAt").as[Instant] shouldBe deadline
      get().json shouldBe json

    "read updated enrichment and workflow without a rescan or cached result snapshot" in:
      seedScan()
      seedFinding()
      get().status shouldBe 200
      details.collection.updateOne(Filters.equal("vuln_id", "CVE-2026-0001"),
        Updates.combine(Updates.set("summary", "Updated summary"), Updates.set("epss", 0.25),
          Updates.set("guidance", "User-owned guidance remains untouched"))).toFuture().futureValue
      workflow.collection.updateOne(Filters.equal("vuln_id", "CVE-2026-0001"),
        Updates.combine(Updates.set("state", "riskAccepted"), Updates.set("priority", "schedule"))).toFuture().futureValue
      val row = (get().json \ "results").as[Seq[JsValue]].head
      (row \ "summary").as[String] shouldBe "Updated summary"
      (row \ "epss").as[Double] shouldBe 0.25
      (row \ "state").as[String] shouldBe "riskAccepted"
      (row \ "priority").as[String] shouldBe "schedule"
      val raw = mongo.database.getCollection[BsonDocument]("vulnerabilities_v2").find().headOption().futureValue.get
      raw.getString("guidance").getValue shouldBe "User-owned guidance remains untouched"

    "scope evidence to the exact service and version, and workflow to the exact service" in:
      seedScan()
      seedFinding()
      seedScan(s = "other-service")
      seedScan(v = "1.9.0")
      get("other-service").json.\("results").as[Seq[JsValue]] shouldBe empty
      get(v = "1.9.0").json.\("results").as[Seq[JsValue]] shouldBe empty
      get().json.\("page").\("total").as[Int] shouldBe 1

    "retain non-success scan status and nullable last successful scan rather than inventing success" in:
      seedScan(status = "failed", last = None)
      val response = get()
      response.status shouldBe 200
      (response.json \ "scanStatus").as[String] shouldBe "failed"
      (response.json \ "lastSuccessfulScan").get shouldBe JsNull

    "serialize a missing deadline as null and optional enrichment as absent" in:
      seedScan()
      seedFinding()
      workflow.collection.updateOne(Filters.equal("vuln_id", "CVE-2026-0001"),
        Updates.unset("sla.deadline")).toFuture().futureValue
      details.collection.updateOne(Filters.equal("vuln_id", "CVE-2026-0001"),
        Updates.combine(Updates.unset("cvss_score"), Updates.unset("epss"), Updates.unset("kev"))).toFuture().futureValue
      val row = (get().json \ "results").as[Seq[JsValue]].head
      (row \ "sla" \ "deadline").get shouldBe JsNull
      (row \ "cvss").asOpt[Double] shouldBe None
      (row \ "epss").asOpt[Double] shouldBe None
      (row \ "kev").asOpt[Boolean] shouldBe None

    "return all results above 50 and fail explicitly beyond the configured resource bound" in:
      seedScan()
      (1 to 60).foreach(i => seedFinding(s"CVE-fixture-$i", storedId = UUID.randomUUID().toString))
      val response = get()
      response.status shouldBe 200
      (response.json \ "results").as[Seq[JsValue]].size shouldBe 60
      (response.json \ "page").as[JsObject] shouldBe Json.obj("limit" -> 60, "offset" -> 0, "total" -> 60)
      seedFinding("CVE-fixture-61", storedId = UUID.randomUUID().toString)
      get().status shouldBe 500

    "fail on missing joined details instead of returning incomplete success" in:
      seedScan()
      seedFinding()
      details.collection.deleteMany(Filters.empty()).toFuture().futureValue
      get().status shouldBe 500

    "fail on missing workflow instead of generating a synthetic assessment" in:
      seedScan()
      seedFinding()
      workflow.collection.deleteMany(Filters.empty()).toFuture().futureValue
      get().status shouldBe 500

    "fail on malformed persisted workflow instead of defaulting to an enum value" in:
      seedScan()
      seedFinding()
      workflow.collection.updateOne(Filters.equal("vuln_id", "CVE-2026-0001"),
        Updates.set("state", "unknown-state")).toFuture().futureValue
      get().status shouldBe 500

    "fail on a successful scan without a successful timestamp" in:
      seedScan(last = None)
      get().status shouldBe 500

    "store dates as actual BSON dates, including nested SLA values" in:
      seedScan()
      seedFinding()
      val scan = mongo.database.getCollection[BsonDocument]("scan_records_v2").find().headOption().futureValue.get
      scan.getDateTime("scan_date").getValue shouldBe scanned.toEpochMilli
      scan.getDateTime("last_successful_scan").getValue shouldBe scanned.toEpochMilli
      val w = mongo.database.getCollection[BsonDocument]("service_occurrences_v2").find().headOption().futureValue.get
      w.getDateTime("first_detected").getValue shouldBe scanned.toEpochMilli
      w.getDocument("sla").getDateTime("deadline").getValue shouldBe deadline.toEpochMilli
      w.getDocument("sla").getDateTime("clockStartedAt").getValue shouldBe Instant.parse("2026-09-01T10:00:00Z").toEpochMilli
      w.getDocument("sla").getDateTime("breachedAt").getValue shouldBe deadline.toEpochMilli

    "preserve the existing permissive service and version bindings for opaque labels" in:
      seedScan(s = "service-label", v = "development")
      get("service-label", "development").status shouldBe 200

    "preserve the legacy team endpoint" in:
      ws.url(s"http://localhost:$port/vulnerabilities/v2/team").addQueryStringParameters("team" -> "PlatOps")
        .get().futureValue.status shouldBe 200
