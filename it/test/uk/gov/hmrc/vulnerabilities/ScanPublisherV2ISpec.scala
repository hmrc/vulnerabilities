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

import java.time.{Clock, Instant, ZoneOffset}
import java.util.UUID
import java.util.concurrent.atomic.AtomicBoolean
import org.mongodb.scala.{ClientSession, MongoException, ObservableFuture, SingleObservableFuture}
import org.mongodb.scala.bson.BsonDocument
import org.mongodb.scala.model.{Filters, Updates}
import org.scalatest.{BeforeAndAfterAll, BeforeAndAfterEach, EitherValues, OptionValues}
import org.scalatest.concurrent.{IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.play.guice.GuiceOneServerPerSuite
import play.api.{Application, Configuration}
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.ws.WSClient
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.test.MongoSupport
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.model.v2.deployment.OccurrenceState
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.*
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.ScanPublicationErrorV2.*
import uk.gov.hmrc.vulnerabilities.persistence.v2.*
import uk.gov.hmrc.vulnerabilities.service.v2.UnavailableInitialWorkflowPolicyV2
import uk.gov.hmrc.vulnerabilities.support.FixtureInitialWorkflowPolicyV2
import uk.gov.hmrc.vulnerabilities.support.HistoricalPublicationV1
import scala.concurrent.{Future, Promise}
import scala.concurrent.ExecutionContext.Implicits.global

class ScanPublisherV2ISpec
  extends AnyWordSpec
    with Matchers
    with ScalaFutures
    with IntegrationPatience
    with EitherValues
    with OptionValues
    with GuiceOneServerPerSuite
    with MongoSupport
    with BeforeAndAfterAll
    with BeforeAndAfterEach:

  override def fakeApplication(): Application =
    GuiceApplicationBuilder().configure("mongodb.uri" -> mongoUri, "aws.sqs.enabled" -> false).build()

  private lazy val mongo = app.injector.instanceOf[MongoComponent]
  private lazy val details = app.injector.instanceOf[VulnerabilityRepositoryV2]
  private lazy val evidence = app.injector.instanceOf[VulnerabilityOccurrenceRepositoryV2]
  private lazy val workflows = app.injector.instanceOf[ServiceOccurrenceRepositoryV2]
  private lazy val scans = app.injector.instanceOf[ScanRecordRepositoryV2]
  private lazy val attempts = app.injector.instanceOf[ScanAttemptRepositoryV2]
  private lazy val vulnerabilityHistory = app.injector.instanceOf[VulnerabilityHistoryRepositoryV2]
  private lazy val occurrenceHistory = app.injector.instanceOf[OccurrenceHistoryRepositoryV2]
  private lazy val transactions = app.injector.instanceOf[MongoTransactionsV2]
  private lazy val store = app.injector.instanceOf[DeploymentStoreV2]
  private lazy val ws = app.injector.instanceOf[WSClient]
  private val now = Instant.parse("2026-10-21T12:00:00Z")
  private val sourceTime = Instant.parse("2026-09-11T10:00:00Z")
  private val fixedClock = Clock.fixed(now, ZoneOffset.UTC)
  private val context = ScanContextV2(ServiceName("example-service"), Version("1.8.0"))
  private val id = "CVE-2026-0001"
  private val source = XrayFindingSourceV2("XRAY-SYNTHETIC", None, Some(9.8), "High", None,
    "lib/example-lib.jar", "example-service_1.8.0.tgz", Seq("example-service", "example-lib"),
    "synthetic/example-service", sourceTime, sourceTime, None, Some("Not human guidance"), Seq("not-a-team"))
  private val finding = ScannerFindingV2(id, "Synthetic finding", Some(8.1),
    MavenComponentV2("uk.gov.hmrc", "example-lib", "2.4.0"), Seq("2.4.1"),
    Seq("https://example.invalid/one"), Seq(source))

  private def publisher(
    synthetic: Boolean = true, maxFindings: Int = 60, maxObservations: Int = 200,
    clock: Clock = fixedClock, tx: MongoTransactionsV2 = transactions, scanRepository: ScanRecordRepositoryV2 = scans
  ): ScanPublisherV2 =
    ScanPublisherV2(details, evidence, workflows, scanRepository, attempts, vulnerabilityHistory, occurrenceHistory, tx, clock,
      if synthetic then FixtureInitialWorkflowPolicyV2 else UnavailableInitialWorkflowPolicyV2(),
      Configuration("v2.write.max-findings" -> maxFindings, "v2.write.max-observations" -> maxObservations))

  private def request(
    c: ScanContextV2 = context, rows: Seq[ScannerFindingV2] = Seq(finding),
    generated: Option[Instant] = Some(sourceTime)
  ): PublishScanV2 =
    PublishScanV2(UUID.randomUUID().toString, ScannerFindingsV2(c, generated, rows), ScanCompletionV2(true, true),
      rows.map(_.vulnerabilityId -> Seq.empty[ImportedDependencyV2]).toMap, WorkflowInitialisationV2.UsePolicy)

  private def admit(input: PublishScanV2, p: ScanPublisherV2 = publisher()): ScanAdmissionV2 =
    p.admit(input.runId, input.findings.context).futureValue.value

  private def publish(input: PublishScanV2, p: ScanPublisherV2 = publisher()): ScanPublicationReceiptV2 =
    admit(input, p)
    p.publish(input).futureValue.value

  private def current(c: ScanContextV2 = context): DeploymentRecordsV2 =
    store.read(c.serviceName.asString, c.appVersion.original).futureValue.value

  private def raw(collection: String, filter: org.mongodb.scala.bson.conversions.Bson = Filters.empty()): BsonDocument =
    mongo.database.getCollection[BsonDocument](collection).find(filter).headOption().futureValue.value

  private def count(collection: String): Long =
    mongo.database.getCollection[BsonDocument](collection).countDocuments().toFuture().futureValue

  private def httpStatus(c: ScanContextV2 = context): Int =
    ws.url(s"http://localhost:$port/vulnerabilities/api/v2/services/${c.serviceName.asString}/app-versions/${c.appVersion.original}/occurrences")
      .get().futureValue.status

  override def beforeAll(): Unit =
    super.beforeAll()
    dropDatabase()
    Seq(details.ensureIndexes(), evidence.ensureIndexes(), workflows.ensureIndexes(), scans.ensureIndexes(),
      attempts.ensureIndexes(), vulnerabilityHistory.ensureIndexes(), occurrenceHistory.ensureIndexes()).foreach(_.futureValue)

  override def beforeEach(): Unit =
    super.beforeEach()
    Seq("vulnerabilities_v2", "vulnerability_occurrences_v2", "service_occurrences_v2", "scan_records_v2",
      "scan_attempts_v2", "vulnerability_history_v2", "occurrence_history_v2").foreach: name =>
        mongo.database.getCollection[BsonDocument](name).deleteMany(Filters.empty()).toFuture().futureValue

  override def afterAll(): Unit =
    try dropDatabase()
    finally
      mongoComponent.client.close()
      super.afterAll()

  "ScanPublisherV2" should:
    "replay a historical unversioned committed receipt with the frozen old fingerprint and unchanged provenance" in:
      val input = request()
      val receipt = publish(input)
      val workflow = current().workflows.head
      val history = raw("occurrence_history_v2")
      // Representative old record: identical old fields, no newly added version discriminator.
      attempts.collection.updateOne(Filters.equal("run_id", input.runId), Updates.combine(
        Updates.set("digest", HistoricalPublicationV1.fingerprint(input)), Updates.unset("fingerprint_version")))
        .toFuture().futureValue
      attempts.collection.find().headOption().futureValue.value.fingerprint_version shouldBe None
      publisher(synthetic = false).publish(input).futureValue.value shouldBe receipt
      val changed = input.copy(findings = input.findings.copy(findings = Seq(finding.copy(summary = "Different"))))
      publisher(synthetic = false).publish(changed).futureValue.left.value shouldBe RunIdentityConflict(input.runId)
      current().workflows.head shouldBe workflow
      raw("occurrence_history_v2") shouldBe history
      count("occurrence_history_v2") shouldBe 1
      raw("scan_attempts_v2").containsKey("fingerprint_version") shouldBe false
      val existingOnly = request(rows = Seq.empty).copy(workflowInitialisation = WorkflowInitialisationV2.ExistingOnly)
      val emptyReceipt = publish(existingOnly, publisher(synthetic = false))
      attempts.collection.updateOne(Filters.equal("run_id", existingOnly.runId), Updates.combine(
        Updates.set("digest", HistoricalPublicationV1.fingerprint(existingOnly)), Updates.unset("fingerprint_version")))
        .toFuture().futureValue
      publisher(synthetic = false).publish(existingOnly).futureValue.value shouldBe emptyReceipt
      count("occurrence_history_v2") shouldBe 1

    "store a versioned digest for new receipts and reject unsupported future formats" in:
      val input = request()
      val receipt = publish(input)
      val record = attempts.collection.find().headOption().futureValue.value
      record.fingerprint_version shouldBe Some(2)
      record.digest shouldBe Some(ScanPublicationFingerprintV2.current(input))
      publisher(synthetic = false).publish(input).futureValue.value shouldBe receipt
      attempts.collection.updateOne(Filters.equal("run_id", input.runId), Updates.set("fingerprint_version", 99)).toFuture().futureValue
      publisher().publish(input).futureValue.left.value shouldBe UnsupportedFingerprintVersion(99)

    "avoid policy evaluation for existing workflows even when caller permits policy use" in:
      publish(request())
      val original = current().workflows.head
      publish(request(), publisher(synthetic = false))
      current().workflows.head shouldBe original
      count("occurrence_history_v2") shouldBe 1

    "keep observation time and occurrence UUID stable across an aborted transaction retry" in:
      val input = request()
      admit(input)
      val first = AtomicBoolean(true)
      val observed = new java.util.concurrent.ConcurrentLinkedQueue[ServiceOccurrenceRecordV2]()
      val retrying = new MongoTransactionsV2(mongo):
        override def writing[A](operation: ClientSession => Future[A]): Future[A] =
          super.writing: session =>
            operation(session).flatMap: value =>
              workflows.collection.find(session).headOption().map: workflow =>
                workflow.foreach(observed.add)
                if first.compareAndSet(true, false) then throw new MongoException(11000, "forced retry before commit")
                value
      val receipt = publisher(tx = retrying).publish(input).futureValue.value
      import scala.jdk.CollectionConverters.*
      observed.asScala.toSeq should have size 2
      observed.asScala.map(_.occurrence_id).toSet should have size 1
      observed.asScala.map(_.first_detected).toSet shouldBe Set(receipt.publishedAt)
      count("occurrence_history_v2") shouldBe 1

    "publish technical findings, explicit dependency metadata, timestamps and an atomic receipt" in:
      val input = request().copy(importedBy = Map(id -> Seq(ImportedDependencyV2("upstream", "parent", "3.0"))))
      val admission = admit(input)
      admission.generation shouldBe 1L
      val receipt = publisher().publish(input).futureValue.value
      receipt.publishedAt shouldBe now
      receipt.evidenceChanges shouldBe EvidenceChangesV2(Seq(id), Seq.empty, Seq.empty)
      val result = current()
      result.scan.status shouldBe "succeeded"
      result.scan.scan_date shouldBe now
      result.scan.last_successful_scan shouldBe Some(now)
      result.scan.source_report_generated shouldBe Some(sourceTime)
      result.evidence.head.component_version shouldBe Some("2.4.0")
      result.evidence.head.imported_by.head.version shouldBe "3.0"
      result.evidence.head.scanner_observation.value.sources shouldBe Seq(source)
      result.vulnerabilities.head.fixed_version shouldBe Seq("2.4.1")
      result.workflows.head.first_detected shouldBe now
      result.workflows.head.synthetic_initialisation shouldBe Some(true)
      raw("scan_records_v2").get("scan_date").isDateTime shouldBe true
      raw("vulnerability_occurrences_v2").getDocument("scanner_observation")
        .getArray("sources").get(0).asDocument().get("published").isDateTime shouldBe true
      UUID.fromString(result.workflows.head.occurrence_id)
      count("vulnerability_history_v2") shouldBe 1
      count("occurrence_history_v2") shouldBe 1
      httpStatus() shouldBe 200

    "return the durable receipt on exact retries without writes or duplicate history" in:
      val input = request()
      val first = publish(input)
      val revision = current().vulnerabilities.head.scanner_revision
      admit(input).generation shouldBe 1
      val later = publisher(clock = Clock.fixed(now.plusSeconds(300), ZoneOffset.UTC))
      later.publish(input).futureValue.value shouldBe first
      current().vulnerabilities.head.scanner_revision shouldBe revision
      count("scan_attempts_v2") shouldBe 1
      count("vulnerability_history_v2") shouldBe 1
      count("occurrence_history_v2") shouldBe 1

    "reject changed content for an already published run" in:
      val input = request()
      val first = publish(input)
      val changed = input.copy(findings = input.findings.copy(findings = Seq(finding.copy(summary = "Changed"))))
      publisher().publish(changed).futureValue.left.value shouldBe RunIdentityConflict(input.runId)
      publisher().publish(input).futureValue.value shouldBe first

    "replay a committed receipt even if workflow policy is subsequently unavailable" in:
      val input = request()
      val receipt = publish(input)
      publisher(synthetic = false).publish(input).futureValue.value shouldBe receipt

    "record BSON-millisecond server time so a real nanosecond clock cannot change retry receipts" in:
      val input = request()
      val p = publisher(clock = Clock.fixed(Instant.parse("2026-10-21T12:00:00.123456789Z"), ZoneOffset.UTC))
      val first = publish(input, p)
      first.publishedAt shouldBe Instant.parse("2026-10-21T12:00:00.123Z")
      p.publish(input).futureValue.value shouldBe first
      current().workflows.head.first_detected shouldBe first.publishedAt

    "reject run identity reuse for a different deployment and reject unadmitted publication" in:
      val input = request()
      admit(input)
      publisher().admit(input.runId, context.copy(appVersion = Version("2.0.0"))).futureValue.left.value shouldBe
        RunIdentityConflict(input.runId)
      publisher().publish(request()).futureValue.left.value shouldBe a[UnknownRun]
      store.read("example-service", "1.8.0").futureValue shouldBe None

    "preserve the occurrence UUID, first detection and workflow across versions and evidence removal" in:
      val first = request()
      publish(first)
      val original = current().workflows.head
      workflows.collection.updateOne(Filters.equal("vuln_id", id), Updates.set("state", "riskAccepted")).toFuture().futureValue
      val laterContext = context.copy(appVersion = Version("2.0.0"))
      publish(request(c = laterContext))
      val next = current(laterContext).workflows.head
      next.occurrence_id shouldBe original.occurrence_id
      next.first_detected shouldBe original.first_detected
      next.state shouldBe OccurrenceState.riskAccepted
      publish(request(rows = Seq.empty))
      publish(request())
      current().workflows.head shouldBe next
      count("service_occurrences_v2") shouldBe 1
      count("occurrence_history_v2") shouldBe 1

    "update scanner fields while preserving guidance, enrichment and unknown workflow/evidence fields" in:
      publish(request())
      val initial = current().workflows.head
      details.collection.updateOne(Filters.equal("vuln_id", id), Updates.combine(
        Updates.set("guidance", "Human-maintained"), Updates.set("epss", 0.72), Updates.set("kev", true),
        Updates.set("future_user_field", "retained"))).toFuture().futureValue
      workflows.collection.updateOne(Filters.equal("vuln_id", id),
        Updates.set("internet_facing", true)).toFuture().futureValue
      evidence.collection.updateOne(Filters.equal("vuln_id", id),
        Updates.set("future_evidence_field", "retained")).toFuture().futureValue
      val changed = finding.copy(summary = "Revised", cvss = Some(9.0), fixedVersions = Seq("2.5.0"),
        references = Seq("https://example.invalid/two"))
      publish(request(rows = Seq(changed)))
      val result = current()
      result.vulnerabilities.head.summary shouldBe "Revised"
      result.vulnerabilities.head.cvss_score shouldBe Some(9.0)
      result.vulnerabilities.head.fixed_version shouldBe Seq("2.5.0")
      result.vulnerabilities.head.epss shouldBe Some(0.72)
      result.vulnerabilities.head.kev shouldBe Some(true)
      result.vulnerabilities.head.references shouldBe Some(Seq("https://example.invalid/one", "https://example.invalid/two"))
      result.workflows.head shouldBe initial
      raw("vulnerabilities_v2").getString("guidance").getValue shouldBe "Human-maintained"
      raw("vulnerabilities_v2").getString("future_user_field").getValue shouldBe "retained"
      raw("service_occurrences_v2").getBoolean("internet_facing").getValue shouldBe true
      raw("vulnerability_occurrences_v2").getString("future_evidence_field").getValue shouldBe "retained"
      count("vulnerability_history_v2") shouldBe 2

    "preserve CVSS on an absent incoming score and merge rather than clear references" in:
      publish(request())
      publish(request(rows = Seq(finding.copy(cvss = None, references = Seq.empty))))
      current().vulnerabilities.head.cvss_score shouldBe Some(8.1)
      current().vulnerabilities.head.references shouldBe Some(finding.references)
      current().evidence.head.scanner_observation.value.cvss shouldBe None
      count("vulnerability_history_v2") shouldBe 1

    "retain an unknown CVSS as absent rather than zero" in:
      publish(request(rows = Seq(finding.copy(cvss = None))))
      current().vulnerabilities.head.cvss_score shouldBe None

    "allow different installed dependency versions with compatible global scanner details" in:
      publish(request())
      val other = context.copy(serviceName = ServiceName("other-service"))
      publish(request(c = other, rows = Seq(finding.copy(component = finding.component.copy(installedVersion = "2.3.0")))))
      current(other).evidence.head.component_version shouldBe Some("2.3.0")
      current().evidence.head.component_version shouldBe Some("2.4.0")

    Seq(
      "component" -> finding.copy(component = finding.component.copy(artefact = "another-lib")),
      "summary" -> finding.copy(summary = "Incompatible summary"),
      "fixedVersions" -> finding.copy(fixedVersions = Seq("3.0.0")),
      "cvss" -> finding.copy(cvss = Some(9.9))
    ).foreach { (field, changed) =>
      s"reject conflicting $field evidence from another service without publishing any rows" in:
        publish(request())
        val previous = current()
        val other = context.copy(serviceName = ServiceName("other-service"))
        val input = request(c = other, rows = Seq(finding.copy(vulnerabilityId = "CVE-2026-0002"), changed))
        admit(input)
        publisher().publish(input).futureValue.left.value match
          case ScannerConflict(`id`, fields, _) => fields should contain(field)
          case error => fail(s"Expected scanner conflict, got $error")
        current() shouldBe previous
        store.read(other.serviceName.asString, other.appVersion.original).futureValue shouldBe None
        count("vulnerabilities_v2") shouldBe 1
        count("vulnerability_history_v2") shouldBe 1
    }

    "reject incompatible fixes retained by another application version of the same service" in:
      publish(request())
      val input = request(c = context.copy(appVersion = Version("2.0.0")),
        rows = Seq(finding.copy(fixedVersions = Seq("3.0.0"))))
      admit(input)
      publisher().publish(input).futureValue.left.value shouldBe a[ScannerConflict]

    "reject component identity changes even when there is no other deployment" in:
      publish(request())
      val input = request(rows = Seq(finding.copy(component = finding.component.copy(artefact = "another-lib"))))
      admit(input)
      publisher().publish(input).futureValue.left.value shouldBe a[ScannerConflict]

    "allow scanner updates after incompatible observations have actually been removed" in:
      publish(request())
      val other = context.copy(serviceName = ServiceName("other-service"))
      publish(request(c = other))
      publish(request(c = other, rows = Seq.empty))
      publish(request(rows = Seq(finding.copy(summary = "New summary", fixedVersions = Seq("3.0.0")))))
      current().vulnerabilities.head.summary shouldBe "New summary"

    "not treat missing scores from other deployments as authoritative zero or a conflict" in:
      publish(request(rows = Seq(finding.copy(cvss = None))))
      val other = context.copy(serviceName = ServiceName("other-service"))
      publish(request(c = other, rows = Seq(finding.copy(cvss = Some(9.0)))))
      current().vulnerabilities.head.cvss_score shouldBe Some(9.0)
      val noScore = request(rows = Seq(finding.copy(cvss = None)))
      publish(noScore)
      current().vulnerabilities.head.cvss_score shouldBe Some(9.0)

    "reject unmanaged global records rather than adopting or replacing them" in:
      details.collection.insertOne(VulnerabilityRecordV2(id, finding.summary, finding.component.identity,
        finding.fixedVersions, finding.cvss, None, None)).toFuture().futureValue
      val input = request()
      admit(input)
      publisher().publish(input).futureValue.left.value shouldBe AdoptionRequired(id)
      raw("vulnerabilities_v2").containsKey("scanner_revision") shouldBe false
      count("scan_records_v2") shouldBe 0

    "reject retained evidence without scanner provenance" in:
      publish(request())
      evidence.collection.updateOne(Filters.equal("vuln_id", id), Updates.unset("scanner_observation")).toFuture().futureValue
      val input = request(c = context.copy(serviceName = ServiceName("other-service")))
      admit(input)
      publisher().publish(input).futureValue.left.value shouldBe AdoptionRequired(id)

    "require explicit completion and coverage without changing the last successful GET dataset or status" in:
      publish(request())
      val previous = current()
      Seq(ScanCompletionV2(false, true), ScanCompletionV2(true, false), ScanCompletionV2(false, false)).foreach: completion =>
        val input = request(rows = Seq.empty).copy(completion = completion)
        admit(input)
        publisher().publish(input).futureValue.left.value shouldBe UnverifiedScan
        current() shouldBe previous
        httpStatus() shouldBe 200

    "keep a failed first attempt unavailable to GET rather than publishing failure as a scan" in:
      val input = request().copy(completion = ScanCompletionV2(false, false))
      admit(input)
      publisher().publish(input).futureValue.left.value shouldBe UnverifiedScan
      httpStatus() shouldBe 404

    "replace exact-version evidence on verified empty success without resolving or deleting workflows" in:
      publish(request())
      val otherVersion = context.copy(appVersion = Version("2.0.0"))
      publish(request(c = otherVersion))
      val originalWorkflow = current().workflows.head
      val receipt = publish(request(rows = Seq.empty))
      receipt.evidenceChanges shouldBe EvidenceChangesV2(Seq.empty, Seq.empty, Seq(id))
      current().evidence shouldBe empty
      current().scan.status shouldBe "succeeded"
      httpStatus() shouldBe 200
      current(otherVersion).evidence should have size 1
      current(otherVersion).workflows.head shouldBe originalWorkflow
      count("occurrence_history_v2") shouldBe 1
      count("vulnerabilities_v2") shouldBe 1

    "publish a verified empty first scan without workflow initialisation or invented policy" in:
      val input = request(rows = Seq.empty).copy(workflowInitialisation = WorkflowInitialisationV2.ExistingOnly)
      publish(input, publisher(synthetic = false))
      current().evidence shouldBe empty
      count("service_occurrences_v2") shouldBe 0

    "keep production policy unavailable and require explicit caller intent even with a fixture provider" in:
      val input = request()
      admit(input)
      app.injector.instanceOf[ScanPublisherV2].publish(input).futureValue.left.value shouldBe WorkflowPolicyUnavailable(id)
      val existingOnly = input.copy(workflowInitialisation = WorkflowInitialisationV2.ExistingOnly)
      publisher().publish(existingOnly).futureValue.left.value shouldBe InitialisationRequired(id)
      count("vulnerabilities_v2") shouldBe 0

    "preserve existing workflows without requiring any initial policy" in:
      publish(request())
      val input = request(c = context.copy(appVersion = Version("2.0.0")))
        .copy(workflowInitialisation = WorkflowInitialisationV2.ExistingOnly)
      publish(input, publisher(synthetic = false))
      current(input.findings.context).workflows.head.occurrence_id shouldBe current().workflows.head.occurrence_id

    "require explicitly supplied imported-by for new evidence and preserve it on later omitted input" in:
      val missing = request().copy(importedBy = Map.empty)
      admit(missing)
      publisher().publish(missing).futureValue.left.value shouldBe MissingImportedBy(id)
      val input = request().copy(importedBy = Map(id -> Seq(ImportedDependencyV2("parent", "lib", "1"))))
      publish(input)
      val later = request().copy(importedBy = Map.empty)
      publish(later)
      current().evidence.head.imported_by.head.group shouldBe "parent"
      val newVersion = request(c = context.copy(appVersion = Version("2.0.0"))).copy(importedBy = Map.empty)
      admit(newVersion)
      publisher().publish(newVersion).futureValue.left.value shouldBe MissingImportedBy(id)

    "reserve increasing generations at admission and prevent older completion overwriting a newer success" in:
      val older = request()
      val newer = request(rows = Seq(finding.copy(summary = "Newer")))
      admit(older).generation shouldBe 1
      admit(newer).generation shouldBe 2
      val receipt = publisher().publish(newer).futureValue.value
      publisher().publish(older).futureValue.left.value shouldBe Superseded(older.runId, 2L)
      current().scan.run_id shouldBe Some(newer.runId)
      current().vulnerabilities.head.summary shouldBe "Newer"
      publisher().publish(newer).futureValue.value shouldBe receipt

    "allow an older success when a newer admitted attempt fails validation" in:
      val older = request()
      val newer = request().copy(completion = ScanCompletionV2(false, true))
      admit(older)
      admit(newer)
      publisher().publish(newer).futureValue.left.value shouldBe UnverifiedScan
      publisher().publish(older).futureValue.value.generation shouldBe 1
      current().scan.run_id shouldBe Some(older.runId)

    "return an old durable receipt even after a newer generation has published" in:
      val older = request()
      val receipt = publish(older)
      val newer = request()
      publish(newer)
      publisher().publish(older).futureValue.value shouldBe receipt
      current().scan.run_id shouldBe Some(newer.runId)

    "deduplicate concurrent admissions and allocate unique ordered generations" in:
      val p = publisher()
      val one = request()
      val same = Future.sequence((1 to 8).map(_ => p.admit(one.runId, context))).futureValue.map(_.value)
      same.map(_.generation).distinct shouldBe Seq(1L)
      val runs = (1 to 8).map(_ => request())
      val admissions = Future.sequence(runs.map(r => p.admit(r.runId, context))).futureValue.map(_.value)
      admissions.map(_.generation).sorted shouldBe (2L to 9L)
      count("scan_attempts_v2") shouldBe 9

    "deduplicate concurrent publication retries for the same logical run" in:
      val input = request()
      admit(input)
      val p = publisher()
      val receipts = Future.sequence((1 to 6).map(_ => p.publish(input))).futureValue.map(_.value)
      receipts.distinct should have size 1
      current().vulnerabilities.head.scanner_revision shouldBe Some(1L)
      count("vulnerability_history_v2") shouldBe 1
      count("occurrence_history_v2") shouldBe 1

    "revalidate supersession when a newer success commits during the older transaction's reads" in:
      val older = request()
      val newer = request(rows = Seq(finding.copy(summary = "Newer")))
      admit(older)
      admit(newer)
      val readStarted = Promise[Unit]()
      val continueRead = Promise[Unit]()
      val firstRead = AtomicBoolean(true)
      val pausedScans = new ScanRecordRepositoryV2(mongo):
        override def findDeployment(service: String, version: String, session: Option[ClientSession]) =
          super.findDeployment(service, version, session).flatMap: result =>
            if firstRead.compareAndSet(true, false) then
              readStarted.success(())
              continueRead.future.map(_ => result)
            else Future.successful(result)
      val finishingOlder = publisher(scanRepository = pausedScans).publish(older)
      readStarted.future.futureValue
      try publisher().publish(newer).futureValue.value.generation shouldBe 2L
      finally continueRead.trySuccess(())
      finishingOlder.futureValue.left.value shouldBe Superseded(older.runId, 2L)
      current().scan.run_id shouldBe Some(newer.runId)
      current().vulnerabilities.head.summary shouldBe "Newer"

    "serialize concurrent global creation and reuse a workflow across application versions" in:
      val one = request()
      val two = request(c = context.copy(appVersion = Version("2.0.0")))
      admit(one)
      admit(two)
      Future.sequence(Seq(publisher().publish(one), publisher().publish(two))).futureValue.foreach(_.isRight shouldBe true)
      count("vulnerabilities_v2") shouldBe 1
      count("service_occurrences_v2") shouldBe 1
      count("vulnerability_occurrences_v2") shouldBe 2
      count("vulnerability_history_v2") shouldBe 1
      count("occurrence_history_v2") shouldBe 1

    "reject one of two concurrent incompatible global creations instead of last-writer wins" in:
      val one = request()
      val two = request(c = context.copy(serviceName = ServiceName("other-service")),
        rows = Seq(finding.copy(fixedVersions = Seq("3.0.0"))))
      admit(one)
      admit(two)
      val results = Future.sequence(Seq(publisher().publish(one), publisher().publish(two))).futureValue
      results.count(_.isRight) shouldBe 1
      results.flatMap(_.left.toOption).head shouldBe a[ScannerConflict]
      count("scan_records_v2") shouldBe 1
      count("vulnerability_occurrences_v2") shouldBe 1

    "atomically roll back details, workflows, evidence, history and receipt on a late transaction failure" in:
      publish(request())
      val previous = current()
      val input = request(rows = Seq(finding.copy(vulnerabilityId = "CVE-2026-0002")))
      admit(input)
      val failing = new MongoTransactionsV2(mongo):
        override def snapshot[A](operation: ClientSession => Future[A]): Future[A] =
          super.snapshot(session => operation(session).flatMap(_ => Future.failed(IllegalStateException("forced rollback"))))
      publisher(tx = failing).publish(input).failed.futureValue.getMessage shouldBe "forced rollback"
      current() shouldBe previous
      count("vulnerabilities_v2") shouldBe 1
      count("service_occurrences_v2") shouldBe 1
      count("vulnerability_history_v2") shouldBe 1
      count("occurrence_history_v2") shouldBe 1
      attempts.collection.find(Filters.equal("run_id", input.runId)).headOption().futureValue.value.receipt shouldBe None
      publisher().publish(input).futureValue.value.evidenceChanges.removed shouldBe Seq(id)

    "reconcile an uncertain commit reply through the same durable run receipt" in:
      val input = request()
      admit(input)
      val uncertain = new MongoTransactionsV2(mongo):
        override def writing[A](operation: ClientSession => Future[A]): Future[A] =
          super.writing(operation).flatMap: _ =>
            val error = new MongoException("Simulated lost commit reply")
            error.addLabel(MongoException.UNKNOWN_TRANSACTION_COMMIT_RESULT_LABEL)
            Future.failed(error)
      publisher(tx = uncertain).publish(input).futureValue.left.value match
        case StorageFailure(_, uncertainCommit) => uncertainCommit shouldBe true
        case other => fail(s"Expected uncertain storage result, got $other")
      val receipt = publisher().publish(input).futureValue.value
      current().scan.scan_date shouldBe receipt.publishedAt
      count("vulnerability_history_v2") shouldBe 1
      count("occurrence_history_v2") shouldBe 1

    "record evidence changes on the receipt and history only for actual detail/workflow changes" in:
      publish(request())
      val identical = publish(request())
      identical.evidenceChanges shouldBe EvidenceChangesV2(Seq.empty, Seq.empty, Seq.empty)
      count("vulnerability_history_v2") shouldBe 1
      count("occurrence_history_v2") shouldBe 1
      val changed = finding.copy(component = finding.component.copy(installedVersion = "2.3.0"))
      publish(request(rows = Seq(changed))).evidenceChanges.changed shouldBe Seq(id)
      count("vulnerability_history_v2") shouldBe 1
      val revised = request(rows = Seq(changed.copy(summary = "Revised")))
      publish(revised)
      val events = vulnerabilityHistory.collection.find().toFuture().futureValue
      events.map(_.event_type).sorted shouldBe Seq("details_updated", "vulnerability_created")
      events.foreach: event =>
        event.actor shouldBe HistoryActorV2("system", "xray-v2-publication")
        event.occurred_at shouldBe now
        event.sources.head.keys should contain("run_id")
      count("occurrence_history_v2") shouldBe 1

    "preserve absent report time without retaining a previous report's timestamp" in:
      publish(request())
      publish(request(generated = None))
      current().scan.source_report_generated shouldBe None
      current().evidence.head.scanner_observation.value.source_report_generated shouldBe None
      current().scan.scan_date shouldBe now

    "fail bounded publication and global conflict checks instead of truncating them" in:
      val many = request(rows = Seq(finding, finding.copy(vulnerabilityId = "CVE-2026-0002")))
      admit(many)
      publisher(maxFindings = 1).publish(many).futureValue.left.value shouldBe a[ResourceLimit]
      publish(request())
      publish(request(c = context.copy(serviceName = ServiceName("other-service"))))
      val input = request()
      admit(input)
      publisher(maxObservations = 1).publish(input).futureValue.left.value shouldBe a[ResourceLimit]
      current().scan.run_id should not be Some(input.runId)

    "reject forged or duplicate findings and unknown imported-by keys at the boundary" in:
      val invalid = Seq(
        request(rows = Seq(finding, finding)),
        request(rows = Seq(finding.copy(vulnerabilityId = "XRAY-1234"))),
        request(rows = Seq(finding.copy(cvss = Some(Double.NaN)))),
        request(rows = Seq(finding.copy(component = finding.component.copy(group = "not/a/group")))),
        request().copy(importedBy = Map("CVE-2026-9999" -> Seq.empty))
      )
      invalid.foreach: input =>
        admit(input)
        publisher().publish(input).futureValue.left.value shouldBe a[InvalidInput]
      count("scan_records_v2") shouldBe 0

    "keep deployment reads coherent when a publication commits between join queries" in:
      val first = request()
      publish(first)
      val readStarted = Promise[Unit]()
      val continueRead = Promise[Unit]()
      val pausedScans = new ScanRecordRepositoryV2(mongo):
        override def findDeployment(service: String, version: String, session: Option[ClientSession]) =
          super.findDeployment(service, version, session).flatMap: result =>
            readStarted.success(())
            continueRead.future.map(_ => result)
      val snapshotStore = DeploymentStoreV2(details, evidence, workflows, pausedScans, transactions,
        Configuration("v2.read.max-findings" -> 60))
      val reading = snapshotStore.read("example-service", "1.8.0")
      readStarted.future.futureValue
      val next = request(rows = Seq(finding.copy(vulnerabilityId = "CVE-2026-0002")))
      try publish(next)
      finally continueRead.trySuccess(())
      val snapshot = reading.futureValue.value
      snapshot.scan.run_id shouldBe Some(first.runId)
      snapshot.evidence.map(_.vuln_id) shouldBe Seq(id)
      snapshot.vulnerabilities.map(_.vuln_id) shouldBe Seq(id)
      snapshot.workflows.map(_.vuln_id) shouldBe Seq(id)
      current().scan.run_id shouldBe Some(next.runId)
      current().evidence.map(_.vuln_id) shouldBe Seq("CVE-2026-0002")
