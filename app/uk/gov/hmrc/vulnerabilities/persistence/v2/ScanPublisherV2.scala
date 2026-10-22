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

package uk.gov.hmrc.vulnerabilities.persistence.v2

import java.nio.charset.StandardCharsets.UTF_8
import java.time.{Clock, Instant}
import java.time.temporal.ChronoUnit.MILLIS
import java.util.UUID
import javax.inject.{Inject, Singleton}
import org.mongodb.scala.{ClientSession, MongoException, ObservableFuture, SingleObservableFuture}
import org.mongodb.scala.bson.BsonDocument
import org.mongodb.scala.model.{Filters, Sorts, UpdateOptions}
import org.mongodb.scala.bson.conversions.Bson
import play.api.{Configuration, Logger}
import play.api.libs.json.*
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.model.v2.deployment.ImportedBy
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.*
import uk.gov.hmrc.vulnerabilities.model.v2.ingestion.ScanPublicationErrorV2.*
import uk.gov.hmrc.vulnerabilities.service.v2.InitialWorkflowPolicyV2
import ScanPublicationFingerprintV2.observation
import scala.concurrent.{ExecutionContext, Future}

/** Private persistence boundary. No connector, trigger, policy engine or automatic adoption. */
@Singleton
class ScanPublisherV2 @Inject()(
  details: VulnerabilityRepositoryV2,
  evidence: VulnerabilityOccurrenceRepositoryV2,
  workflows: ServiceOccurrenceRepositoryV2,
  scans: ScanRecordRepositoryV2,
  attempts: ScanAttemptRepositoryV2,
  vulnerabilityHistory: VulnerabilityHistoryRepositoryV2,
  occurrenceHistory: OccurrenceHistoryRepositoryV2,
  transactions: MongoTransactionsV2,
  clock: Clock,
  policy: InitialWorkflowPolicyV2,
  config: Configuration
)(using ExecutionContext):
  private val logger = Logger(getClass)
  private val maximum = config.get[Int]("v2.write.max-findings")
  private val maximumObservations = config.get[Int]("v2.write.max-observations")
  require(maximum > 0 && maximum < Int.MaxValue / 2, "v2.write.max-findings must be positive and less than Int.MaxValue / 2")
  require(maximumObservations > 0 && maximumObservations < Int.MaxValue,
    "v2.write.max-observations must be positive and less than Int.MaxValue")

  private case class Rejected(error: ScanPublicationErrorV2) extends RuntimeException(error.toString)
  private def reject(error: ScanPublicationErrorV2): Nothing = throw Rejected(error)
  private def bound(size: Int, limit: Int, reason: String): Unit =
    if size > limit then reject(ResourceLimit(reason))

  private def deployment(context: ScanContextV2, serviceField: String = "service"): Bson =
    Filters.and(Filters.equal(serviceField, context.serviceName.asString),
      Filters.equal("service_version", context.appVersion.original))

  private def contextOf(attempt: ScanAttemptRecordV2): ScanContextV2 =
    ScanContextV2(ServiceName(attempt.service_name), Version(attempt.service_version))

  private def result[A](operation: => Future[A]): Future[Either[ScanPublicationErrorV2, A]] =
    Future.unit.flatMap(_ => operation).map(Right(_)).recover:
      case Rejected(error) =>
        logger.warn(s"V2 publication rejected: $error")
        Left(error)
      case e: MongoException =>
        logger.error("V2 publication database operation failed; reconcile using the same run identity", e)
        Left(StorageFailure(e, e.hasErrorLabel(MongoException.UNKNOWN_TRANSACTION_COMMIT_RESULT_LABEL)))

  /** Admission, not completion time, establishes ordering. Reusing a run cannot allocate another generation. */
  def admit(runId: String, context: ScanContextV2): Future[Either[ScanPublicationErrorV2, ScanAdmissionV2]] =
    result:
      validateIdentity(runId, context)
      val admittedAt = clock.instant().truncatedTo(MILLIS)
      transactions.writing: session =>
        attempts.collection.find(session, Filters.equal("run_id", runId)).headOption().flatMap:
          case Some(previous) =>
            if contextOf(previous) != context then reject(RunIdentityConflict(runId))
            Future.successful(ScanAdmissionV2(runId, context, previous.generation))
          case None =>
            attempts.collection.find(session, deployment(context, "service_name"))
              .sort(Sorts.descending("generation")).limit(1).headOption().flatMap: latest =>
                if latest.exists(_.generation == Long.MaxValue) then reject(ResourceLimit("Scan generation exhausted"))
                val generation = latest.fold(1L)(_.generation + 1)
                attempts.collection.insertOne(session,
                  ScanAttemptRecordV2(runId, context.serviceName.asString, context.appVersion.original, generation, admittedAt))
                  .toFuture().map(_ => ScanAdmissionV2(runId, context, generation))

  def publish(input: PublishScanV2): Future[Either[ScanPublicationErrorV2, ScanPublicationReceiptV2]] =
    result:
      validate(input)
      val digest = ScanPublicationFingerprintV2.current(input)
      // Fixed for the whole operation, including transaction retries; not the exact commit instant.
      val publishedAt = clock.instant().truncatedTo(MILLIS)
      val occurrenceIds = input.findings.findings.map(f => f.vulnerabilityId -> UUID.randomUUID().toString).toMap
      transactions.writing: session =>
        attempts.collection.find(session, Filters.equal("run_id", input.runId)).headOption().flatMap:
          case None => reject(UnknownRun(input.runId))
          case Some(attempt) =>
            if contextOf(attempt) != input.findings.context then reject(RunIdentityConflict(input.runId))
            attempt.receipt match
              case Some(receipt) =>
                val expected = attempt.fingerprint_version match
                  case None => ScanPublicationFingerprintV2.legacy(input)
                  case Some(ScanPublicationFingerprintV2.currentVersion) => digest
                  case Some(version) => reject(UnsupportedFingerprintVersion(version))
                if !attempt.digest.contains(expected) then reject(RunIdentityConflict(input.runId))
                Future.successful(receipt)
              case None => publishTransaction(session, input, attempt, digest, publishedAt, occurrenceIds)

  private def validateIdentity(runId: String, context: ScanContextV2): Unit =
    if runId.isBlank || context.serviceName.asString.isBlank || context.appVersion.original.isBlank then
      reject(InvalidInput("Run, service and application version must be nonblank"))

  private def validate(input: PublishScanV2): Unit =
    validateIdentity(input.runId, input.findings.context)
    if !input.completion.reportSucceeded || !input.completion.artefactCoverageVerified then reject(UnverifiedScan)
    val findings = input.findings.findings
    bound(findings.size, maximum, "Incoming report exceeds the finding limit")
    if findings.map(_.vulnerabilityId).distinct.size != findings.size then reject(InvalidInput("Duplicate CVE findings"))
    if (input.importedBy.keySet -- findings.map(_.vulnerabilityId)).nonEmpty then
      reject(InvalidInput("Imported-by supplied for a CVE absent from the report"))
    findings.foreach: finding =>
      val component = finding.component
      val tokens = Seq(component.group, component.artefact, component.installedVersion)
      if !finding.vulnerabilityId.matches("CVE-[0-9]{4}-[0-9]{4,}") ||
        tokens.exists(t => t.isEmpty || t.exists(c => c.isWhitespace || c.isSpaceChar || ":/?#".contains(c))) ||
        finding.cvss.exists(s => !s.isFinite || s < 0 || s > 10)
      then reject(InvalidInput("Publication requires validated CVE, Maven coordinates and optional CVSS"))

  private case class Plan(
    before: Map[String, VulnerabilityRecordV2],
    after: Map[String, VulnerabilityRecordV2],
    newEvidence: Map[String, SlugOccurrenceRecordV2],
    newWorkflows: Seq[ServiceOccurrenceRecordV2],
    changes: EvidenceChangesV2
  )

  private def publishTransaction(
    session: ClientSession, input: PublishScanV2, attempt: ScanAttemptRecordV2, digest: String, publishedAt: Instant,
    occurrenceIds: Map[String, String]
  ): Future[ScanPublicationReceiptV2] =
    val context = input.findings.context
    for
      scan <- scans.findDeployment(context.serviceName.asString, context.appVersion.original, Some(session))
      _ = if scan.flatMap(_.generation).exists(_ > attempt.generation) then
        reject(Superseded(input.runId, scan.flatMap(_.generation).get))
      previous <- evidence.findDeployment(context.serviceName.asString, context.appVersion.original, maximum, Some(session))
      _ = bound(previous.size, maximum, "Existing deployment exceeds the finding limit")
      ids = (previous.map(_.vuln_id) ++ input.findings.findings.map(_.vulnerabilityId)).distinct.sorted
      global <- if ids.isEmpty then Future.successful(Seq.empty[VulnerabilityRecordV2])
        else details.findByIds(ids, maximum * 2, Some(session))
      retained <- if ids.isEmpty then Future.successful(Seq.empty[SlugOccurrenceRecordV2])
        else evidence.collection.find(session, Filters.in("vuln_id", ids*)).limit(maximumObservations + 1).toFuture()
      _ = bound(retained.size, maximumObservations, "Global compatibility evidence exceeds the observation limit")
      existingWorkflows <- if ids.isEmpty then Future.successful(Seq.empty[ServiceOccurrenceRecordV2])
        else workflows.findByIds(context.serviceName.asString, ids, maximum * 2, Some(session))
      plan = prepare(input, global, previous, retained, existingWorkflows, publishedAt, occurrenceIds)
      _ <- writeDetails(session, input, attempt, plan, publishedAt)
      _ <- writeWorkflows(session, input, attempt, plan, publishedAt)
      _ <- writeEvidence(session, context, plan)
      scanRecord = ScanRecordV2(context.serviceName.asString, context.appVersion.original, publishedAt,
        "succeeded", Some(publishedAt), Some(input.runId), Some(attempt.generation), input.findings.generatedDate)
      scanFields = ScanRecordV2.mongoFormat.writes(scanRecord)
      _ <- scans.collection.updateOne(session, deployment(context, "service_name"),
        set(scanFields + ("source_report_generated" -> scanFields.value.getOrElse("source_report_generated", JsNull))),
        UpdateOptions().upsert(true)).toFuture()
      receipt = ScanPublicationReceiptV2(input.runId, attempt.generation, publishedAt, plan.changes)
      _ <- attempts.collection.updateOne(session, Filters.equal("run_id", input.runId),
        set(Json.obj("digest" -> digest, "fingerprint_version" -> ScanPublicationFingerprintV2.currentVersion,
          "receipt" -> ScanAttemptRecordV2.receiptFormat.writes(receipt))))
        .toFuture()
    yield receipt

  private def prepare(
    input: PublishScanV2,
    global: Seq[VulnerabilityRecordV2],
    previous: Seq[SlugOccurrenceRecordV2],
    retained: Seq[SlugOccurrenceRecordV2],
    existingWorkflows: Seq[ServiceOccurrenceRecordV2],
    publishedAt: Instant,
    occurrenceIds: Map[String, String]
  ): Plan =
    val context = input.findings.context
    val before = global.map(v => v.vuln_id -> v).toMap
    val oldEvidence = previous.map(e => e.vuln_id -> e).toMap
    global.foreach(v => if v.scanner_revision.isEmpty then reject(AdoptionRequired(v.vuln_id)))
    retained.foreach: e =>
      if e.scanner_observation.isEmpty || !before.contains(e.vuln_id) then reject(AdoptionRequired(e.vuln_id))
    val otherEvidence = retained.filterNot(e => e.service == context.serviceName.asString && e.service_version == context.appVersion.original)
    val after = input.findings.findings.map: finding =>
      val id = finding.vulnerabilityId
      val other = otherEvidence.filter(_.vuln_id == id)
      val fields = Seq(
        Option.when(before.get(id).exists(_.vuln_component != finding.component.identity) ||
          other.exists(_.scanner_observation.exists(_.component != finding.component.identity)))("component"),
        Option.when(other.exists(_.scanner_observation.exists(_.summary != finding.summary)))("summary"),
        Option.when(other.exists(_.scanner_observation.exists(_.fixed_versions.toSet != finding.fixedVersions.toSet)))("fixedVersions"),
        Option.when(finding.cvss.exists(score => other.exists(_.scanner_observation.exists(_.cvss.exists(_ != score)))))("cvss")
      ).flatten
      if fields.nonEmpty then reject(ScannerConflict(id, fields, other.map(e =>
        ScanContextV2(ServiceName(e.service), Version(e.service_version))).distinct))
      val existing = before.get(id)
      val references = (existing.flatMap(_.references).getOrElse(Seq.empty) ++ finding.references).distinct
      val fixes = existing.filter(_.fixed_version.toSet == finding.fixedVersions.toSet)
        .fold(finding.fixedVersions)(_.fixed_version)
      id -> VulnerabilityRecordV2(id, finding.summary, finding.component.identity, fixes,
        finding.cvss.orElse(existing.flatMap(_.cvss_score)), existing.flatMap(_.epss), existing.flatMap(_.kev),
        Some(references), Some(existing.flatMap(_.scanner_revision).getOrElse(0L)))
    val newEvidence = input.findings.findings.map: finding =>
      val id = finding.vulnerabilityId
      val importedBy = input.importedBy.get(id).map(_.map(d => ImportedBy(d.group, d.artefact, d.version)))
        .orElse(oldEvidence.get(id).map(_.imported_by)).getOrElse(reject(MissingImportedBy(id)))
      id -> SlugOccurrenceRecordV2(id, context.serviceName.asString, context.appVersion.original,
        importedBy, Some(finding.component.installedVersion), Some(observation(input, finding)))
    val newWorkflows = input.findings.findings.filterNot(f => existingWorkflows.exists(_.vuln_id == f.vulnerabilityId)).map: finding =>
      if input.workflowInitialisation != WorkflowInitialisationV2.UsePolicy then reject(InitialisationRequired(finding.vulnerabilityId))
      val values = policy.initialValues(InitialWorkflowContextV2(context, finding, publishedAt)).fold(reject, identity)
      ServiceOccurrenceRecordV2(finding.vulnerabilityId, context.serviceName.asString,
        occurrenceIds(finding.vulnerabilityId), publishedAt, values.priority, values.state, values.sla,
        synthetic_initialisation = Some(values.synthetic))
    val next = newEvidence.toMap
    val added = next.keySet -- oldEvidence.keySet
    val removed = oldEvidence.keySet -- next.keySet
    val changed = (next.keySet intersect oldEvidence.keySet).filter: id =>
      val old = oldEvidence(id)
      val current = next(id)
      old.copy(scanner_observation = old.scanner_observation.map(_.copy(run_id = input.runId))) != current
    Plan(before, after.toMap, next, newWorkflows,
      EvidenceChangesV2(added.toSeq.sorted, changed.toSeq.sorted, removed.toSeq.sorted))

  private def scannerFields(v: VulnerabilityRecordV2): JsObject =
    Json.obj("vuln_id" -> v.vuln_id, "summary" -> v.summary, "vuln_component" -> v.vuln_component,
      "fixed_version" -> v.fixed_version, "references" -> v.references.getOrElse(Seq.empty)) ++
      v.cvss_score.fold(Json.obj())(score => Json.obj("cvss_score" -> score))

  private def set(fields: JsObject): BsonDocument =
    BsonDocument(Json.stringify(Json.obj("$set" -> fields)))

  private def serial[A](items: Iterable[A])(operation: A => Future[Unit]): Future[Unit] =
    items.foldLeft(Future.unit)((previous, item) => previous.flatMap(_ => operation(item)))

  private def writeDetails(
    session: ClientSession, input: PublishScanV2, attempt: ScanAttemptRecordV2, plan: Plan, now: Instant
  ): Future[Unit] =
    // Also lock removed CVEs: concurrent publications must recheck retained observations after removals.
    serial((plan.before.keySet ++ plan.after.keySet).toSeq.sorted): id =>
      val next = plan.after.get(id)
      val old = plan.before.get(id)
      val write = old match
        case None =>
          details.collection.insertOne(session, next.get.copy(scanner_revision = Some(1L))).toFuture().map(_ => ())
        case Some(_) =>
          val update = Json.obj("$inc" -> Json.obj("scanner_revision" -> 1L)) ++
            next.fold(Json.obj())(v => Json.obj("$set" -> scannerFields(v)))
          details.collection.updateOne(session, Filters.equal("vuln_id", id), BsonDocument(Json.stringify(update)))
            .toFuture().map(_ => ())
      write.flatMap: _ =>
        next match
          case Some(v) if old.isEmpty || old.exists(o => scannerFields(o) != scannerFields(v)) =>
            val eventType = if old.isEmpty then "vulnerability_created" else "details_updated"
            vulnerabilityHistory.collection.insertOne(session, history(input, attempt, id, None, eventType, now,
              Json.obj("before" -> old.map(scannerFields), "after" -> scannerFields(v)),
              plan.newWorkflows.exists(_.synthetic_initialisation.contains(true)))).toFuture().map(_ => ())
          case _ => Future.unit

  private def writeWorkflows(
    session: ClientSession, input: PublishScanV2, attempt: ScanAttemptRecordV2, plan: Plan, now: Instant
  ): Future[Unit] =
    serial(plan.newWorkflows): workflow =>
      for
        _ <- workflows.collection.insertOne(session, workflow).toFuture()
        _ <- occurrenceHistory.collection.insertOne(session, history(input, attempt, workflow.vuln_id,
          Some(workflow.service), "occurrence_created", now,
          Json.obj("after" -> ServiceOccurrenceRecordV2.mongoFormat.writes(workflow),
            "synthetic" -> workflow.synthetic_initialisation.contains(true)),
          workflow.synthetic_initialisation.contains(true))).toFuture()
      yield ()

  private def writeEvidence(session: ClientSession, context: ScanContextV2, plan: Plan): Future[Unit] =
    for
      _ <- serial(plan.changes.removed): id =>
        evidence.collection.deleteOne(session, Filters.and(deployment(context), Filters.equal("vuln_id", id)))
          .toFuture().map(_ => ())
      _ <- serial(plan.newEvidence.values.toSeq.sortBy(_.vuln_id)): e =>
        evidence.collection.updateOne(session, Filters.and(deployment(context), Filters.equal("vuln_id", e.vuln_id)),
          set(SlugOccurrenceRecordV2.mongoFormat.writes(e)), UpdateOptions().upsert(true)).toFuture().map(_ => ())
    yield ()

  private def history(
    input: PublishScanV2, attempt: ScanAttemptRecordV2, id: String, service: Option[String],
    eventType: String, now: Instant, changes: JsObject, syntheticInitialisation: Boolean
  ): HistoryRecordV2 =
    val identity = Json.stringify(Json.arr(input.runId, id, service, eventType))
    HistoryRecordV2(UUID.nameUUIDFromBytes(identity.getBytes(UTF_8)).toString, id, service, eventType,
      now, HistoryActorV2("system", "xray-v2-publication"), changes, "Validated V2 scan publication",
      Seq(Json.obj("run_id" -> input.runId, "generation" -> attempt.generation,
        "synthetic_initialisation" -> syntheticInitialisation)))
