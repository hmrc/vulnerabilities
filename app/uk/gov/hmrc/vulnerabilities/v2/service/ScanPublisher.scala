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

package uk.gov.hmrc.vulnerabilities.v2.service

import java.nio.charset.StandardCharsets.UTF_8
import java.time.{Clock, Instant}
import java.time.temporal.ChronoUnit.MILLIS
import java.util.UUID
import javax.inject.{Inject, Singleton}
import org.mongodb.scala.{MongoException, ObservableFuture, SingleObservableFuture}
import org.mongodb.scala.bson.BsonDocument
import org.mongodb.scala.model.{Filters, Sorts, UpdateOptions}
import org.mongodb.scala.bson.conversions.Bson
import play.api.{Configuration, Logger}
import play.api.libs.json.*
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.v2.model.deployment.ImportedBy
import uk.gov.hmrc.vulnerabilities.v2.model.deployment.OccurrenceState
import uk.gov.hmrc.vulnerabilities.v2.model.ingestion.*
import uk.gov.hmrc.vulnerabilities.v2.model.ingestion.ScanPublicationError.*
import uk.gov.hmrc.vulnerabilities.v2.persistence.*
import ScanPublicationFingerprint.observation
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class ScanPublisher @Inject()(
  details: VulnerabilityRepository,
  evidence: VulnerabilityOccurrenceRepository,
  workflows: ServiceOccurrenceRepository,
  scans: ScanRecordRepository,
  attempts: ScanAttemptRepository,
  vulnerabilityHistory: VulnerabilityHistoryRepository,
  occurrenceHistory: OccurrenceHistoryRepository,
  clock: Clock,
  policy: InitialWorkflowPolicy,
  config: Configuration
)(using ExecutionContext):
  private val logger = Logger(getClass)
  private val maximum = config.get[Int]("v2.write.max-findings")
  private val maximumObservations = config.get[Int]("v2.write.max-observations")
  require(maximum > 0 && maximum < Int.MaxValue / 2, "v2.write.max-findings must be positive and less than Int.MaxValue / 2")
  require(maximumObservations > 0 && maximumObservations < Int.MaxValue,
    "v2.write.max-observations must be positive and less than Int.MaxValue")

  private case class Rejected(error: ScanPublicationError) extends RuntimeException(error.toString)
  private def reject(error: ScanPublicationError): Nothing = throw Rejected(error)
  private def bound(size: Int, limit: Int, reason: String): Unit =
    if size > limit then reject(ResourceLimit(reason))

  private def deployment(context: ScanContext, serviceField: String = "service"): Bson =
    Filters.and(Filters.equal(serviceField, context.serviceName.asString),
      Filters.equal("service_version", context.appVersion.original))

  private def contextOf(attempt: ScanAttemptRecord): ScanContext =
    ScanContext(ServiceName(attempt.service_name), Version(attempt.service_version))

  private def result[A](operation: => Future[A]): Future[Either[ScanPublicationError, A]] =
    Future.unit.flatMap(_ => operation).map(Right(_)).recover:
      case Rejected(error) =>
        logger.warn(s"V2 publication rejected: $error")
        Left(error)
      case e: MongoException =>
        logger.error("V2 publication database operation failed; inspect persisted state before retrying", e)
        Left(StorageFailure(e))

  def admit(runId: String, context: ScanContext): Future[Either[ScanPublicationError, ScanAdmission]] =
    result:
      validateIdentity(runId, context)
      val admittedAt = clock.instant().truncatedTo(MILLIS)
      attempts.collection.find(Filters.equal("run_id", runId)).headOption().flatMap:
          case Some(previous) =>
            if contextOf(previous) != context then reject(RunIdentityConflict(runId))
            Future.successful(ScanAdmission(runId, context, previous.generation))
          case None =>
            attempts.collection.find(deployment(context, "service_name"))
              .sort(Sorts.descending("generation")).limit(1).headOption().flatMap: latest =>
                if latest.exists(_.generation == Long.MaxValue) then reject(ResourceLimit("Scan generation exhausted"))
                val generation = latest.fold(1L)(_.generation + 1)
                attempts.collection.insertOne(
                  ScanAttemptRecord(runId, context.serviceName.asString, context.appVersion.original, generation, admittedAt))
                  .toFuture().map(_ => ScanAdmission(runId, context, generation))

  def publish(input: PublishScan): Future[Either[ScanPublicationError, ScanPublicationReceipt]] =
    result:
      validate(input)
      val digest = ScanPublicationFingerprint.current(input)
      val publishedAt = clock.instant().truncatedTo(MILLIS)
      val occurrenceIds = input.findings.findings.map(f => f.vulnerabilityId -> UUID.randomUUID().toString).toMap
      attempts.collection.find(Filters.equal("run_id", input.runId)).headOption().flatMap:
          case None => reject(UnknownRun(input.runId))
          case Some(attempt) =>
            if contextOf(attempt) != input.findings.context then reject(RunIdentityConflict(input.runId))
            attempt.receipt match
              case Some(receipt) =>
                val expected = attempt.fingerprint_version match
                  case None => ScanPublicationFingerprint.legacy(input)
                  case Some(ScanPublicationFingerprint.currentVersion) => digest
                  case Some(version) => reject(UnsupportedFingerprintVersion(version))
                if !attempt.digest.contains(expected) then reject(RunIdentityConflict(input.runId))
                Future.successful(receipt)
              case None => publishOperations(input, attempt, digest, publishedAt, occurrenceIds)

  private def validateIdentity(runId: String, context: ScanContext): Unit =
    if runId.isBlank || context.serviceName.asString.isBlank || context.appVersion.original.isBlank then
      reject(InvalidInput("Run, service and application version must be nonblank"))

  private def validate(input: PublishScan): Unit =
    validateIdentity(input.runId, input.findings.context)
    if !input.completion.reportSucceeded || !input.completion.artefactCoverageVerified then reject(UnverifiedScan)
    val findings = input.findings.findings
    bound(findings.size, maximum, "Incoming report exceeds the finding limit")
    if findings.map(_.observationKey).distinct.size != findings.size then
      reject(InvalidInput("Duplicate component observations"))
    if (input.importedBy.keySet -- (findings.map(_.vulnerabilityId) ++ findings.map(_.observationKey))).nonEmpty then
      reject(InvalidInput("Imported-by supplied for an observation absent from the report"))
    findings.foreach: finding =>
      val component = finding.component
      val tokens = Seq(component.group, component.artefact, component.installedVersion)
      if !finding.vulnerabilityId.matches("CVE-[0-9]{4}-[0-9]{4,}") ||
        tokens.exists(t => t.isEmpty || t.exists(c => c.isWhitespace || c.isSpaceChar || ":/?#".contains(c))) ||
        finding.cvss.exists(s => !s.isFinite || s < 0 || s > 10)
      then reject(InvalidInput("Publication requires validated CVE, Maven coordinates and optional CVSS"))

  private case class Plan(
    before: Map[String, VulnerabilityRecord],
    after: Map[String, VulnerabilityRecord],
    newEvidence: Map[String, SlugOccurrenceRecord],
    newWorkflows: Seq[ServiceOccurrenceRecord],
    reopenedWorkflows: Seq[WorkflowReopening],
    changes: EvidenceChanges
  )

  private case class WorkflowReopening(
    workflow: ServiceOccurrenceRecord,
    newState: OccurrenceState,
    previousCvss: Double,
    newCvss: Double
  )

  private case class PublicationState(
    previous: Seq[SlugOccurrenceRecord],
    global: Seq[VulnerabilityRecord],
    retained: Seq[SlugOccurrenceRecord],
    existingWorkflows: Seq[ServiceOccurrenceRecord]
  )

  private def publishOperations(
    input: PublishScan, attempt: ScanAttemptRecord, digest: String, publishedAt: Instant,
    occurrenceIds: Map[String, String]
  ): Future[ScanPublicationReceipt] =
    val context = input.findings.context
    for
      state <- loadPublicationState(input, attempt)
      plan = prepare(input, state.global, state.previous, state.retained, state.existingWorkflows, publishedAt, occurrenceIds)
      _ <- writeDetails(input, attempt, plan, publishedAt)
      _ <- writeWorkflows(input, attempt, plan, publishedAt)
      _ <- writeEvidence(context, plan)
      receipt <- persistPublication(input, attempt, digest, publishedAt, plan)
    yield receipt

  private def loadPublicationState(
    input: PublishScan,
    attempt: ScanAttemptRecord
  ): Future[PublicationState] =
    val context = input.findings.context
    for
      scan <- scans.findDeployment(context.serviceName.asString, context.appVersion.original)
      _ = if scan.flatMap(_.generation).exists(_ > attempt.generation) then
        reject(Superseded(input.runId, scan.flatMap(_.generation).get))
      previous <- evidence.findDeployment(context.serviceName.asString, context.appVersion.original, maximum)
      _ = bound(previous.size, maximum, "Existing deployment exceeds the finding limit")
      ids = (previous.map(_.vuln_id) ++ input.findings.findings.map(_.vulnerabilityId)).distinct.sorted
      global <- if ids.isEmpty then Future.successful(Seq.empty[VulnerabilityRecord])
        else details.findByIds(ids, maximum * 2)
      retained <- if ids.isEmpty then Future.successful(Seq.empty[SlugOccurrenceRecord])
        else evidence.collection.find(Filters.in("vuln_id", ids*)).limit(maximumObservations + 1).toFuture()
      _ = bound(retained.size, maximumObservations, "Global compatibility evidence exceeds the observation limit")
      existingWorkflows <- if ids.isEmpty then Future.successful(Seq.empty[ServiceOccurrenceRecord])
        else workflows.findByIds(context.serviceName.asString, ids, maximum * 2)
    yield PublicationState(previous, global, retained, existingWorkflows)

  private def persistPublication(
    input: PublishScan,
    attempt: ScanAttemptRecord,
    digest: String,
    publishedAt: Instant,
    plan: Plan
  ): Future[ScanPublicationReceipt] =
    val context = input.findings.context
    val scanRecord = ScanRecord(context.serviceName.asString, context.appVersion.original, publishedAt,
      "succeeded", Some(publishedAt), Some(input.runId), Some(attempt.generation), input.findings.generatedDate)
    val scanFields = ScanRecord.mongoFormat.writes(scanRecord)
    val receipt = ScanPublicationReceipt(input.runId, attempt.generation, publishedAt, plan.changes)
    for
      _ <- scans.collection.updateOne(deployment(context, "service_name"),
        set(scanFields + ("source_report_generated" -> scanFields.value.getOrElse("source_report_generated", JsNull))),
        UpdateOptions().upsert(true)).toFuture()
      _ <- attempts.collection.updateOne(Filters.equal("run_id", input.runId),
        set(Json.obj("digest" -> digest, "fingerprint_version" -> ScanPublicationFingerprint.currentVersion,
          "receipt" -> ScanAttemptRecord.receiptFormat.writes(receipt))))
        .toFuture()
    yield receipt

  private def prepare(
    input: PublishScan,
    global: Seq[VulnerabilityRecord],
    previous: Seq[SlugOccurrenceRecord],
    retained: Seq[SlugOccurrenceRecord],
    existingWorkflows: Seq[ServiceOccurrenceRecord],
    publishedAt: Instant,
    occurrenceIds: Map[String, String]
  ): Plan =
    val context = input.findings.context
    val before = global.map(v => v.vuln_id -> v).toMap
    val oldEvidence = previous.map(e => e.vuln_id -> e).toMap
    validateExistingData(global, retained, before)
    val otherEvidence = retained.filterNot(e => e.service == context.serviceName.asString && e.service_version == context.appVersion.original)
    val after = buildUpdatedDetails(input, before, otherEvidence)
    val newEvidence = buildEvidence(input, context, oldEvidence)
    val newWorkflows = initialiseMissingWorkflows(input, context, existingWorkflows, publishedAt, occurrenceIds)
    val changes = calculateEvidenceChanges(oldEvidence, newEvidence.toMap)
    val reopenedWorkflows = planWorkflowReopenings(input, before, existingWorkflows)
    Plan(before, after, newEvidence.toMap, newWorkflows, reopenedWorkflows, changes)

  private def validateExistingData(
    global: Seq[VulnerabilityRecord],
    retained: Seq[SlugOccurrenceRecord],
    existing: Map[String, VulnerabilityRecord]
  ): Unit =
    global.foreach(v => if v.scanner_revision.isEmpty then reject(AdoptionRequired(v.vuln_id)))
    retained.foreach: evidence =>
      if evidence.scanner_observation.isEmpty || !existing.contains(evidence.vuln_id) then
        reject(AdoptionRequired(evidence.vuln_id))

  private def buildUpdatedDetails(
    input: PublishScan,
    existing: Map[String, VulnerabilityRecord],
    otherEvidence: Seq[SlugOccurrenceRecord]
  ): Map[String, VulnerabilityRecord] =
    input.findings.findings.map: finding =>
      val id = finding.vulnerabilityId
      val other = otherEvidence.filter(_.vuln_id == id)
      val fields = Seq(
        Option.when(other.exists(_.scanner_observation.exists(_.summary != finding.summary)))("summary")
      ).flatten
      if fields.nonEmpty then reject(ScannerConflict(id, fields, other.map(e =>
        ScanContext(ServiceName(e.service), Version(e.service_version))).distinct))
      val previous = existing.get(id)
      val references = (previous.flatMap(_.references).getOrElse(Seq.empty) ++ finding.references).distinct
      val fixes = finding.fixedVersions
      id -> VulnerabilityRecord(id, finding.summary, finding.component.identity, fixes,
        finding.cvss.orElse(previous.flatMap(_.cvss_score)), previous.flatMap(_.epss), previous.flatMap(_.kev),
        Some(references), Some(previous.flatMap(_.scanner_revision).getOrElse(0L)))
    .toMap

  private def buildEvidence(
    input: PublishScan,
    context: ScanContext,
    oldEvidence: Map[String, SlugOccurrenceRecord]
  ): Seq[(String, SlugOccurrenceRecord)] =
    input.findings.findings.groupBy(_.vulnerabilityId).toSeq.sortBy(_._1).map: (id, findings) =>
      val componentObservations = findings.map: finding =>
        val importedBy = importedByFor(input, finding, findings.size, oldEvidence.get(id))
        ComponentObservation(
          finding.component.identity,
          finding.component.installedVersion,
          finding.component.packageType,
          finding.fixedVersions,
          importedBy,
          observation(input, finding)
        )
      val first = componentObservations.head
      id -> SlugOccurrenceRecord(id, context.serviceName.asString, context.appVersion.original,
        first.imported_by, Some(first.component_version), Some(first.scanner_observation), componentObservations)

  private def importedByFor(
    input: PublishScan,
    finding: ScannerFinding,
    observationCount: Int,
    previous: Option[SlugOccurrenceRecord]
  ): Seq[ImportedBy] =
    input.importedBy.get(finding.observationKey)
      .map(_.map(d => ImportedBy(d.group, d.artefact, d.version)))
      .orElse:
        Option.when(observationCount == 1):
          input.importedBy.get(finding.vulnerabilityId)
            .map(_.map(d => ImportedBy(d.group, d.artefact, d.version)))
            .orElse(previous.map(_.imported_by))
            .getOrElse(reject(MissingImportedBy(finding.vulnerabilityId)))
      .orElse:
        previous.flatMap(_.observations.find(_.component == finding.component.identity)
          .filter(_.component_version == finding.component.installedVersion).map(_.imported_by))
      .getOrElse(reject(MissingImportedBy(finding.vulnerabilityId)))

  private def initialiseMissingWorkflows(
    input: PublishScan,
    context: ScanContext,
    existingWorkflows: Seq[ServiceOccurrenceRecord],
    publishedAt: Instant,
    occurrenceIds: Map[String, String]
  ): Seq[ServiceOccurrenceRecord] =
    input.findings.findings
      .groupBy(_.vulnerabilityId)
      .toSeq
      .sortBy(_._1)
      .map(_._2.head)
      .filterNot(f => existingWorkflows.exists(_.vuln_id == f.vulnerabilityId))
      .map: finding =>
        if input.workflowInitialisation != WorkflowInitialisation.UsePolicy then reject(InitialisationRequired(finding.vulnerabilityId))
        val values = policy.initialValues(InitialWorkflowContext(context, finding, publishedAt)).fold(reject, identity)
        ServiceOccurrenceRecord(finding.vulnerabilityId, context.serviceName.asString,
          occurrenceIds(finding.vulnerabilityId), publishedAt, values.priority, values.state, values.sla,
          synthetic_initialisation = Some(values.synthetic))

  private def calculateEvidenceChanges(
    oldEvidence: Map[String, SlugOccurrenceRecord],
    newEvidence: Map[String, SlugOccurrenceRecord]
  ): EvidenceChanges =
    val added = newEvidence.keySet -- oldEvidence.keySet
    val removed = oldEvidence.keySet -- newEvidence.keySet
    val changed = (newEvidence.keySet intersect oldEvidence.keySet).filter: id =>
      val old = oldEvidence(id)
      val current = newEvidence(id)
      def withoutRunId(value: SlugOccurrenceRecord): SlugOccurrenceRecord =
        value.copy(
          scanner_observation = value.scanner_observation.map(_.copy(run_id = "")),
          observations = value.observations.map(o =>
            o.copy(scanner_observation = o.scanner_observation.copy(run_id = "")))
        )
      withoutRunId(old) != withoutRunId(current)
    EvidenceChanges(added.toSeq.sorted, changed.toSeq.sorted, removed.toSeq.sorted)

  private def planWorkflowReopenings(
    input: PublishScan,
    previousDetails: Map[String, VulnerabilityRecord],
    existingWorkflows: Seq[ServiceOccurrenceRecord]
  ): Seq[WorkflowReopening] =
    val workflowsById = existingWorkflows.map(workflow => workflow.vuln_id -> workflow).toMap
    input.findings.findings.flatMap: finding =>
      workflowsById.get(finding.vulnerabilityId).flatMap: workflow =>
        val previousCvss = previousDetails.get(finding.vulnerabilityId).flatMap(_.cvss_score)
        val incomingCvss = finding.cvss
        Option.when(
          workflow.state != OccurrenceState.actionable &&
            (for
              previous <- previousCvss
              incoming <- incomingCvss
            yield incoming > previous).getOrElse(false)
        )(WorkflowReopening(workflow, OccurrenceState.actionable, previousCvss.get, incomingCvss.get))

  private def scannerFields(v: VulnerabilityRecord): JsObject =
    Json.obj("vuln_id" -> v.vuln_id, "summary" -> v.summary, "vuln_component" -> v.vuln_component,
      "fixed_version" -> v.fixed_version, "references" -> v.references.getOrElse(Seq.empty)) ++
      v.cvss_score.fold(Json.obj())(score => Json.obj("cvss_score" -> score))

  private def set(fields: JsObject): BsonDocument =
    BsonDocument(Json.stringify(Json.obj("$set" -> fields)))

  private def serial[A](items: Iterable[A])(operation: A => Future[Unit]): Future[Unit] =
    items.foldLeft(Future.unit)((previous, item) => previous.flatMap(_ => operation(item)))

  private def writeDetails(
    input: PublishScan, attempt: ScanAttemptRecord, plan: Plan, now: Instant
  ): Future[Unit] =
    serial((plan.before.keySet ++ plan.after.keySet).toSeq.sorted): id =>
      val next = plan.after.get(id)
      val old = plan.before.get(id)
      val write = old match
        case None =>
          details.collection.insertOne(next.get.copy(scanner_revision = Some(1L))).toFuture().map(_ => ())
        case Some(_) =>
          val update = Json.obj("$inc" -> Json.obj("scanner_revision" -> 1L)) ++
            next.fold(Json.obj())(v => Json.obj("$set" -> scannerFields(v)))
          details.collection.updateOne(Filters.equal("vuln_id", id), BsonDocument(Json.stringify(update)))
            .toFuture().map(_ => ())
      write.flatMap: _ =>
        writeHistoryIfDetailsChanged(input, attempt, plan, id, old, next, now)

  private def writeHistoryIfDetailsChanged(
    input: PublishScan,
    attempt: ScanAttemptRecord,
    plan: Plan,
    id: String,
    old: Option[VulnerabilityRecord],
    next: Option[VulnerabilityRecord],
    now: Instant
  ): Future[Unit] =
    next match
      case Some(value) if old.isEmpty || old.exists(previous => scannerFields(previous) != scannerFields(value)) =>
        val eventType = if old.isEmpty then "vulnerability_created" else "details_updated"
        vulnerabilityHistory.collection.insertOne(history(input, attempt, id, None, eventType, now,
          Json.obj("before" -> old.map(scannerFields), "after" -> scannerFields(value)),
          plan.newWorkflows.exists(_.synthetic_initialisation.contains(true)))).toFuture().map(_ => ())
      case _ => Future.unit

  private def writeWorkflows(
    input: PublishScan, attempt: ScanAttemptRecord, plan: Plan, now: Instant
  ): Future[Unit] =
    for
      _ <- serial(plan.newWorkflows): workflow =>
        for
          _ <- workflows.collection.insertOne(workflow).toFuture()
          _ <- occurrenceHistory.collection.insertOne(history(input, attempt, workflow.vuln_id,
            Some(workflow.service), "occurrence_created", now,
            Json.obj("after" -> ServiceOccurrenceRecord.mongoFormat.writes(workflow),
              "synthetic" -> workflow.synthetic_initialisation.contains(true)),
            workflow.synthetic_initialisation.contains(true))).toFuture()
        yield ()
      _ <- serial(plan.reopenedWorkflows)(reopen =>
        workflows.collection.updateOne(
          Filters.and(Filters.equal("vuln_id", reopen.workflow.vuln_id),
            Filters.equal("service", reopen.workflow.service)),
          set(Json.obj("state" -> reopen.newState))).toFuture().flatMap: _ =>
            occurrenceHistory.collection.insertOne(history(input, attempt, reopen.workflow.vuln_id,
              Some(reopen.workflow.service), "occurrence_reopened", now,
              Json.obj("before" -> reopen.workflow.state, "after" -> reopen.newState,
                "previousCvss" -> reopen.previousCvss, "newCvss" -> reopen.newCvss,
                "reason" -> "CVSS severity increased"),
              syntheticInitialisation = false)).toFuture().map(_ => ())
      )
    yield ()

  private def writeEvidence(context: ScanContext, plan: Plan): Future[Unit] =
    for
      _ <- serial(plan.changes.removed): id =>
        evidence.collection.deleteOne(Filters.and(deployment(context), Filters.equal("vuln_id", id)))
          .toFuture().map(_ => ())
      _ <- serial(plan.newEvidence.values.toSeq.sortBy(_.vuln_id)): e =>
        evidence.collection.updateOne(Filters.and(deployment(context), Filters.equal("vuln_id", e.vuln_id)),
          set(SlugOccurrenceRecord.mongoFormat.writes(e)), UpdateOptions().upsert(true)).toFuture().map(_ => ())
    yield ()

  private def history(
    input: PublishScan, attempt: ScanAttemptRecord, id: String, service: Option[String],
    eventType: String, now: Instant, changes: JsObject, syntheticInitialisation: Boolean
  ): HistoryRecord =
    val identity = Json.stringify(Json.arr(input.runId, id, service, eventType))
    HistoryRecord(UUID.nameUUIDFromBytes(identity.getBytes(UTF_8)).toString, id, service, eventType,
      now, HistoryActor("system", "xray-v2-publication"), changes, "Validated V2 scan publication",
      Seq(Json.obj("run_id" -> input.runId, "generation" -> attempt.generation,
        "synthetic_initialisation" -> syntheticInitialisation)))
