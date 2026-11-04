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

package uk.gov.hmrc.vulnerabilities.v2.persistence

import javax.inject.{Inject, Singleton}
import org.mongodb.scala.ClientSession
import org.mongodb.scala.model.{IndexModel, IndexOptions, Indexes}
import org.mongodb.scala.model.Filters
import play.api.libs.json.Format
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.PlayMongoRepository
import scala.concurrent.ExecutionContext
import scala.concurrent.Future

abstract class Repository[A: scala.reflect.ClassTag](
  name: String,
  mongo: MongoComponent,
  format: Format[A],
  keys: Seq[String],
  additional: Seq[IndexModel] = Seq.empty
)(using ExecutionContext) extends PlayMongoRepository[A](
  collectionName = name,
  mongoComponent = mongo,
  domainFormat = format,
  indexes = Seq(IndexModel(Indexes.ascending(keys*), IndexOptions().unique(true))) ++ additional,
  replaceIndexes = false
):
  override lazy val requiresTtlIndex = false

@Singleton
class VulnerabilityRepository @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends Repository("vulnerabilities_v2", mongo, VulnerabilityRecord.mongoFormat, Seq("vuln_id")):
  def findByIds(ids: Seq[String], maximum: Int, session: Option[ClientSession] = None): Future[Seq[VulnerabilityRecord]] =
    val filter = Filters.in("vuln_id", ids*)
    session.fold(collection.find(filter))(collection.find(_, filter)).limit(maximum + 1).toFuture()

@Singleton
class VulnerabilityOccurrenceRepository @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends Repository("vulnerability_occurrences_v2", mongo, SlugOccurrenceRecord.mongoFormat,
    Seq("vuln_id", "service", "service_version"), Seq(IndexModel(Indexes.ascending("service", "service_version")))):
  def findDeployment(service: String, version: String, maximum: Int, session: Option[ClientSession] = None): Future[Seq[SlugOccurrenceRecord]] =
    val filter = Filters.and(Filters.equal("service", service), Filters.equal("service_version", version))
    session.fold(collection.find(filter))(collection.find(_, filter))
      .sort(org.mongodb.scala.model.Sorts.ascending("vuln_id")).limit(maximum + 1).toFuture()

@Singleton
class ServiceOccurrenceRepository @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends Repository("service_occurrences_v2", mongo, ServiceOccurrenceRecord.mongoFormat,
    Seq("vuln_id", "service"), Seq(IndexModel(Indexes.ascending("occurrence_id"), IndexOptions().unique(true)))):
  def findByIds(service: String, ids: Seq[String], maximum: Int, session: Option[ClientSession] = None): Future[Seq[ServiceOccurrenceRecord]] =
    val filter = Filters.and(Filters.equal("service", service), Filters.in("vuln_id", ids*))
    session.fold(collection.find(filter))(collection.find(_, filter))
      .limit(maximum + 1).toFuture()

@Singleton
class ScanRecordRepository @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends Repository("scan_records_v2", mongo, ScanRecord.mongoFormat,
    Seq("service_name", "service_version"), Seq(IndexModel(Indexes.ascending("scan_date")))):
  def findDeployment(service: String, version: String, session: Option[ClientSession] = None): Future[Option[ScanRecord]] =
    val filter = Filters.and(Filters.equal("service_name", service), Filters.equal("service_version", version))
    session.fold(collection.find(filter))(collection.find(_, filter)).headOption()

@Singleton
class VulnerabilityHistoryRepository @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends Repository("vulnerability_history_v2", mongo, HistoryRecord.mongoFormat, Seq("event_id"),
    Seq(IndexModel(Indexes.ascending("vuln_id", "occurred_at"))))

@Singleton
class OccurrenceHistoryRepository @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends Repository("occurrence_history_v2", mongo, HistoryRecord.mongoFormat, Seq("event_id"),
    Seq(IndexModel(Indexes.ascending("vuln_id", "service", "occurred_at"))))

@Singleton
class ScanAttemptRepository @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends Repository("scan_attempts_v2", mongo, ScanAttemptRecord.mongoFormat, Seq("run_id"),
    Seq(IndexModel(Indexes.ascending("service_name", "service_version", "generation"), IndexOptions().unique(true))))
