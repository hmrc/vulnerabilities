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

import javax.inject.{Inject, Singleton}
import org.mongodb.scala.model.{IndexModel, IndexOptions, Indexes}
import org.mongodb.scala.model.Filters
import play.api.libs.json.Format
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.PlayMongoRepository
import scala.concurrent.ExecutionContext
import scala.concurrent.Future

abstract class RepositoryV2[A: scala.reflect.ClassTag](
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
class VulnerabilityRepositoryV2 @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends RepositoryV2("vulnerabilities_v2", mongo, VulnerabilityRecordV2.mongoFormat, Seq("vuln_id")):
  def findByIds(ids: Seq[String], maximum: Int): Future[Seq[VulnerabilityRecordV2]] =
    collection.find(Filters.in("vuln_id", ids*)).limit(maximum + 1).toFuture()

@Singleton
class VulnerabilityOccurrenceRepositoryV2 @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends RepositoryV2("vulnerability_occurrences_v2", mongo, SlugOccurrenceRecordV2.mongoFormat,
    Seq("vuln_id", "service", "service_version"), Seq(IndexModel(Indexes.ascending("service", "service_version")))):
  def findDeployment(service: String, version: String, maximum: Int): Future[Seq[SlugOccurrenceRecordV2]] =
    collection.find(Filters.and(Filters.equal("service", service), Filters.equal("service_version", version)))
      .sort(org.mongodb.scala.model.Sorts.ascending("vuln_id")).limit(maximum + 1).toFuture()

@Singleton
class ServiceOccurrenceRepositoryV2 @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends RepositoryV2("service_occurrences_v2", mongo, ServiceOccurrenceRecordV2.mongoFormat,
    Seq("vuln_id", "service"), Seq(IndexModel(Indexes.ascending("occurrence_id"), IndexOptions().unique(true)))):
  def findByIds(service: String, ids: Seq[String], maximum: Int): Future[Seq[ServiceOccurrenceRecordV2]] =
    collection.find(Filters.and(Filters.equal("service", service), Filters.in("vuln_id", ids*)))
      .limit(maximum + 1).toFuture()

@Singleton
class ScanRecordRepositoryV2 @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends RepositoryV2("scan_records_v2", mongo, ScanRecordV2.mongoFormat,
    Seq("service_name", "service_version"), Seq(IndexModel(Indexes.ascending("scan_date")))):
  def findDeployment(service: String, version: String): Future[Option[ScanRecordV2]] =
    collection.find(Filters.and(Filters.equal("service_name", service), Filters.equal("service_version", version))).headOption()

@Singleton
class VulnerabilityHistoryRepositoryV2 @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends RepositoryV2("vulnerability_history_v2", mongo, HistoryRecordV2.mongoFormat, Seq("event_id"),
    Seq(IndexModel(Indexes.ascending("vuln_id", "occurred_at"))))

@Singleton
class OccurrenceHistoryRepositoryV2 @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends RepositoryV2("occurrence_history_v2", mongo, HistoryRecordV2.mongoFormat, Seq("event_id"),
    Seq(IndexModel(Indexes.ascending("vuln_id", "service", "occurred_at"))))
