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
import org.mongodb.scala.model.{IndexModel, IndexOptions, Indexes}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.PlayMongoRepository
import scala.concurrent.ExecutionContext

@Singleton
class ScanAttemptRepository @Inject()(mongo: MongoComponent)(using ExecutionContext)
  extends PlayMongoRepository[ScanAttemptRecord](
    collectionName = "scan_attempts_v2",
    mongoComponent = mongo,
    domainFormat = ScanAttemptRecord.mongoFormat,
    indexes = Seq(
      IndexModel(Indexes.ascending("run_id"), IndexOptions().unique(true)),
      IndexModel(
        Indexes.ascending("service_name", "service_version", "generation"),
        IndexOptions().unique(true)
      )
    ),
    replaceIndexes = false
  ):
  override lazy val requiresTtlIndex = false
