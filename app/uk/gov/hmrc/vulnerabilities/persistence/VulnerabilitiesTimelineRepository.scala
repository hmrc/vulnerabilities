/*
 * Copyright 2023 HM Revenue & Customs
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

import com.mongodb.bulk.{BulkWriteInsert, BulkWriteUpsert}
import com.mongodb.client.model.{Indexes, InsertOneModel}
import org.mongodb.scala.model.{Filters, IndexModel, IndexOptions, InsertOneModel, InsertOneOptions, ReplaceOneModel, ReplaceOptions, UpdateOneModel, UpdateOptions, Updates}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.PlayMongoRepository
import uk.gov.hmrc.vulnerabilities.model.ServiceVulnerability

import java.util
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class VulnerabilitiesTimelineRepository @Inject()(
                                      mongoComponent: MongoComponent,
                                    )(implicit ec: ExecutionContext
                                    ) extends PlayMongoRepository(
  collectionName = "vulnerabilitiesTimeline",
  mongoComponent = mongoComponent,
  domainFormat   = ServiceVulnerability.mongoFormat,
  indexes        = Seq(
    IndexModel(Indexes.descending("weekBeginning", "service", "id"), IndexOptions().unique(true))
  )
)
{
  def replaceOrInsert(serviceVulnerabilities: Seq[ServiceVulnerability]): Future[Unit] = {
    val bulkWrites = serviceVulnerabilities.map(sv =>
      ReplaceOneModel(
        Filters.and(
          Filters.equal("id", sv.id),
          Filters.equal("service", sv.service),
          Filters.equal("weekBeginning", sv.weekBeginning)
        ),
        sv,
        ReplaceOptions().upsert(true)
      )
    )
    collection.bulkWrite(bulkWrites).toFuture().map(_ => ())
  }
}
