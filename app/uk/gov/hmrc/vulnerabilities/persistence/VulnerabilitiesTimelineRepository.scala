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


import org.mongodb.scala.model.{Accumulators, Filters, IndexModel, IndexOptions, Indexes, ReplaceOneModel, ReplaceOptions}
import org.mongodb.scala.model.Indexes.{ascending, compoundIndex, descending}
import org.mongodb.scala.bson.conversions.Bson
import org.mongodb.scala.bson.{BsonArray, BsonDocument}
import org.mongodb.scala.model.Aggregates.{`match`, group}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.{CollectionFactory, PlayMongoRepository}
import uk.gov.hmrc.vulnerabilities.model.{TimelineEvent, VulnerabilitiesTimelineCount}

import java.time.Instant
import java.util.concurrent.TimeUnit
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class VulnerabilitiesTimelineRepository @Inject()(
  mongoComponent: MongoComponent,
)(implicit
  ec            : ExecutionContext
) extends PlayMongoRepository(
  collectionName = "vulnerabilitiesTimeline",
  mongoComponent = mongoComponent,
  domainFormat   = TimelineEvent.mongoFormat,
  indexes        = Seq(
    IndexModel(compoundIndex(descending("weekBeginning"), descending("service"), descending("id")),IndexOptions().unique(true).background(true)),
    IndexModel(Indexes.ascending("weekBeginning"),IndexOptions().expireAfter(2 * 365, TimeUnit.DAYS).background(true)),
    IndexModel(Indexes.ascending("id"),IndexOptions().name("id").background(true)),
    IndexModel(Indexes.ascending("service"),IndexOptions().name("service").background(true)),
    IndexModel(Indexes.ascending("teams"),IndexOptions().name("teams").background(true)),
  )
)
{
  def replaceOrInsert(serviceVulnerabilities: Seq[TimelineEvent]): Future[Unit] = {
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

  def getTimelineCountsForService(service: Option[String], team: Option[String], vulnerability: Option[String], from: Instant, to: Instant): Future[Seq[VulnerabilitiesTimelineCount]] = {

    val optFilters: Seq[Bson] = Seq(
      service.map      (s => Filters.eq("service", s.toLowerCase)),
      team.map         (t => Filters.eq("teams", t)),
      vulnerability.map(v => Filters.eq("id", v.toUpperCase))
    ).flatten

    val pipeline: Seq[Bson] = Seq(
      Some(`match`(Filters.and(Filters.gte("weekBeginning", from), Filters.lte("weekBeginning",to)))),
      if(optFilters.isEmpty) None else Some(`match`(Filters.and(optFilters: _*))),
      Some(group(
        id = "$weekBeginning",
        Accumulators.first("service", "$service"),
        Accumulators.sum("actionRequired",
          BsonDocument("$cond" -> BsonDocument("if" -> BsonDocument("$eq" -> BsonArray("$curationStatus", "ACTION_REQUIRED")), "then" -> 1, "else" -> 0))
        ),
        Accumulators.sum("noActionRequired",
          BsonDocument("$cond" -> BsonDocument("if" -> BsonDocument("$eq" -> BsonArray("$curationStatus", "NO_ACTION_REQUIRED")), "then" -> 1, "else" -> 0))
        ),
        Accumulators.sum("investigationOngoing",
          BsonDocument("$cond" -> BsonDocument("if" -> BsonDocument("$eq" -> BsonArray("$curationStatus", "INVESTIGATION_ONGOING")), "then" -> 1, "else" -> 0))
        ),
        Accumulators.sum("uncurated",
          BsonDocument("$cond" -> BsonDocument("if" -> BsonDocument("$eq" -> BsonArray("$curationStatus", "UNCURATED")), "then" -> 1, "else" -> 0))
        ),
        Accumulators.sum("total", 1)
      ))
    ).flatten

    CollectionFactory.collection(mongoComponent.database, "vulnerabilitiesTimeline", VulnerabilitiesTimelineCount.mongoFormat)
      .aggregate(pipeline).toFuture()
  }


}
