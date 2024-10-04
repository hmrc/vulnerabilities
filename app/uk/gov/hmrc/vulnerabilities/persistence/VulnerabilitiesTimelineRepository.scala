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

import org.mongodb.scala.ObservableFuture
import org.mongodb.scala.bson.conversions.Bson
import org.mongodb.scala.model.Aggregates.{`match`, group}
import org.mongodb.scala.model.Indexes.{compoundIndex, descending}
import org.mongodb.scala.model._
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.{CollectionFactory, PlayMongoRepository}
import uk.gov.hmrc.vulnerabilities.model.{CurationStatus, ServiceName, TimelineEvent, VulnerabilitiesTimelineCount}

import java.time.Instant
import java.util.concurrent.TimeUnit
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class VulnerabilitiesTimelineRepository @Inject()(
  mongoComponent: MongoComponent,
)(using
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
                     IndexModel(Indexes.ascending("curationStatus"),IndexOptions().name("curationStatus").background(true))
                   )
):
  def replaceOrInsert(serviceVulnerabilities: Seq[TimelineEvent]): Future[Unit] =
    collection.bulkWrite(
      serviceVulnerabilities.map: sv =>
        ReplaceOneModel(
          Filters.and(
            Filters.equal("id", sv.id),
            Filters.equal("service", sv.service),
            Filters.equal("weekBeginning", sv.weekBeginning)
          ),
          sv,
          ReplaceOptions().upsert(true)
        )
    ).toFuture().map(_ => ())

  private val Quoted = """^\"(.*)\"$""".r

  def getTimelineCounts(
    serviceName   : Option[ServiceName]    = None
  , team          : Option[String]         = None
  , vulnerability : Option[String]         = None
  , curationStatus: Option[CurationStatus] = None
  , from          : Instant
  , to            : Instant
  ): Future[Seq[VulnerabilitiesTimelineCount]] =
    val optFilters: Seq[Bson] = Seq(
      serviceName.map {
        case ServiceName(Quoted(s)) => Filters.equal("service", s.toLowerCase())
        case ServiceName(s)         => Filters.regex("service", s.toLowerCase())
      },
      team.map         (t => Filters.eq("teams", t)),
      vulnerability.map(v => Filters.eq("id", v.toUpperCase)),
      curationStatus.map(cs => Filters.eq("curationStatus", cs.asString))
    ).flatten

    val pipeline: Seq[Bson] = Seq(
      Some(`match`(Filters.and(Filters.gte("weekBeginning", from), Filters.lte("weekBeginning",to)))),
      if optFilters.isEmpty then None else Some(`match`(Filters.and(optFilters: _*))),
      Some(group(id = "$weekBeginning", Accumulators.sum("count", 1)))
    ).flatten

    CollectionFactory.collection(mongoComponent.database, "vulnerabilitiesTimeline", VulnerabilitiesTimelineCount.mongoFormat)
      .aggregate(pipeline).toFuture()
