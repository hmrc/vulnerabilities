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

import org.mongodb.scala.bson.conversions.Bson
import org.mongodb.scala.model._
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.{CollectionFactory, PlayMongoRepository}
import uk.gov.hmrc.vulnerabilities.model.{CurationStatus, ServiceName, TeamName, TimelineEvent, VulnerabilitiesTimelineCount}

import java.time.Instant
import java.util.concurrent.TimeUnit
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class VulnerabilitiesTimelineRepository @Inject()(
  mongoComponent: MongoComponent,
)(using
  ExecutionContext
) extends PlayMongoRepository[TimelineEvent](
  collectionName = "vulnerabilitiesTimeline",
  mongoComponent = mongoComponent,
  domainFormat   = TimelineEvent.mongoFormat,
  indexes        = Seq(
                     IndexModel(Indexes.descending("weekBeginning", "service", "id"), IndexOptions().unique(true)),
                     IndexModel(Indexes.ascending("weekBeginning") , IndexOptions().expireAfter(2 * 365, TimeUnit.DAYS)),
                     IndexModel(Indexes.ascending("id")            , IndexOptions().name("id")),
                     IndexModel(Indexes.ascending("service")       , IndexOptions().name("service")),
                     IndexModel(Indexes.ascending("teams")         , IndexOptions().name("teams")),
                     IndexModel(Indexes.ascending("curationStatus"), IndexOptions().name("curationStatus"))
                   )
):
  def replaceOrInsert(serviceVulnerabilities: Seq[TimelineEvent]): Future[Unit] =
    collection.bulkWrite(
      serviceVulnerabilities.map: sv =>
        ReplaceOneModel(
          Filters.and(
            Filters.equal("id"           , sv.id),
            Filters.equal("service"      , sv.service),
            Filters.equal("weekBeginning", sv.weekBeginning)
          ),
          sv,
          ReplaceOptions().upsert(true)
        )
    ).toFuture().map(_ => ())

  private val Quoted = """^\"(.*)\"$""".r

  def getTimelineCounts(
    serviceName   : Option[ServiceName]    = None
  , team          : Option[TeamName]       = None
  , vulnerability : Option[String]         = None
  , curationStatus: Option[CurationStatus] = None
  , from          : Instant
  , to            : Instant
  ): Future[Seq[VulnerabilitiesTimelineCount]] =
    CollectionFactory.collection(mongoComponent.database, "vulnerabilitiesTimeline", VulnerabilitiesTimelineCount.mongoFormat)
      .aggregate:
        Seq(
          Aggregates.`match`:
            Filters.and(
              Filters.gte("weekBeginning", from)
            , Filters.lte("weekBeginning", to)
            , serviceName.fold(Filters.empty):
                case ServiceName(Quoted(s)) => Filters.equal("service", s.toLowerCase)
                case ServiceName(s)         => Filters.regex("service", s.toLowerCase)
            , team          .fold(Filters.empty)(t  => Filters.eq("teams"         , t.asString))
            , vulnerability .fold(Filters.empty)(v  => Filters.eq("id"            , v.toUpperCase))
            , curationStatus.fold(Filters.empty)(cs => Filters.eq("curationStatus", cs.asString))
            )
        , Aggregates.group(id = "$weekBeginning", Accumulators.sum("count", 1))
        )
      .toFuture()
