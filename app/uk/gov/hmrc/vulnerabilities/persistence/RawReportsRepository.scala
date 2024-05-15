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

import play.api.Configuration
import com.mongodb.client.model.Indexes
import org.mongodb.scala.bson.{BsonArray, BsonDocument, BsonDateTime}
import org.mongodb.scala.ClientSession
import org.mongodb.scala.model.{Aggregates, Field, Filters, IndexModel, IndexOptions, ReplaceOptions, Projections, Updates, UpdateOptions}
import uk.gov.hmrc.mongo.transaction.{TransactionConfiguration, Transactions}

import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.{CollectionFactory, PlayMongoRepository}
import uk.gov.hmrc.vulnerabilities.model.{Report, ServiceName, SlugInfoFlag, TimelineEvent, Version}

import java.time.Instant
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class RawReportsRepository @Inject()(
  final val mongoComponent: MongoComponent
, config                  : Configuration
)(implicit
  ec            : ExecutionContext
) extends PlayMongoRepository(
  collectionName = "rawReports"
, mongoComponent = mongoComponent
, domainFormat   = Report.mongoFormat
, indexes        = IndexModel(Indexes.ascending("serviceName", "serviceVersion"), IndexOptions().unique(true)) ::
                   SlugInfoFlag.values.map(f => IndexModel(Indexes.hashed(f.asString)))
, replaceIndexes = true
) with Transactions {

  // No ttl required for this collection - managed by SQS
  override lazy val requiresTtlIndex = false

  private implicit val tc: TransactionConfiguration =
    TransactionConfiguration.strict

  private val exclusionRegex: String = config.get[String]("regex.exclusion")

  private val deployedSlugsInfoFlags: List[SlugInfoFlag] =
    SlugInfoFlag.values.filterNot(f => f == SlugInfoFlag.Latest || f == SlugInfoFlag.Integration || f == SlugInfoFlag.Development)

  val Quoted = """^\"(.*)\"$""".r
  private def toServiceNameFilter(serviceNames: Seq[ServiceName]) =
    serviceNames match {
      case Seq(ServiceName(Quoted(s))) => Filters.equal("serviceName", s.toLowerCase())
      case Seq(ServiceName(s))         => Filters.regex("serviceName", s.toLowerCase())
      case xs                          => Filters.in(   "serviceName", xs.map(_.asString): _*)
    }

  // Like find but service name defaults to an exact match - otherwise we'd have to add quotes
  def exists(
    serviceName: ServiceName
  , version    : Version
  ): Future[Boolean] =
    collection
      .find(Filters.and(
        Filters.equal("serviceName"   , serviceName.asString)
      , Filters.equal("serviceVersion", version.original)
      ))
      .headOption()
      .map(_.isDefined)

  def find(
    flag        : Option[SlugInfoFlag]
  , serviceNames: Option[Seq[ServiceName]]
  , version     : Option[Version]
  ): Future[Seq[Report]] =
    collection
      .find(Filters.and(
        serviceNames.fold(Filters.empty())(toServiceNameFilter)
      , version.fold(Filters.empty())(v => Filters.equal("serviceVersion", v.original))
      , flag.fold(Filters.empty())(f => Filters.equal(f.asString, true))
      ))
      .toFuture()
      .map(_.map(report => report.copy(rows = report.rows.filter(row => exclusionRegex.r.matches(row.componentPhysicalPath)))))

  def findDeployed(serviceName: ServiceName): Future[Seq[Report]] =
    collection
      .find(Filters.and(
        Filters.equal("serviceName", serviceName.asString)
      , Filters.or(deployedSlugsInfoFlags.map(f => Filters.equal(f.asString, true)): _*)
      ))
      .toFuture()
      .map(_.map(report => report.copy(rows = report.rows.filter(row => exclusionRegex.r.matches(row.componentPhysicalPath)))))

  def getMaxVersion(serviceName: ServiceName): Future[Option[Version]] =
    collection
      .find[Version](Filters.equal("serviceName", serviceName.asString))
      .projection(Projections.include("version"))
      .foldLeft(Option.empty[Version]){
        case (optMax, version) if optMax.exists(_ > version) => optMax
        case (_     , version)                               => Some(version)
      }.toFuture()

  def put(report: Report): Future[Unit] =
    collection
      .replaceOne(
        filter      = Filters.and(
                        Filters.equal("serviceName"   , report.serviceName.asString)
                      , Filters.equal("serviceVersion", report.serviceVersion.original)
                      )
      , replacement = report
      , options     = ReplaceOptions().upsert(true)
      )
      .toFuture()
      .map(_ => ())

  def delete(serviceName: ServiceName, version: Version): Future[Unit] =
    collection
      .deleteOne(Filters.and(
        Filters.equal("serviceName"   , serviceName.asString),
        Filters.equal("serviceVersion", version.original)
      ))
      .toFuture()
      .map(_ => ())

  def setFlag(flag: SlugInfoFlag, serviceName: ServiceName, version: Version): Future[Unit] =
    withSessionAndTransaction { session =>
      for {
        _ <- clearFlag(flag, serviceName, session)
        _ <- collection
               .updateOne(
                 clientSession = session,
                 filter        = Filters.and(
                                   Filters.equal("serviceName"   , serviceName.asString),
                                   Filters.equal("serviceVersion", version.original),
                                 ),
                 update        = Updates.set(flag.asString, true),
                 options       = UpdateOptions().upsert(true)
               )
               .toFuture()
      } yield ()
    }

  def clearFlag(flag: SlugInfoFlag, serviceName: ServiceName): Future[Unit] =
    withSessionAndTransaction { session =>
      clearFlag(flag, serviceName, session)
    }

  private def clearFlag(flag: SlugInfoFlag, serviceName: ServiceName, session: ClientSession): Future[Unit] =
    collection
      .updateMany(
          clientSession = session,
          filter        = Filters.and(
                            Filters.equal("serviceName", serviceName.asString),
                            Filters.equal(flag.asString, true)
                          ),
          update        = Updates.set(flag.asString, false)
        )
      .toFuture()
      .map(_ => ())

  def findStale(reportsBefore: Instant): Future[Seq[Report]] =
    collection
      .find(Filters.and(
        Filters.or((deployedSlugsInfoFlags :+ SlugInfoFlag.Latest).map(f => Filters.equal(f.asString, true)): _*)
      , Filters.lt("generatedDate", reportsBefore)
      ))
      .toFuture()

  def getTimelineData(weekBeginning: Instant): Future[Seq[TimelineEvent]] = {
    //Ensure that any changes made to this query are reflected in the comment above.
    CollectionFactory
      .collection(mongoComponent.database, "rawReports", TimelineEvent.mongoFormat)
      .aggregate(
        Seq(
          Aggregates.`match`(Filters.or(deployedSlugsInfoFlags.map(f => Filters.equal(f.asString, true)): _*)),
          Aggregates.unwind("$rows"),
          Aggregates.`match`(Filters.regex("rows.component_physical_path", exclusionRegex)),
          Aggregates.project(
            Projections.fields(
              //Not all Vulnerabilities have a CVE-id, so if doesn't exist, get the issueID as fallback.
              Projections.computed("id", BsonDocument(
                "$let" -> BsonDocument(
                  "vars" -> BsonDocument("cveArray" -> BsonDocument( "$arrayElemAt" -> BsonArray("$rows.cves", 0))),
                  "in"   -> BsonDocument("$ifNull" -> BsonArray("$$cveArray.cve", "$rows.issue_id"))
                )
              )),
              Projections.computed("service", BsonDocument("$arrayElemAt" -> BsonArray(BsonDocument("$split" -> BsonArray("$rows.path", "/")), 2)))
            )
          ),
          //The purpose of the group stage is to completely de-dupe the data, using the three keys as combined unique identifiers.
          Aggregates.group(id = BsonDocument("id" -> "$id", "service" -> "$service")),
          Aggregates.replaceRoot("$_id"),
          Aggregates.lookup(
            from         = "assessments",
            localField   = "id",
            foreignField = "id",
            as           = "curationStatus"
          ),
          Aggregates.set(
            Field("weekBeginning" , BsonDateTime(weekBeginning.toEpochMilli())),
            Field("teams"         , BsonArray()),
            Field("curationStatus", BsonDocument("$ifNull" -> BsonArray(BsonDocument("$arrayElemAt" -> BsonArray("$curationStatus.curationStatus", 0)), "UNCURATED")))
          ),
        )
      ).toFuture()
  }
}
