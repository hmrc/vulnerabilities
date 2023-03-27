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

import com.mongodb.client.model.Indexes
import org.mongodb.scala.MongoCollection
import org.mongodb.scala.bson.{BsonArray, BsonDocument, BsonNull}
import org.mongodb.scala.model.Aggregates.{`match`, group, lookup, project, replaceRoot, set, unwind}
import org.mongodb.scala.model.Projections.{computed, excludeId, fields}
import org.mongodb.scala.model.{Accumulators, Field, Filters, IndexModel, IndexOptions}
import play.api.{Configuration, Logger}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.{CollectionFactory, PlayMongoRepository}
import uk.gov.hmrc.vulnerabilities.model.{Report, ServiceVulnerability, UnrefinedVulnerabilitySummary}

import java.time.temporal.ChronoUnit
import java.time.Instant
import java.util.concurrent.TimeUnit
import javax.inject.{Inject, Singleton}
import scala.concurrent.duration.FiniteDuration
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class RawReportsRepository @Inject()(
mongoComponent: MongoComponent,
configuration: Configuration
)(implicit ec: ExecutionContext
) extends PlayMongoRepository(
    collectionName = "rawReports",
    mongoComponent = mongoComponent,
    domainFormat   = Report.mongoFormat,
    indexes        = Seq(IndexModel(Indexes.descending("generatedDate"), IndexOptions().name("generatedDate").background(true).expireAfter(2 * 365, TimeUnit.DAYS))),
    replaceIndexes = true
)
    {
      private val dataCutOff = configuration.get[FiniteDuration]("data.refresh-cutoff").toMillis.toInt
      private val logger = Logger(this.getClass)


      def insertReport(report: Report, name: String): Future[Unit] = {
        collection
          .insertOne(report)
          .toFuture()
          .map(_ => logger.info(s"Inserted report for $name into rawReports repository"))
      }

      def getReportsInLastXDays(): Future[Seq[Report]] =
        collection.find(Filters.gt("generatedDate", recent())).toFuture()

      // use a different view to allow distinctVulnerabilitiesSummary to return a different case class
      private val vcsCollection: MongoCollection[UnrefinedVulnerabilitySummary] =
        CollectionFactory.collection(
          mongoComponent.database,
          "rawReports",
          UnrefinedVulnerabilitySummary.reads
        )

      def recent() = Instant.now().minus(dataCutOff, ChronoUnit.MILLIS)
      //Only transform data added to rawReports within last X Days
      //This stops out of date, and since fixed reports being transformed into vulnerability summaries

      def getNewDistinctVulnerabilities(): Future[Seq[UnrefinedVulnerabilitySummary]] =
        vcsCollection.aggregate(
          Seq(
            `match`(Filters.gt("generatedDate", recent())),
            unwind("$rows"),
            unwind("$rows.cves"),
            project(
              BsonDocument(
                "id"            -> BsonDocument("$ifNull" -> BsonArray("$rows.cves.cve", "$rows.issue_id")),
                "vuln"          -> "$rows",
                "generatedDate" -> "$generatedDate",
                "score"         -> BsonDocument("$ifNull" -> BsonArray("$rows.cvss3_max_score", 0.0))
              )
            ),
            group(
              "$id",
              Accumulators.addToSet("vulns", "$vuln"),
              Accumulators.first("generatedDate", "$generatedDate"),
              Accumulators.first("score", "$score")
            ),
            project(
              BsonDocument(
                "distinctVulnerability" -> BsonDocument("$arrayElemAt" -> BsonArray("$vulns", 0)),
                "generatedDate" -> "$generatedDate",
                "occurrences" -> BsonDocument("$map" -> BsonDocument(
                  "input" -> "$vulns",
                  "as"    -> "v",
                  "in"    -> BsonDocument(
                    "vulnComponent" -> "$$v.vulnerable_component",
                    "path"          -> "$$v.path",
                    "componentPhysicalPath" -> "$$v.component_physical_path"
                  )
                )),
                "score" ->
                  BsonDocument("$cond" -> BsonDocument(
                  "if" -> BsonDocument("$eq" -> BsonArray("$score", 0.0)),
                  "then" -> BsonNull.apply(),
                  "else" -> "$score"
                )),
              )
            )
          )
        )
          .allowDiskUse(true)
          .toFuture()

      /*
      BELOW is the raw Mongo query that the getTimelineData() method performs.
      Adding it as a comment for ease of testing changes to the query in the future.

      db.getCollection('rawReports').aggregate(
[
    {
        $match : {"generatedDate": { $gte: ISODate("2022-12-15T00:00:00.000Z")}}
    },
    {
        $unwind: "$rows"
    },
    { $project:
        {
            id: {
                $let: {
                        vars: {cveArray: { $arrayElemAt: ["$rows.cves", 0] } },
                        in: { $ifNull: ["$$cveArray.cve", "$rows.issue_id"] }
                    }
            },
            service: {
                    $arrayElemAt: [ { $split: ["$rows.path", "/"] }, 2 ]
            },
            weekBeginning: { $dateFromParts : {
                    isoWeekYear: { $isoWeekYear: "$generatedDate"},
                    isoWeek: { $isoWeek: "$generatedDate"}
                }
            }
        }
    },
    {
        $group: {
            _id: {
                id: "$id",
                service: "$service",
                weekBeginning: "$weekBeginning"
            },
        }
    },
    { $replaceRoot: { newRoot: "$_id" } },
    { $lookup:
        {
            from: "assessments",
            localField: "id",
            foreignField: "id",
            as: "curationStatus"
        }
    },
    { $set:
        {
            teams: [],
            curationStatus: { $ifNull: [ { $arrayElemAt: ["$curationStatus.curationStatus", 0]}, "UNCURATED"] }
        }
    }
])
       */

      def getTimelineData(reportsAfter: Instant): Future[Seq[ServiceVulnerability]] = {
        //Ensure that any changes made to this query are reflected in the comment above.
        CollectionFactory.collection(mongoComponent.database, "rawReports", ServiceVulnerability.mongoFormat).aggregate(
          Seq(
            `match`(Filters.gte("generatedDate", reportsAfter)), //Only process recent reports
            unwind("$rows"),
            project(
              fields(
                //Not all Vulnerabilities have a CVE-id, so if doesn't exist, get the issueID as fallback.
                computed("id", BsonDocument(
                  "$let" -> BsonDocument(
                    "vars" -> BsonDocument("cveArray" -> BsonDocument( "$arrayElemAt" -> BsonArray("$rows.cves", 0))),
                    "in" -> BsonDocument("$ifNull" -> BsonArray("$$cveArray.cve", "$rows.issue_id"))
                  )
                )),
                computed("service", BsonDocument(
                  "$arrayElemAt" -> BsonArray(
                    BsonDocument("$split" -> BsonArray("$rows.path", "/")), 2
                  )
                )),
                computed("weekBeginning", BsonDocument(  //truncate generatedDate to beginning of week
                  "$dateFromParts" -> BsonDocument(
                    "isoWeekYear" -> BsonDocument("$isoWeekYear" -> "$generatedDate"),
                    "isoWeek"     -> BsonDocument("$isoWeek" -> "$generatedDate")
                   )
                )
              )
            )),
            //The purpose of the group stage is to completely de-dupe the data, using the three keys as combined unique identifiers.
            group(id = BsonDocument("id" -> "$id", "service" -> "$service", "weekBeginning" -> "$weekBeginning")),
            replaceRoot("$_id"),
            lookup(
              from         = "assessments",
              localField   = "id",
              foreignField = "id",
              as           = "curationStatus"
            ),
            set(
              Field("teams", BsonArray()),
              Field("curationStatus", BsonDocument(
              "$ifNull" -> BsonArray(
                BsonDocument("$arrayElemAt" -> BsonArray("$curationStatus.curationStatus", 0)),
                "UNCURATED"
              )
            ))),
          )).toFuture()
      }
    }
