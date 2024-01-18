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
import org.mongodb.scala.model.Projections.{computed, fields}
import org.mongodb.scala.model.{Accumulators, Field, Filters, IndexModel, IndexOptions, Sorts}
import play.api.Logger
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.{CollectionFactory, PlayMongoRepository}
import uk.gov.hmrc.vulnerabilities.config.{AppConfig, DataConfig}
import uk.gov.hmrc.vulnerabilities.model.{Report, TimelineEvent, UnrefinedVulnerabilitySummary}

import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.concurrent.TimeUnit
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class RawReportsRepository @Inject()(
  mongoComponent: MongoComponent,
  config        : DataConfig,
  appConfig: AppConfig
)(implicit
  ec            : ExecutionContext
) extends PlayMongoRepository(
  collectionName = "rawReports",
  mongoComponent = mongoComponent,
  domainFormat   = Report.mongoFormat,
  indexes        = Seq(
                    IndexModel(Indexes.ascending("serviceName"), IndexOptions().unique(false).background(true)),
                    IndexModel(Indexes.ascending("serviceVersion"), IndexOptions().unique(false).background(true)),
                    IndexModel(Indexes.descending("generatedDate"), IndexOptions().name("generatedDate").background(true).expireAfter(2 * 365, TimeUnit.DAYS))
                   )
){
  private val dataRefreshCutoff        = config.dataRefreshCutoff.toMillis.toInt
  private val dataTransformationCutoff = config.dataTransformationCutoff.toMillis.toInt
  private val logger = Logger(this.getClass)

  def insertReport(report: Report, name: String): Future[Unit] =
    collection
      .insertOne(report)
      .toFuture()
      .map(_ => logger.info(s"Inserted report for $name into rawReports repository"))

  def getReportsInLastXDays(): Future[Seq[Report]] =
    collection.find(
      Filters.gt("generatedDate", Instant.now().minus(dataRefreshCutoff, ChronoUnit.MILLIS)))
      .toFuture()

  def vulnerabilitiesCount(serviceName: String, version: Option[String] = None): Future[Option[Int]] =
    collection.find(
      Filters.and(
        Filters.eq("serviceName", serviceName),
        version.fold(Filters.empty())(v => Filters.eq("serviceVersion", v)),
      )
    )
    .sort(Sorts.orderBy(Sorts.descending("serviceVersion")))
    .limit(1)
    .headOption()
    .map(_.map(_.rows.size))

  // use a different view to allow distinctVulnerabilitiesSummary to return a different case class
  private val vcsCollection: MongoCollection[UnrefinedVulnerabilitySummary] =
    CollectionFactory.collection(
      mongoComponent.database,
      "rawReports",
      UnrefinedVulnerabilitySummary.reads
    )

  def recent() = Instant.now()
    .minus(dataTransformationCutoff, ChronoUnit.MILLIS)
  //Having a separate config value for dataTranformationCutOff to dataRefreshCutoff, where the former is always larger than the latter, addresses edge case that occurs following a scheduler run,
  //in which not all reports were redownloaded (as recent reports exist within the dataCutOff for those service/versions, perhaps due to a deployment event)
  //But those same reports could then be outside of the dataCutOff following a new deploymentEvent, meaning they wouldn't be picked up by below query until the next scheduler run, causing (temporary) missing data.

  def getNewDistinctVulnerabilities(): Future[Seq[UnrefinedVulnerabilitySummary]] =
    vcsCollection.aggregate(
      Seq(
        //Only transform data added to rawReports within last X Days
        //This stops out of date, and since fixed reports being transformed into vulnerability summaries
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

  db.getCollection('rawReports').aggregate([
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
        weekBeginning: {
          $dateFromParts : {
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
        }
      }
    },
    { $replaceRoot: { newRoot: "$_id" } },
    { $lookup: {
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

  def getTimelineData(reportsAfter: Instant): Future[Seq[TimelineEvent]] = {
    //Ensure that any changes made to this query are reflected in the comment above.
    CollectionFactory.collection(mongoComponent.database, "rawReports", TimelineEvent.mongoFormat).aggregate(
      Seq(
        `match`(Filters.gte("generatedDate", reportsAfter)), //Only process recent reports
        unwind("$rows"),
        `match`(Filters.regex("rows.component_physical_path", appConfig.exclusionRegex)), //Exclude row elements if matching regex
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
