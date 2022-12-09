/*
 * Copyright 2022 HM Revenue & Customs
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
import org.mongodb.scala.model.Aggregates.{`match`, group, project, unwind}
import org.mongodb.scala.model.{Accumulators, Filters, IndexModel, IndexOptions}
import play.api.Configuration
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.{CollectionFactory, PlayMongoRepository}
import uk.gov.hmrc.vulnerabilities.config.{SchedulerConfigs}
import uk.gov.hmrc.vulnerabilities.model.{Report, UnrefinedVulnerabilitySummary}

import java.time.temporal.ChronoUnit
import java.time.{LocalDateTime, ZoneOffset}
import javax.inject.{Inject, Singleton}
import scala.concurrent.duration.FiniteDuration
import scala.concurrent.{ExecutionContext, Future}



@Singleton
class RawReportsRepository @Inject()(
mongoComponent: MongoComponent,
schedulerConfigs: SchedulerConfigs
)(implicit ec: ExecutionContext
) extends PlayMongoRepository(
    collectionName = "rawReports",
    mongoComponent = mongoComponent,
    domainFormat   = Report.mongoFormat,
    indexes        = Seq(IndexModel(Indexes.descending("generatedDate"), IndexOptions().name("generatedDate").background(true)))
)
    {

      def insertReport(report: Report): Future[Unit] = {
        collection
          .insertOne(report)
          .toFuture()
          .map(_ => ())
      }

      def countReports: Future[Int] =
        collection.find().toFuture.map(_.length)

      def getReportsInLastXDays: Future[Seq[Report]] =
        collection.find(Filters.gt("generatedDate", recent)).toFuture()

      // use a different view to allow distinctVulnerabilitiesSummary to return a different case class
      private val vcsCollection: MongoCollection[UnrefinedVulnerabilitySummary] =
        CollectionFactory.collection(
          mongoComponent.database,
          "rawReports",
          UnrefinedVulnerabilitySummary.reads
        )

      def recent = LocalDateTime.now().minus(schedulerConfigs.dataReloadScheduler.dataCutOff, ChronoUnit.DAYS)
      //Only transform data added to rawReports within last 24 hours
      //This stops out of date, and since fixed reports being transformed into vulnerability summaries
      //Works as the scheduler runs every 7 days

      //TO-DO:
      // It would be neater if each scheduler run assigned a random 'job id' to all raw reports inserted in the collection
      // This could be passed through the Service for comprehension, and used as a filter in `getNewDistinctVulnerabilities` below
      // This would be better than a time cut off - as we are able to hit a manual reload endpoint, outside of the schedule window.

      def getNewDistinctVulnerabilities: Future[Seq[UnrefinedVulnerabilitySummary]] =
        vcsCollection.aggregate(
          Seq(
            `match`(Filters.gt("generatedDate", recent)),
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
    }
