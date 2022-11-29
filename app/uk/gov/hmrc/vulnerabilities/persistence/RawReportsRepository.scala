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
import org.mongodb.scala.bson.{BsonArray, BsonDocument}
import org.mongodb.scala.model.Aggregates.{`match`, group, project, unwind}
import org.mongodb.scala.model.{Accumulators, Filters, IndexModel, IndexOptions, Sorts}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.{CollectionFactory, PlayMongoRepository}
import uk.gov.hmrc.vulnerabilities.model.{Report, UnrefinedVulnerabilitySummary, VulnerabilitySummary}

import java.time.temporal.ChronoUnit
import java.time.{Instant, LocalDate, LocalDateTime, ZoneOffset}
import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}



@Singleton
class RawReportsRepository @Inject()(
mongoComponent: MongoComponent
)(implicit ec: ExecutionContext
) extends PlayMongoRepository(
    collectionName = "rawReports",
    mongoComponent = mongoComponent,
    domainFormat   = Report.mongoFormat,
    indexes        = Seq(IndexModel(Indexes.descending("generatedDate"), IndexOptions().name("generatedDate").background(true)))
)
    {

      def insertReports(reports: Seq[Report]): Future[Int] =
        collection
          .insertMany(reports)
          .toFuture()
          .map(res => res.getInsertedIds.size())

      private def now = LocalDateTime.now().toInstant(ZoneOffset.UTC)

      def getMostRecent: Future[Instant] =
        collection
          .find(Sorts.descending("generatedDate"))
          .headOption()
          .map(_.map(_.generatedDate).getOrElse(now))

      // use a different view to allow distinctVulnerabilitiesSummary to return a different case class
      private val vcsCollection: MongoCollection[UnrefinedVulnerabilitySummary] =
        CollectionFactory.collection(
          mongoComponent.database,
          "rawReports",
          UnrefinedVulnerabilitySummary.reads
        )

      private def yesterday = now.minus(6, ChronoUnit.HOURS) //Only transform data added to rawReports within last 6 hours

      def getNewDistinctVulnerabilities: Future[Seq[UnrefinedVulnerabilitySummary]] =
        vcsCollection.aggregate(
          Seq(
            `match`(Filters.gt("generatedDate", yesterday)),
            unwind("$rows"),
            unwind("$rows.cves"),
            project(
              BsonDocument(
                "id"            -> BsonDocument("$ifNull" -> BsonArray("$rows.cves.cve", "$rows.issue_id")),
                "vuln"          -> "$rows",
                "generatedDate" -> "$generatedDate"
              )
            ),
            group("$id", Accumulators.addToSet("vulns", "$vuln"), Accumulators.first("generatedDate", "$generatedDate")),
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
              )
            )
          )
        ).toFuture()
}
