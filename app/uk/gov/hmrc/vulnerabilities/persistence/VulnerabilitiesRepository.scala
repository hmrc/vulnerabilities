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
import org.mongodb.scala.bson.{BsonArray, BsonDocument}
import org.mongodb.scala.MongoCollection
import org.mongodb.scala.model.Accumulators.{first, push}
import org.mongodb.scala.model.Aggregates._
import org.mongodb.scala.model.{Filters, IndexModel, IndexOptions, Sorts}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.{CollectionFactory, PlayMongoRepository}
import uk.gov.hmrc.vulnerabilities.model.{Vulnerability, VulnerabilitySummary}

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class VulnerabilitiesRepository @Inject()(
                                mongoComponent: MongoComponent
                              )(implicit ec: ExecutionContext
                              ) extends PlayMongoRepository(
  collectionName = "vulnerabilities",
  mongoComponent = mongoComponent,
  domainFormat   = Vulnerability.mongoFormat,
  indexes        = Seq(
    IndexModel(Indexes.ascending("service"), IndexOptions().name("service").background(true)),
    IndexModel(Indexes.ascending("id"), IndexOptions().name("id").background(true)),
    IndexModel(Indexes.ascending("teams"), IndexOptions().name("teams").background(true)),
    IndexModel(Indexes.ascending("curationStatus"), IndexOptions().name("curationStatus").background(true)),
  ),
) {
  def search(service: Option[String] = None, id: Option[String] = None, description: Option[String] = None, team: Option[String] = None): Future[Seq[Vulnerability]] = {
    val filters = Seq(
      service.map(s => Filters.equal("service", s)),
           id.map(i => Filters.regex("id", i)),
  description.map(d => Filters.regex("description", d)),
         team.map(t => Filters.equal("teams", t))
    ).flatten

    filters match {
      case Nil => collection.find().toFuture()
      case more => collection.find(Filters.and(more: _*)).toFuture()
    }
  }

  // use a different view to allow distinctVulnerabilitiesSummary to return a different case class
  private val vcsCollection: MongoCollection[VulnerabilitySummary] =
    CollectionFactory.collection(
      mongoComponent.database,
      "vulnerabilities",
      VulnerabilitySummary.mongoFormat
    )

  def distinctVulnerabilitiesSummary(id: Option[String], curationStatus: Option[String], service: Option[String], team: Option[String]): Future[Seq[VulnerabilitySummary]] = {
    val Quoted = """^\"(.*)\"$""".r

    val optFilters = Seq(
                    id.map(i => Filters.regex("id", i.toUpperCase())),
        curationStatus.map(r => Filters.equal("curationStatus", r)),
                  team.map(t => Filters.equal("teams", t)),
               service.map{
                 case Quoted(s) => Filters.equal("service", s.toLowerCase())
                 case s         => Filters.regex("service", s.toLowerCase())
               }
    ).flatten

    val pipeline = Seq(
      group(
        id = "$id",
        push("teams", "$teams"),
        push("occurrences", BsonDocument(
          "service" -> "$service",
          "serviceVersion" -> "$serviceVersion",
          "componentPathInSlug" -> "$componentPathInSlug"
        )),
        first("distinctVulnerability", BsonDocument(
          "vulnerableComponentName" -> "$vulnerableComponentName",
          "vulnerableComponentVersion" -> "$vulnerableComponentVersion",
          "id" -> "$id",
          "score" -> "$score",
          "description" -> "$description",
          "fixedVersions" -> "$fixedVersions",
          "references" -> "$references",
          "published" -> "$published",
          "assessment" -> "$assessment",
          "curationStatus" -> "$curationStatus",
          "ticket" -> "$ticket"
        ))
      ),
      sort(
        Sorts.orderBy(Sorts.descending("distinctVulnerability.score"), Sorts.ascending("distinctVulnerability.id"))
      ),
      project(
        BsonDocument(
          "occurrences" -> "$occurrences",
          "teams" -> BsonDocument("$reduce" ->
            BsonDocument(
              "input" -> "$teams",
              "initialValue" -> BsonArray(),
              "in" -> BsonDocument("$concatArrays" -> BsonArray("$$value", "$$this"))
            )
          ),
          "distinctVulnerability" -> "$distinctVulnerability"
        )),
      project(
        BsonDocument(
          "occurrences" -> "$occurrences",
          "teams" -> BsonDocument("$setUnion" -> "$teams"),
          "distinctVulnerability" -> "$distinctVulnerability"
        ))
    )

    val finalPipeline = optFilters match {
      case Nil => pipeline
      case more => `match`(Filters.and(more: _*)) +: pipeline
    }

    vcsCollection.aggregate(finalPipeline).toFuture()
 }
}

