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
import org.mongodb.scala.model.{Filters, IndexModel, IndexOptions}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.PlayMongoRepository
import uk.gov.hmrc.vulnerabilities.model.Vulnerability

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
    IndexModel(Indexes.ascending("cve"), IndexOptions().name("cve").background(true)),
    IndexModel(Indexes.ascending("teams"), IndexOptions().name("teams").background(true)),
  ),
) {
  def search(service: Option[String] = None, id: Option[String] = None, description: Option[String] = None, team: Option[String] = None, requiresAction: Option[Boolean] = None): Future[Seq[Vulnerability]] = {
    val filters = Seq(
             service.map(s => Filters.equal("service", s)),
                  id.map(i => Filters.regex("id", i)),
         description.map(d => Filters.regex("description", d)),
                team.map(t => Filters.equal("teams", t)),
      requiresAction.map(r => Filters.equal("requiresAction", r))
    ).flatten

    filters match {
      case Nil => collection.find().toFuture()
      case more => collection.find(Filters.and(more:_*)).toFuture()
    }
  }
}