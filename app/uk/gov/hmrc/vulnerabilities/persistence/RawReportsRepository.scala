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
import org.mongodb.scala.model.{IndexModel, IndexOptions}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.PlayMongoRepository
import uk.gov.hmrc.vulnerabilities.model.Report

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
    indexes        = Seq()
)
    {

      def insertReports(reports: Seq[Report]): Future[Int] =
        collection
          .insertMany(reports)
          .toFuture()
          .map(res => res.getInsertedIds.size())
}
