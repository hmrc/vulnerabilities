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

import javax.inject.{Inject, Singleton}
import org.mongodb.scala.model.{Filters, ReplaceOptions}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.PlayMongoRepository
import uk.gov.hmrc.vulnerabilities.model.ArtifactoryToken
import uk.gov.hmrc.vulnerabilities.Crypto

import scala.concurrent.{ExecutionContext, Future}

@Singleton
class ArtifactoryTokenRepository @Inject()(
  mongoComponent: MongoComponent
)(using
  ExecutionContext
, Crypto
) extends PlayMongoRepository[ArtifactoryToken](
  mongoComponent = mongoComponent,
  collectionName = "artifactoryToken",
  domainFormat   = ArtifactoryToken.mongoFormat,
  indexes        = Seq.empty
):
  override lazy val requiresTtlIndex = false // just a single row thats updated, so doesn't rely on ttl indexes

  def get(): Future[Option[ArtifactoryToken]] =
    collection
      .find(Filters.empty)
      .headOption()

  def put(token: ArtifactoryToken): Future[Unit] =
    collection
      .replaceOne(
        filter      = Filters.empty,
        replacement = token,
        options     = ReplaceOptions().upsert(true)
      )
      .toFuture()
      .map(_ => ())
