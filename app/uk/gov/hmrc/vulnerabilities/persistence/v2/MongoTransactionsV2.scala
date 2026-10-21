/*
 * Copyright 2026 HM Revenue & Customs
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

package uk.gov.hmrc.vulnerabilities.persistence.v2

import javax.inject.{Inject, Singleton}
import org.mongodb.scala.{ClientSession, MongoException, ReadConcern, ReadPreference, TransactionOptions, WriteConcern}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.transaction.{TransactionConfiguration, Transactions}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class MongoTransactionsV2 @Inject()(protected val mongoComponent: MongoComponent)(using ExecutionContext)
  extends Transactions:
  private given TransactionConfiguration = TransactionConfiguration.strict.copy(
    transactionOptions = Some(TransactionOptions.builder()
      .readConcern(ReadConcern.SNAPSHOT)
      .writeConcern(WriteConcern.MAJORITY)
      .readPreference(ReadPreference.primary())
      .build())
  )

  def snapshot[A](operation: ClientSession => Future[A]): Future[A] =
    withSessionAndTransaction(operation)

  // Concurrent first inserts can raise E11000 without a transient-transaction label.
  // Restart with a new snapshot to check the winning record rather than ignore the conflict.
  def writing[A](operation: ClientSession => Future[A]): Future[A] =
    def attempt(remaining: Int): Future[A] =
      snapshot(operation).recoverWith:
        case e: MongoException if e.getCode == 11000 && remaining > 0 => attempt(remaining - 1)
    attempt(8)
