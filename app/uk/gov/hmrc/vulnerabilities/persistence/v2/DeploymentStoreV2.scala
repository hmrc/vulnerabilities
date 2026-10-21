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
import play.api.Configuration
import uk.gov.hmrc.vulnerabilities.model.v2.deployment.V2ResourceLimit
import scala.concurrent.{ExecutionContext, Future}

/** All parts of the deployment join share one committed snapshot. */
@Singleton
class DeploymentStoreV2 @Inject()(
  details: VulnerabilityRepositoryV2,
  evidence: VulnerabilityOccurrenceRepositoryV2,
  workflow: ServiceOccurrenceRepositoryV2,
  scans: ScanRecordRepositoryV2,
  transactions: MongoTransactionsV2,
  config: Configuration
)(using ExecutionContext):
  private val maximum = config.get[Int]("v2.read.max-findings")
  require(maximum > 0 && maximum < Int.MaxValue, "v2.read.max-findings must be positive and less than Int.MaxValue")

  def read(service: String, version: String): Future[Option[DeploymentRecordsV2]] =
    transactions.snapshot: session =>
      scans.findDeployment(service, version, Some(session)).flatMap:
        case None => Future.successful(None)
        case Some(scan) =>
          evidence.findDeployment(service, version, maximum, Some(session)).flatMap: occurrences =>
            checkBound(occurrences.size)
            if occurrences.isEmpty then Future.successful(Some(DeploymentRecordsV2(scan, Seq.empty, Seq.empty, Seq.empty)))
            else
              val ids = occurrences.map(_.vuln_id)
              for
                vulnerabilities <- details.findByIds(ids, maximum, Some(session))
                workflows <- workflow.findByIds(service, ids, maximum, Some(session))
              yield
                checkBound(vulnerabilities.size)
                checkBound(workflows.size)
                Some(DeploymentRecordsV2(scan, occurrences, vulnerabilities, workflows))

  private def checkBound(size: Int): Unit =
    if size > maximum then throw V2ResourceLimit("V2 deployment exceeds configured read resource limit; no partial results returned")
