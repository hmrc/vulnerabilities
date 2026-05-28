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

package uk.gov.hmrc.vulnerabilities.service

import uk.gov.hmrc.vulnerabilities.model.*
import uk.gov.hmrc.vulnerabilities.persistence.ReportRepository

import java.time.Instant
import scala.collection.mutable
import scala.concurrent.ExecutionContext.Implicits.global
import scala.concurrent.Future
import scala.language.postfixOps

object XrayServiceTestSupport:

  object FakeReportRepository:
    def apply(
      report: Report,
      initialTestVulnerabiltiies: Seq[Report.Vulnerability] = Seq.empty,
    ): ReportRepository with TestRepo =
      new FakeReportRepository (Seq(report), initialTestVulnerabiltiies)

    def apply(
      reportList: Seq[Report]
    ): ReportRepository with TestRepo =
      new FakeReportRepository (reportList, Nil)

  trait TestRepo:
    def getTestStore: Map[String, Report]

  class FakeReportRepository(
    reportList: Seq[Report], 
    testVulnerabilityRows: Seq[Report.Vulnerability]
  )
    extends ReportRepository
      with TestRepo:
    
    val store = mutable.Map.from(reportList.map(r => toKey(r) -> r.copy(rows = testVulnerabilityRows)))

    def toKey(report: Report): String = toKeyFromServiceNameAndVersion(report.serviceName, report.serviceVersion)

    private def toKeyFromServiceNameAndVersion(serviceName: ServiceName, serviceVersion: Version): String =
      s"${serviceName}:${serviceVersion}"

    override def getTestStore: Map[String, Report] = store.toMap

    override def put(report: Report): Future[Unit] =
      store += toKey(report) -> report
      Future.unit

    override def findFlagged(): Future[Seq[Report]] =
      Future.successful(store.values.filter(r => r.latest || r.production || r.staging || r.qa || r.development || r.integration || r.externalTest).toSeq)

    override def findGeneratedBefore(before: Instant): Future[Seq[Report]] =
      Future.successful(store.values.filter(_.generatedDate.isBefore(before)).toSeq)

    override def findNotScanned(): Future[Seq[Report]] =
      Future.successful(store.values.filterNot(_.scanned).toSeq)

    override def find(slugInfoFlag: Option[SlugInfoFlag], serviceNames: Option[Seq[ServiceName]], version: Option[Version]): Future[Seq[Report]] =
      Future.successful(
        store.values.toSeq.filter(r => serviceNames.forall(_.contains(r.serviceName)) && version.forall(_ == r.serviceVersion))
      )

    override def exists(serviceName: ServiceName, version: Version): Future[Boolean] =
      Future.successful(store.values.exists(r => r.serviceName == serviceName && r.serviceVersion == version))

    override def findDeployed(serviceName: ServiceName): Future[Seq[Report]] =
      Future.successful(store.values.filter(_.serviceName == serviceName).toSeq)

    override def delete(serviceName: ServiceName, version: Version): Future[Unit] =
      val key = toKeyFromServiceNameAndVersion(serviceName, version)
      store -= key
      Future.unit

    override def setFlag(flag: SlugInfoFlag, serviceName: ServiceName, version: Version): Future[Unit] =
      Future.unit

    override def clearFlag(flag: SlugInfoFlag, serviceName: ServiceName): Future[Unit] =
      Future.unit

    override def getTimelineData(weekBeginning: Instant): Future[Seq[TimelineEvent]] =
      Future.successful(Seq.empty)




