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

package uk.gov.hmrc.vulnerabilities.service

import uk.gov.hmrc.vulnerabilities.model.{Report, ServiceVersionDeployments, WhatsRunningWhere}

import javax.inject.{Inject, Singleton}

@Singleton
class WhatsRunningWhereService @Inject()(){

  def getEnvsForServiceVersion(wrw: Seq[WhatsRunningWhere]): Seq[ServiceVersionDeployments] =
    wrw
      .flatMap(wrw =>
        removeIntegrationAndDevelopment(wrw)
          .deployments
        .groupBy(_.version)
        .mapValues(deployments => deployments.map(_.environment))
        .map(versionAndEnvs =>
          ServiceVersionDeployments(
            wrw.serviceName,
            versionAndEnvs._1,
            versionAndEnvs._2
          )
        )
      )
      .filterNot(_.environments.isEmpty)    //Remove any SVDs that were only deployed in Int/Dev
      .sortBy(sd => (sd.serviceName, sd.version))

   def removeIntegrationAndDevelopment(wrw: WhatsRunningWhere): WhatsRunningWhere =
     wrw.copy(deployments = wrw.deployments
         .filterNot(dep => (dep.environment == "integration" || dep.environment == "development"))
       )

  def removeSVDIfRecentReportExists(svds: Seq[ServiceVersionDeployments], recentReports: Seq[Report]): Seq[ServiceVersionDeployments] = {
    val reportNames    = recentReports.flatMap(rep => rep.rows.map(_.head.path.split("/")(2)))
    val reportVersions = recentReports.flatMap(rep => rep.rows.map(_.head.path.split("_")(1)))

    svds.filterNot(svd => reportNames.contains(svd.serviceName) && reportVersions.contains(svd.version))
  }
}
