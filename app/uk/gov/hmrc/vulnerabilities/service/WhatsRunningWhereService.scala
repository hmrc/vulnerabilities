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

import uk.gov.hmrc.vulnerabilities.model.{ServiceVersionDeployments, WhatsRunningWhere}

import javax.inject.{Inject, Singleton}

@Singleton
class WhatsRunningWhereService @Inject()(){

  def getEnvsForServiceVersion(wrw: Seq[WhatsRunningWhere]): Seq[ServiceVersionDeployments] =
    wrw
      .flatMap(wrw => wrw.deployments
        .groupBy(_.version)
        .mapValues(deployments => deployments.map(_.environment))
        .map(versionAndEnvs =>
          ServiceVersionDeployments(
            wrw.serviceName,
            versionAndEnvs._1,
            versionAndEnvs._2
          )
        )
      ).sortBy(sd => (sd.serviceName, sd.version))


}
