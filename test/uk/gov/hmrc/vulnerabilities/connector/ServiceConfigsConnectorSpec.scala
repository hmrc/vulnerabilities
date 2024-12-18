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

package uk.gov.hmrc.vulnerabilities.connector

import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.client.WireMock.{aResponse, stubFor, urlMatching}
import org.scalatest.concurrent.{IntegrationPatience, ScalaFutures}
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import org.scalatestplus.mockito.MockitoSugar
import play.api.Configuration
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.http.test.{HttpClientV2Support, WireMockSupport}
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig
import uk.gov.hmrc.vulnerabilities.model.{ArtefactName, RepoName}

import scala.concurrent.ExecutionContext.Implicits.global

class ServiceConfigsConnectorSpec
  extends AnyWordSpec
     with Matchers
     with ScalaFutures
     with IntegrationPatience
     with HttpClientV2Support
     with MockitoSugar
     with WireMockSupport:

  private given HeaderCarrier = HeaderCarrier()

  private val servicesConfig = ServicesConfig(
    Configuration(
      "microservice.services.service-configs.port" -> wireMockPort,
      "microservice.services.service-configs.host" -> wireMockHost
    )
  )

  private val connector = ServiceConfigsConnector(servicesConfig, httpClientV2)

  "ServiceConfigsConnector.repositories" should:
    "return all the repositories" in:
      stubFor:
        WireMock.get(urlMatching("/service-configs/service-repo-names"))
          .willReturn:
            aResponse().withBody:
              s"""[
                {"artefactName": "artefact1", "repoName": "repo1"},
                {"artefactName": "artefact2", "repoName": "repo2"}
              ]"""

      connector.artefactToRepos().futureValue shouldBe Seq(
        ArtefactToRepo(ArtefactName("artefact1"), RepoName("repo1")),
        ArtefactToRepo(ArtefactName("artefact2"), RepoName("repo2"))
      )
