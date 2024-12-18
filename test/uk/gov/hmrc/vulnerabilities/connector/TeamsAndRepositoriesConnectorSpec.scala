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
import uk.gov.hmrc.vulnerabilities.model.{RepoName, TeamName}

import scala.concurrent.ExecutionContext.Implicits.global

class TeamsAndRepositoriesConnectorSpec
  extends AnyWordSpec
     with Matchers
     with ScalaFutures
     with IntegrationPatience
     with HttpClientV2Support
     with MockitoSugar
     with WireMockSupport:

  import TeamsAndRepositoriesConnector._

  private given HeaderCarrier = HeaderCarrier()

  private val servicesConfig = ServicesConfig(
    Configuration(
      "microservice.services.teams-and-repositories.port" -> wireMockPort,
      "microservice.services.teams-and-repositories.host" -> wireMockHost
    )
  )

  private val connector = TeamsAndRepositoriesConnector(servicesConfig, httpClientV2)

  "TeamsAndRepositoriesConnector.repositories" should:
    "return all the repositories" in:
      stubFor:
        WireMock.get(urlMatching("/api/v2/repositories"))
          .willReturn:
            aResponse().withBody:
              s"""[
                {"name": "service1", "teamNames": ["team1", "team2"]},
                {"name": "service2", "teamNames": ["team1", "team3"]}
              ]"""

      connector.repositories(teamName = None).futureValue shouldBe Seq(
        Repo(RepoName("service1"), Seq(TeamName("team1"), TeamName("team2"))),
        Repo(RepoName("service2"), Seq(TeamName("team1"), TeamName("team3")))
      )
