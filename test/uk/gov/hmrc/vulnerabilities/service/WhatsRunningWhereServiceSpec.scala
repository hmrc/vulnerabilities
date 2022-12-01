package uk.gov.hmrc.vulnerabilities.service

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import uk.gov.hmrc.vulnerabilities.model.{Deployment, ServiceVersionDeployments, WhatsRunningWhere}



class WhatsRunningWhereServiceSpec extends AnyWordSpec with Matchers {

  "WhatsRunningWhereService" when {
    "getting envs for service version" should {
      "Transform each WRW deployment into a unique ServiceVersionDeployment, and sort by (name, version)" in new Setup {
        val expectedResult = Seq(
          ServiceVersionDeployments(serviceName = "service1", version = "1.0", environments = Seq("production")),
          ServiceVersionDeployments(serviceName = "service1", version = "1.1", environments = Seq("qa")),
          ServiceVersionDeployments(serviceName = "service2", version = "1.9.6", environments = Seq("qa")),
          ServiceVersionDeployments(serviceName = "service2", version = "1.9.8", environments = Seq("externaltest")),
          ServiceVersionDeployments(serviceName = "service3", version = "1.22", environments = Seq("staging", "production")),
        )

        val result = whatsRunningWhereService.getEnvsForServiceVersion(connectorResponseHigherEnvs)

        result.length shouldBe 5
        result should contain theSameElementsInOrderAs expectedResult
        result.last.environments shouldBe Seq("staging", "production")
      }

      "Remove integration & development Deployments, and filter out empty ServiceVersionDeployments" in new Setup {
        val expectedResult = Seq(
          ServiceVersionDeployments(serviceName = "service1", version = "1.0", environments = Seq("production")),
          ServiceVersionDeployments(serviceName = "service1", version = "1.1", environments = Seq("qa")),
          ServiceVersionDeployments(serviceName = "service2", version = "1.9.6", environments = Seq("qa")),
          ServiceVersionDeployments(serviceName = "service2", version = "1.9.8", environments = Seq("externaltest")),
          ServiceVersionDeployments(serviceName = "service3", version = "1.22", environments = Seq("staging", "production")),
          ServiceVersionDeployments(serviceName = "service5", version = "1.29", environments = Seq("production", "externaltest")),
        )

        val result = whatsRunningWhereService.getEnvsForServiceVersion(connectorResponseAllEnvs)

        result.length shouldBe 6
        result should contain theSameElementsInOrderAs expectedResult
        result.last.environments shouldBe Seq("production", "externaltest")

      }
    }
  }
  trait Setup {
    val wrw1 = WhatsRunningWhere(serviceName = "service1",
      deployments = Seq(Deployment(environment = "qa", version = "1.1"), Deployment(environment = "production", version = "1.0")))
    val wrw2 = WhatsRunningWhere(serviceName = "service2",
      deployments = Seq(Deployment(environment = "externaltest", version = "1.9.8"), Deployment(environment = "qa", version = "1.9.6")))
    val wrw3 = WhatsRunningWhere(serviceName = "service3",
      deployments = Seq(Deployment(environment = "staging", version = "1.22"), Deployment(environment = "production", version = "1.22")))
    val wrw4 = WhatsRunningWhere(serviceName = "service4",
      deployments = Seq(Deployment(environment = "integration", version = "1.23"), Deployment(environment = "development", version = "1.23")))
    val wrw5 =  WhatsRunningWhere(serviceName = "service5",
      deployments = Seq(Deployment(environment = "integration", version = "1.29"), Deployment(environment = "production", version = "1.29"), Deployment(environment = "externaltest", version = "1.29")))


    val connectorResponseHigherEnvs   = Seq(wrw1, wrw2, wrw3)
    val connectorResponseAllEnvs      = Seq(wrw1, wrw2, wrw3, wrw4, wrw5)

    val whatsRunningWhereService = new WhatsRunningWhereService
  }
}
