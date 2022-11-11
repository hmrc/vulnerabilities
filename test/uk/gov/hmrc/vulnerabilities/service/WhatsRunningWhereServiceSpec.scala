package uk.gov.hmrc.vulnerabilities.service

import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import uk.gov.hmrc.vulnerabilities.model.{Deployment, ServiceVersionDeployments, WhatsRunningWhere}



class WhatsRunningWhereServiceSpec extends AnyWordSpec with Matchers {

  "getEnvsForServiceVersion" should {
    "Transform each WRW deployment into a unique ServiceVersionDeployment, and sort by (name, version)" in new Setup {
      val expectedResult = Seq(
        ServiceVersionDeployments(serviceName = "service1", version = "1.0",   environments = Seq("production")),
        ServiceVersionDeployments(serviceName = "service1", version = "1.1",   environments = Seq("integration")),
        ServiceVersionDeployments(serviceName = "service2", version = "1.9.6", environments = Seq("qa")),
        ServiceVersionDeployments(serviceName = "service2", version = "1.9.8", environments = Seq("development")),
        ServiceVersionDeployments(serviceName = "service3", version = "1.22",  environments = Seq("staging", "production")),
      )

      val result = whatsRunningWhereService.getEnvsForServiceVersion(successfulConnectorResponse)

      result.length shouldBe 5
      result should contain theSameElementsInOrderAs expectedResult
      result.last.environments shouldBe Seq("staging", "production")
    }
  }
}

trait Setup {
  val wrw1 = WhatsRunningWhere(serviceName = "service1",
    deployments = Seq(Deployment(environment = "integration", version = "1.1"), Deployment(environment = "production", version = "1.0")))
  val wrw2 = WhatsRunningWhere(serviceName = "service2",
    deployments = Seq(Deployment(environment = "development", version = "1.9.8"), Deployment(environment = "qa", version = "1.9.6")))
  val wrw3 = WhatsRunningWhere(serviceName = "service3",
    deployments = Seq(Deployment(environment = "staging", version = "1.22"), Deployment(environment = "production", version = "1.22")))

  val successfulConnectorResponse = Seq(wrw1, wrw2, wrw3)
  val emptyConnectorResponse      = Seq()

  val whatsRunningWhereService = new WhatsRunningWhereService
}