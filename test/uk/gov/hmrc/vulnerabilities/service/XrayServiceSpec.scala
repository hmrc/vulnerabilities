package uk.gov.hmrc.vulnerabilities.service

import akka.actor.ActorSystem
import org.mockito.MockitoSugar.mock
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import uk.gov.hmrc.vulnerabilities.connectors.XrayConnector
import uk.gov.hmrc.vulnerabilities.model.{Filter, ReportRequestPayload, Resource, ServiceVersionDeployments, XrayRepo}
import uk.gov.hmrc.vulnerabilities.persistence.RawReportsRepository

import scala.concurrent.ExecutionContext.Implicits.global

class XrayServiceSpec extends AnyWordSpec with Matchers {

  "XrayService" when {
    "creating an xray payload" should {
      "Transform a serviceVersionDeployments into a ReportRequestPayload" in new Setup {
        val expectedResult = ReportRequestPayload(
          name = s"AppSec-report-service1_1.0",
          resources = Resource(Seq(XrayRepo(name="webstore-local"))),
          filters = Filter(impactedArtifact = s"*/service1_1.0*")
        )

        val res = whatsRunningWhereService.createXrayPayload(svd1)

        res shouldBe(expectedResult)
      }
    }
  }

  trait Setup {

    val xrayConnector = mock[XrayConnector]
    val actorSystem = mock[ActorSystem]
    val rawReportsRepository = mock[RawReportsRepository]

    val svd1 = ServiceVersionDeployments(serviceName = "service1", version = "1.0", environments = Seq("production"))

    val whatsRunningWhereService = new XrayService(
      xrayConnector,
      actorSystem,
      rawReportsRepository
    )
  }
}

