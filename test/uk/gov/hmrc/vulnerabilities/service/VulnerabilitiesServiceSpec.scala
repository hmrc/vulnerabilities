package uk.gov.hmrc.vulnerabilities.service

import org.mockito.MockitoSugar.mock
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import uk.gov.hmrc.vulnerabilities.data.UnrefinedVulnerabilitySummariesData
import uk.gov.hmrc.vulnerabilities.model.{Deployment, ServiceVersionDeployments, WhatsRunningWhere}
import uk.gov.hmrc.vulnerabilities.persistence.VulnerabilitySummariesRepository

import scala.concurrent.ExecutionContext.Implicits.global

class VulnerabilitiesServiceSpec extends AnyWordSpec with Matchers {

  "vulnerabilitiesService" when {
    "converting to vulnerability summary" should {
      "Transform each unrefinedVulnerabilitySummary into a VulnerabilitySummary, using the data from releasesAPI and T&R" in new Setup {
        val expectedResult = ???




      }
    }
  }
  trait Setup {

    val unrefined1 = UnrefinedVulnerabilitySummariesData.unrefined1
    val unrefined2 = UnrefinedVulnerabilitySummariesData.unrefined2
    val unrefined3 = UnrefinedVulnerabilitySummariesData.unrefined3

    val reposWithTeams: Map[String, Seq[String]] = ???

    val vulnerabilitySummariesRepository: VulnerabilitySummariesRepository = mock[VulnerabilitySummariesRepository]
    val vulnerabilitiesService = new VulnerabilitiesService(vulnerabilitySummariesRepository)


  }
}
