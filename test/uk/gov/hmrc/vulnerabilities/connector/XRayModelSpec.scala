package uk.gov.hmrc.vulnerabilities.connector

import org.scalatest.OptionValues
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.libs.json.{Format, JsError, JsResult, JsSuccess, Json}
import uk.gov.hmrc.vulnerabilities.model.Report
import uk.gov.hmrc.vulnerabilities.model.Report.Vulnerability

class XRayModelSpec extends AnyWordSpec
with Matchers
with OptionValues{

  import uk.gov.hmrc.vulnerabilities.connector.XRayTestData._
  "X-Ray Model" when :
    "deserializing XRay JSON for a Vulnerability entry" should :
      "Accept early version of JFrog API format" in :
        val jsValue = Json.parse(vulnerabilityEntryV1)

        given Format[Report.Vulnerability] = Report.Vulnerability.apiFormat

        val result: JsResult[Vulnerability] = jsValue.validate[Vulnerability]

        result match
          case JsSuccess(value, _) =>
            value.summary shouldBe "This is an exploit"
            // optional fields for cross-version compatibility
            value.description should contain("This is an exploit description")
            value.severitySource should contain("Source")
            value.references should contain allOf("foo.com", "bar.net")

          case JsError(errors) => fail(s"Unexpected fail to deserialize with errors: $errors")
      "Accept later version of JFrog API format with optional summary fields" in :
        val jsValue = Json.parse(vulnerabilityEntryV1_X_missingFields)

        given Format[Report.Vulnerability] = Report.Vulnerability.apiFormat

        val result: JsResult[Vulnerability] = jsValue.validate[Vulnerability]

        result match
          case JsSuccess(value, _) =>
            value.summary shouldBe "This is an exploit"
            value.description should be(empty)
            value.severitySource should be(empty)
            value.references should be(empty)
          case JsError(errors) => fail(s"Unexpected fail to deserialize with errors: $errors")

}
