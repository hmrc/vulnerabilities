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

package uk.gov.hmrc.vulnerabilities.model

import org.scalatest.OptionValues
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec
import play.api.libs.json.*
import uk.gov.hmrc.vulnerabilities.model.Report
import uk.gov.hmrc.vulnerabilities.model.Report.Vulnerability

class ModelSpec
  extends AnyWordSpec
    with Matchers
    with OptionValues:

  import TestData.XRayModel._
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

  "MongoDB model for persisted Vulnerabilities" when:
    import TestData.MongoModel
    "deserializing Mongo JSON for a Vulnerability entry" should:

      "Accept the expected format when 'description' / 'refrences' field present " in:
        val jsValue = Json.parse(MongoModel.vulnerabilityEntryV1Mongo)

        given Format[Report.Vulnerability] = Report.Vulnerability.mongoFormat
        val result = Json.fromJson[Report.Vulnerability](jsValue)

        result match
          case JsSuccess(value, _) =>
            value.summary shouldBe "This is an exploit"
            value.description should contain("This is an exploit description")
            value.severitySource should contain("Source")
            value.references should contain allOf("foo.com", "bar.net")

          case JsError(errors) => fail(s"Unexpected fail to deserialize with errors: $errors")

      "Accept the expected format when 'description' / 'refrences' field are absent" in:
        val jsValue = Json.parse(MongoModel.vulnerabilityEntryV1xMissingFieldsMongo)

        given Format[Report.Vulnerability] = Report.Vulnerability.mongoFormat
        val result = Json.fromJson[Report.Vulnerability](jsValue)

        result match
          case JsSuccess(value, _) =>
            value.summary shouldBe "This is an exploit"
            value.description shouldBe empty
            value.severitySource should contain("Source")
            value.references shouldBe empty

          case JsError(errors) => fail(s"Unexpected fail to deserialize with errors: $errors")
