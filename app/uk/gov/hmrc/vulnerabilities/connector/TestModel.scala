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

package uk.gov.hmrc.vulnerabilities.connector

trait TestModel:


  val deploymentInfoForAllEnvironmentsResponse: String =
    """
      |[
      |  {
      |    "name": "example-frontend",
      |    "environment": "development",
      |    "zone": "public",
      |    "type": "frontend",
      |    "slots": 3,
      |    "instances": 1,
      |    "envVars": {},
      |    "jvm": {
      |      "X:MaxRAMPercentage=": "40",
      |      "X:+UseParallelGC": ""
      |    }
      |  },
      |  {
      |    "name": "example-frontend",
      |    "environment": "externaltest",
      |    "zone": "public",
      |    "type": "frontend",
      |    "slots": 4,
      |    "instances": 1,
      |    "envVars": {},
      |    "jvm": {
      |      "X:MaxRAMPercentage=": "40.0",
      |      "X:+UseParallelGC": ""
      |    }
      |  },
      |  {
      |    "name": "example-frontend",
      |    "environment": "production",
      |    "zone": "public",
      |    "type": "frontend",
      |    "slots": 4,
      |    "instances": 1,
      |    "envVars": {},
      |    "jvm": {
      |      "X:MaxRAMPercentage=": "40.0",
      |      "X:+UseParallelGC": ""
      |    }
      |  },
      |  {
      |    "name": "example-frontend",
      |    "environment": "qa",
      |    "zone": "public",
      |    "type": "frontend",
      |    "slots": 3,
      |    "instances": 1,
      |    "envVars": {},
      |    "jvm": {
      |      "X:MaxRAMPercentage=": "40",
      |      "X:+UseParallelGC": ""
      |    }
      |  },
      |  {
      |    "name": "example-frontend",
      |    "environment": "staging",
      |    "zone": "public",
      |    "type": "frontend",
      |    "slots": 3,
      |    "instances": 1,
      |    "envVars": {},
      |    "jvm": {
      |      "X:MaxRAMPercentage=": "40",
      |      "X:+UseParallelGC": ""
      |    }
      |  },
      |    {
      |    "name": "example-backend",
      |    "environment": "development",
      |    "zone": "public",
      |    "type": "backend",
      |    "slots": 3,
      |    "instances": 1,
      |    "envVars": {},
      |    "jvm": {
      |      "X:MaxRAMPercentage=": "40",
      |      "X:+UseParallelGC": ""
      |    }
      |  },
      |  {
      |    "name": "example-backend",
      |    "environment": "externaltest",
      |    "zone": "public",
      |    "type": "backend",
      |    "slots": 4,
      |    "instances": 1,
      |    "envVars": {},
      |    "jvm": {
      |      "X:MaxRAMPercentage=": "40.0",
      |      "X:+UseParallelGC": ""
      |    }
      |  },
      |  {
      |    "name": "example-backend",
      |    "environment": "production",
      |    "zone": "public",
      |    "type": "backend",
      |    "slots": 4,
      |    "instances": 1,
      |    "envVars": {},
      |    "jvm": {
      |      "X:MaxRAMPercentage=": "40.0",
      |      "X:+UseParallelGC": ""
      |    }
      |  },
      |  {
      |    "name": "example-backend",
      |    "environment": "qa",
      |    "zone": "public",
      |    "type": "backend",
      |    "slots": 4,
      |    "instances": 1,
      |    "envVars": {},
      |    "jvm": {
      |      "X:MaxRAMPercentage=": "40.0",
      |      "X:+UseParallelGC": ""
      |    }
      |  },
      |  {
      |    "name": "example-backend",
      |    "environment": "staging",
      |    "zone": "public",
      |    "type": "backend",
      |    "slots": 4,
      |    "instances": 1,
      |    "envVars": {},
      |    "jvm": {
      |      "X:MaxRAMPercentage=": "40.0",
      |      "X:+UseParallelGC": ""
      |    }
      |  }
      |]
      |""".stripMargin
