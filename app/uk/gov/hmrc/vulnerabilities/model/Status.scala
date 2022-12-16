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

package uk.gov.hmrc.vulnerabilities.model

sealed trait Status {
  def statusCode: Int
  def statusMessage: String
}

case object XraySuccess extends Status {
  override val statusCode = 0
  override val statusMessage = "Report has been generated, ready to be downloaded"
}

case object XrayNoData extends Status {
  override val statusCode = 1
  override val statusMessage = "There were no rows in this report, will not attempt to download report."
}

case object XrayNotReady extends Status {
  override val statusCode = 2
  override val statusMessage = "No report was generated within the timeout limit, will not attempt to download or delete from the XRAY UI. Manual cleanup may be required."
}

