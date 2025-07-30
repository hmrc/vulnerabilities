/*
 * Copyright 2025 HM Revenue & Customs
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

import play.api.libs.functional.syntax.toFunctionalBuilderOps
import play.api.libs.json.{Format, Reads, Writes, __}
import uk.gov.hmrc.crypto.{Encrypter, Decrypter, Sensitive}
import uk.gov.hmrc.crypto.json.JsonEncryption
import uk.gov.hmrc.vulnerabilities.Crypto

case class ArtifactoryToken(
  accessToken : Sensitive.SensitiveString
, refreshToken: Sensitive.SensitiveString
)

object ArtifactoryToken:

  val apiReads: Reads[ArtifactoryToken] =
    ( (__ \ "access_token" ).read[String].map(Sensitive.SensitiveString.apply _)
    ~ (__ \ "refresh_token").read[String].map(Sensitive.SensitiveString.apply _)
    )(apply _)

  def mongoFormat(using crypto: Crypto): Format[ArtifactoryToken] =
    given (Encrypter & Decrypter) = crypto.mongoCrypto
    given Format[Sensitive.SensitiveString] =
      JsonEncryption.sensitiveEncrypterDecrypter(Sensitive.SensitiveString.apply)

    ( (__ \ "accessToken" ).format[Sensitive.SensitiveString]
    ~ (__ \ "refreshToken").format[Sensitive.SensitiveString]
    )(apply, pt => Tuple.fromProductTyped(pt))
