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

package uk.gov.hmrc.vulnerabilities.binders

import play.api.mvc.QueryStringBindable
import uk.gov.hmrc.vulnerabilities.model.{CurationStatus, ServiceName, Version}

import java.time.Instant
import scala.util.Try

object Binders {
  implicit def instantBindable(implicit strBinder: QueryStringBindable[String]): QueryStringBindable[Instant] =
    new QueryStringBindable[Instant] {
      override def bind(key: String, params: Map[String, Seq[String]]): Option[Either[String, Instant]] = {
        strBinder.bind(key, params).map(
          _.flatMap(s => Try(Instant.parse(s)).toEither.left.map(_.getMessage))
        )
      }

      override def unbind(key: String, value: Instant): String =
        strBinder.unbind(key, value.toString)
    }

  implicit def curationStatusBindable(implicit strBinder: QueryStringBindable[String]): QueryStringBindable[CurationStatus] =
    new QueryStringBindable[CurationStatus] {
      override def bind(key: String, params: Map[String, Seq[String]]): Option[Either[String, CurationStatus]] =
        strBinder.bind(key, params).map(
          _.flatMap(s => CurationStatus.parse(s))
        )

      override def unbind(key: String, value: CurationStatus): String =
        strBinder.unbind(key, value.asString)
    }

  implicit def serviceNameBindable(implicit strBinder: QueryStringBindable[String]): QueryStringBindable[ServiceName] =
    strBinder.transform(ServiceName.apply, _.asString)

  implicit def versionBindable(implicit strBinder: QueryStringBindable[String]): QueryStringBindable[Version] =
    strBinder.transform(Version.apply, _.original)
}
