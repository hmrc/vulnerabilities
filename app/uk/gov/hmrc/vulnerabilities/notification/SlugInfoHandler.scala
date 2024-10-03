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

package uk.gov.hmrc.vulnerabilities.notification

import cats.data.EitherT

import software.amazon.awssdk.services.sqs.model.Message

import org.apache.pekko.actor.ActorSystem
import play.api.Configuration
import play.api.libs.json.Json
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.vulnerabilities.connector.ArtefactProcessorConnector
import uk.gov.hmrc.vulnerabilities.persistence.RawReportsRepository
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.service.XrayService

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class SlugInfoHandler @Inject()(
  configuration             : Configuration,
  artefactProcessorConnector: ArtefactProcessorConnector,
  rawReportsRepository      : RawReportsRepository,
  xrayService               : XrayService
)(implicit
  actorSystem         : ActorSystem,
  ec                  : ExecutionContext
) extends SqsConsumer(
  name                = "SlugInfo"
, config              = SqsConfig("aws.sqs.slug", configuration)
)(actorSystem, ec) {

  private implicit val hc: HeaderCarrier = HeaderCarrier()

  private def prefix(payload: SlugInfoHandler.SlugEvent) =
    s"SlugInfo (${payload.jobType}) ${payload.eventType} ${payload.serviceName.asString} ${payload.version.original}"

  override protected def processMessage(message: Message): Future[MessageAction] = {
    logger.debug(s"Starting processing SlugInfo message with ID '${message.messageId()}'")
    (for {
      payload <- EitherT
                   .fromEither[Future](Json.parse(message.body).validate(SlugInfoHandler.reads).asEither)
                   .leftMap(error => s"Could not parse SlugInfo message with ID '${message.messageId()}'. Reason: $error")
       _      <- (payload.jobType, payload.eventType) match {
                   case ("slug", "creation") => for {
                                                  slug <- EitherT.fromOptionF(
                                                            artefactProcessorConnector.getSlugInfo(payload.serviceName, payload.version),
                                                            s"SlugInfo for name: ${payload.serviceName.asString}, version: ${payload.version.original} was not found"
                                                          )
                                                  _    <- EitherT.right[String](xrayService.firstScan(payload.serviceName, payload.version, slug.uri))
                                                } yield ()
                   case ("slug", "deletion") => EitherT.right[String](rawReportsRepository.delete(payload.serviceName, payload.version))
                   case _                    => EitherT.right[String](Future.unit)
                 }
      _       =  logger.info(s"${prefix(payload)} with ID '${message.messageId()}' successfully processed.")
    } yield
      MessageAction.Delete(message)
    ).fold(
      error  => {logger.error(error); MessageAction.Ignore(message)}
    , action => action
    )
  }
}

object SlugInfoHandler {
  import play.api.libs.json.{Reads, __}
  import play.api.libs.functional.syntax._

  case class SlugEvent(
    jobType    : String,
    eventType  : String,
    serviceName: ServiceName,
    version    : Version,
  )

  val reads: Reads[SlugEvent] =
    ( (__ \ "jobType").read[String]
    ~ (__ \ "type"   ).read[String]
    ~ (__ \ "name"   ).read[ServiceName](ServiceName.format)
    ~ (__ \ "version").read[Version](Version.format)
    )(SlugEvent.apply _)
}
