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
import cats.implicits._

import software.amazon.awssdk.services.sqs.model.Message

import org.apache.pekko.actor.ActorSystem
import play.api.Configuration
import play.api.libs.json.Json
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.vulnerabilities.model.{ServiceName, SlugInfoFlag, Version}
import uk.gov.hmrc.vulnerabilities.service.XrayService
import uk.gov.hmrc.vulnerabilities.persistence.RawReportsRepository

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}

@Singleton
class DeploymentHandler @Inject()(
  configuration       : Configuration
, rawReportsRepository: RawReportsRepository
, xrayService         : XrayService
)(implicit
  actorSystem: ActorSystem,
  ec         : ExecutionContext
) extends SqsConsumer(
  name   = "Deployment"
, config = SqsConfig("aws.sqs.deployment", configuration)
)(actorSystem, ec) {

  private implicit val hc: HeaderCarrier = HeaderCarrier()

  private def prefix(payload: DeploymentHandler.DeploymentEvent) =
    s"Deployment (${payload.eventType}) ${payload.serviceName.asString} ${payload.version.original} ${payload.environment.asString}"

  override protected def processMessage(message: Message): Future[MessageAction] = {
    logger.debug(s"Starting processing Deployment message with ID '${message.messageId()}'")
    (for {
      payload <- EitherT
                   .fromEither[Future](Json.parse(message.body).validate(DeploymentHandler.mdtpEventReads).asEither)
                   .leftMap(error => s"Could not parse Deployment message with ID '${message.messageId()}'. Reason: $error")
       _      <- payload.eventType match {
                   case "deployment-complete"   => for {
                                                     exists <- EitherT.right[String](rawReportsRepository.exists(payload.serviceName, payload.version))
                                                     _      <- if (exists) EitherT.right[String](rawReportsRepository.setFlag(payload.environment, payload.serviceName, payload.version))
                                                               else        EitherT.right[String](xrayService.firstScan(payload.serviceName, payload.version, Some(payload.environment)))
                                                   } yield ()
                   case "undeployment-complete" => EitherT.right[String](rawReportsRepository.clearFlag(payload.environment, payload.serviceName))
                   case _                       => EitherT.right[String](Future.unit)
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

object DeploymentHandler {

  private case class DeploymentEvent(
    eventType  : String
  , environment: SlugInfoFlag
  , serviceName: ServiceName
  , version    : Version
  )

  import play.api.libs.functional.syntax._
  import play.api.libs.json.{Reads, __}

  private lazy val mdtpEventReads: Reads[DeploymentEvent] =
    ( (__ \ "event_type"          ).read[String]
    ~ (__ \ "environment"         ).read[SlugInfoFlag](SlugInfoFlag.format)
    ~ (__ \ "microservice"        ).read[ServiceName](ServiceName.format)
    ~ (__ \ "microservice_version").read[Version](Version.format)
    )(DeploymentEvent.apply _)
}
