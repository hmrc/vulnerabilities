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

import akka.actor.ActorSystem
import akka.NotUsed
import akka.stream.{ActorAttributes, Materializer, Supervision}
import akka.stream.alpakka.sqs.scaladsl.{SqsAckSink, SqsSource}
import akka.stream.alpakka.sqs.{MessageAction, SqsSourceSettings}
import akka.stream.scaladsl.Source
import cats.data.EitherT
import cats.implicits._
import com.github.matsluni.akkahttpspi.AkkaHttpClient
import play.api.Logging
import play.api.libs.json.{Format, Json}
import software.amazon.awssdk.services.sqs.SqsAsyncClient
import software.amazon.awssdk.services.sqs.model.Message
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.vulnerabilities.config.DeploymentQueueConfig
import uk.gov.hmrc.vulnerabilities.model.{Environment, ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.service.UpdateVulnerabilitiesService

import javax.inject.{Inject, Singleton}
import scala.concurrent.{ExecutionContext, Future}
import scala.util.control.NonFatal
import scala.util.{Failure, Try}

@Singleton
class DeploymentHandler @Inject()(
  config                      : DeploymentQueueConfig,
  updateVulnerabilitiesService: UpdateVulnerabilitiesService
)(implicit
  actorSystem : ActorSystem,
  materializer: Materializer,
  ec          : ExecutionContext
) extends Logging {
  import DeploymentHandler._

  private lazy val queueUrl = config.sqsDeploymentQueue
  private lazy val settings = SqsSourceSettings()

  private implicit val hc = HeaderCarrier()

  private lazy val awsSqsClient =
    Try {
      val client = SqsAsyncClient
        .builder()
        .httpClient(AkkaHttpClient.builder().withActorSystem(actorSystem).build())
        .build()

      actorSystem.registerOnTermination(client.close())
      client
    }.recoverWith {
      case NonFatal(e) => logger.error(s"Failed to set up awsSqsClient: ${e.getMessage}", e); Failure(e)
    }.get

  if (config.isEnabled)
    dedupe(SqsSource(queueUrl.toString, settings)(awsSqsClient))
      .mapAsync(1)(processMessage)
      .withAttributes(ActorAttributes.supervisionStrategy {
        t: Throwable => logger.error(s"Failed to process sqs messages: ${t.getMessage}", t); Supervision.Restart
      })
      .runWith(SqsAckSink(queueUrl.toString)(awsSqsClient))
  else
    logger.warn("DeploymentHandler is disabled.")

  def dedupe(source: Source[Message, NotUsed]): Source[Message, NotUsed] =
    Source.single(Message.builder.messageId("----------").build) // dummy value since the dedupe will ignore the first entry
    .concat(source)
    // are we getting duplicates?
    .sliding(2, 1)
    .mapConcat { case prev +: current +: _=>
        if (prev.messageId == current.messageId) {
          logger.warn(s"Read the same slug message ID twice ${prev.messageId} - ignoring duplicate")
          List.empty
        }
        else List(current)
    }

  private def processMessage(message: Message): Future[MessageAction] = {
    logger.info(s"Starting processing Deployment message with ID '${message.messageId()}'")
    (for {
       payload <- EitherT.fromEither[Future](
                    Json.parse(message.body)
                      .validate(mdtpEventReads)
                      .asEither.left.map(error => s"Could not parse message with ID '${message.messageId()}'.  Reason: " + error.toString)
                  )
       _       <- (payload.eventType, payload.optEnvironment) match {
                    case ("deployment-complete", Some(environment)) =>
                      EitherT.liftF[Future, String, Unit](updateVulnerabilitiesService.updateVulnerabilities(
                          environment = environment.asString,
                          serviceName = payload.serviceName.asString,
                          version     = payload.version.toString
                        ))
                    case (_, None) =>
                      logger.info(s"Not processing message '${message.messageId()}' with unrecognised environment")
                      EitherT.pure[Future, String](())
                    case (eventType, _) =>
                      logger.info(s"Not processing message '${message.messageId()}' with event_type $eventType")
                      EitherT.pure[Future, String](())
                  }
      } yield {
        logger.info(s"Deployment message with ID '${message.messageId()}' successfully processed.")
        MessageAction.Delete(message)
      }
    ).value.map {
      case Left(error)   => logger.error(error)
                            MessageAction.Ignore(message)
      case Right(action) => action
    }
  }
}

object DeploymentHandler {

  private case class DeploymentEvent(
    eventType     : String
  , optEnvironment: Option[Environment]
  , serviceName   : ServiceName
  , version       : Version
  )

  import play.api.libs.functional.syntax._
  import play.api.libs.json.{Reads, __}


  private lazy val mdtpEventReads: Reads[DeploymentEvent] = {
    implicit val er: Reads[Option[Environment]] =
      __.read[String].map(Environment.parse)
    implicit val snf: Format[ServiceName] = ServiceName.format
    implicit val vf: Format[Version] = Version.format

    ( (__ \ "event_type"          ).read[String]
    ~ (__ \ "environment"         ).read[Option[Environment]]
    ~ (__ \ "microservice"        ).read[ServiceName]
    ~ (__ \ "microservice_version").read[Version]
    )(DeploymentEvent.apply _)
  }
}
