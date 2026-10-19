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

package uk.gov.hmrc.vulnerabilities

import org.apache.pekko.actor.ActorSystem
import org.apache.pekko.pattern.after
import org.apache.pekko.stream.Materializer
import play.api.Configuration
import play.api.inject.guice.GuiceApplicationBuilder
import play.api.libs.json.Json
import play.api.routing.Router.Routes
import play.api.routing.SimpleRouter
import uk.gov.hmrc.crypto.Sensitive.SensitiveString
import uk.gov.hmrc.http.HeaderCarrier
import uk.gov.hmrc.http.client.HttpClientV2
import uk.gov.hmrc.mongo.play.PlayMongoModule
import uk.gov.hmrc.play.bootstrap.config.ServicesConfig
import uk.gov.hmrc.vulnerabilities.connector.XrayConnectorV2
import uk.gov.hmrc.vulnerabilities.model.{ArtifactoryToken, ServiceName, Version}
import uk.gov.hmrc.vulnerabilities.model.v2.xray.XrayReport.ReportStatus
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.concurrent.duration.*

final class XrayConnectorV2ManualRouter extends SimpleRouter:
  override def routes: Routes = PartialFunction.empty

object XrayConnectorV2ManualCheck:
  def main(args: Array[String]): Unit =
    require(args.length <= 1, "Usage: XrayConnectorV2ManualCheck [local-stub-port]")
    val port = args.headOption.map(_.toInt).getOrElse(18090)
    require(port >= 1 && port <= 65535, "Local stub port must be between 1 and 65535")
    val config = Configuration.from(Map(
      "microservice.services.xray-v2.protocol" -> "http",
      "microservice.services.xray-v2.host" -> "127.0.0.1",
      "microservice.services.xray-v2.port" -> port,
      "v2.xray.max-export-bytes" -> 33554432
    ))
    val app = GuiceApplicationBuilder()
      .disable[Module]
      .disable[PlayMongoModule]
      .configure("play.http.router" -> classOf[XrayConnectorV2ManualRouter].getName)
      .build()

    try
      given ExecutionContext = app.injector.instanceOf[ActorSystem].dispatcher
      given Materializer = app.injector.instanceOf[Materializer]
      given HeaderCarrier = HeaderCarrier()
      val system = app.injector.instanceOf[ActorSystem]
      val client = XrayConnectorV2(ServicesConfig(config), app.injector.instanceOf[HttpClientV2], config)
      val token = ArtifactoryToken(SensitiveString("dummy-v2-access-token"), SensitiveString("unused"))
      val service = ServiceName("example-service")
      val version = Version("1.8.0")
      println(s"SYNTHETIC connector check against 127.0.0.1:$port; no Mongo or live JFrog access.")
      val request = Await.result(
        client.generateReport(service, version, "webstore-local/example-service/example-service_1.8.0_0.5.2.tgz")(token),
        15.seconds
      )
      println(s"Created synthetic report ${request.reportId}: ${request.status}")

      def poll(remaining: Int): Future[ReportStatus] =
        client.checkStatus(request.reportId)(token).flatMap: status =>
          println(s"Report status: ${status.status}; rows=${status.numberOfRows}; artefacts=${status.totalArtefacts}")
          status.status match
            case "completed" => Future.successful(status)
            case "pending" | "in_progress" if remaining > 1 =>
              after(250.millis, system.scheduler)(poll(remaining - 1))
            case "pending" | "in_progress" =>
              Future.failed(IllegalStateException("Local report did not complete within 10 status checks"))
            case other =>
              Future.failed(IllegalStateException(s"Local report did not complete: $other"))

      try
        Await.result(poll(10), 30.seconds)
        val report = Await.result(client.downloadAndUnzipReport(request.reportId, service, version)(token), 15.seconds)
        println(s"Parsed ${report.rows.size} synthetic finding(s):")
        println(Json.prettyPrint(Json.toJson(report)))
      finally
        Await.result(client.deleteReportFromXray(request.reportId)(token), 15.seconds)
        println(s"Deleted synthetic report ${request.reportId}")
    finally
      Await.result(app.stop(), 15.seconds)
