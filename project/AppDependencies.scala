import play.core.PlayVersion
import play.sbt.PlayImport._
import sbt.Keys.libraryDependencies
import sbt._

object AppDependencies {

  private val bootstrapPlayVersion = "7.21.0"
  private val hmrcMongoPlayVersion = "1.3.0"
  private val alpakkaVersion       = "4.0.0"

  val compile = Seq(
    "uk.gov.hmrc"             %% "bootstrap-backend-play-28"  % bootstrapPlayVersion,
    "uk.gov.hmrc.mongo"       %% "hmrc-mongo-play-28"         % hmrcMongoPlayVersion,
    "org.typelevel"           %% "cats-core"                  % "2.8.0",
    "com.lightbend.akka"      %% "akka-stream-alpakka-sns"    % alpakkaVersion,
    "com.lightbend.akka"      %% "akka-stream-alpakka-sqs"    % alpakkaVersion
  )

  val test = Seq(
    "uk.gov.hmrc"             %% "bootstrap-test-play-28"     % bootstrapPlayVersion  % "test, it",
    "uk.gov.hmrc.mongo"       %% "hmrc-mongo-test-play-28"    % hmrcMongoPlayVersion  % "test, it",
    "org.mockito"             %% "mockito-scala-scalatest"    % "1.17.12"             % Test
  )
}
