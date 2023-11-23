import play.core.PlayVersion
import play.sbt.PlayImport._
import sbt.Keys.libraryDependencies
import sbt._

object AppDependencies {

  private val bootstrapPlayVersion = "7.22.0"
  private val hmrcMongoPlayVersion = "1.5.0"

  val compile = Seq(
    "uk.gov.hmrc"             %% "bootstrap-backend-play-28"  % bootstrapPlayVersion,
    "uk.gov.hmrc.mongo"       %% "hmrc-mongo-play-28"         % hmrcMongoPlayVersion,
    "org.typelevel"           %% "cats-core"                  % "2.9.0",
    "software.amazon.awssdk"  %  "sqs"                        % "2.20.155",
  )

  val test = Seq(
    "uk.gov.hmrc"             %% "bootstrap-test-play-28"     % bootstrapPlayVersion  % Test,
    "uk.gov.hmrc.mongo"       %% "hmrc-mongo-test-play-28"    % hmrcMongoPlayVersion  % Test,
    "org.mockito"             %% "mockito-scala-scalatest"    % "1.17.12"             % Test
  )
}
