import play.core.PlayVersion
import play.sbt.PlayImport._
import sbt.Keys.libraryDependencies
import sbt._

object AppDependencies {

  private val bootstrapPlayVersion = "9.5.0"
  private val hmrcMongoPlayVersion = "2.2.0"

  val compile = Seq(
    caffeine,
    "uk.gov.hmrc"             %% "bootstrap-backend-play-30"  % bootstrapPlayVersion,
    "uk.gov.hmrc.mongo"       %% "hmrc-mongo-play-30"         % hmrcMongoPlayVersion,
    "org.typelevel"           %% "cats-core"                  % "2.10.0",
    "software.amazon.awssdk"  %  "sqs"                        % "2.20.155",
  )

  val test = Seq(
    "uk.gov.hmrc"             %% "bootstrap-test-play-30"     % bootstrapPlayVersion  % Test,
    "uk.gov.hmrc.mongo"       %% "hmrc-mongo-test-play-30"    % hmrcMongoPlayVersion  % Test,
  )
}
