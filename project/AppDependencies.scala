import play.core.PlayVersion
import play.sbt.PlayImport._
import sbt.Keys.libraryDependencies
import sbt._

object AppDependencies {

  val compile = Seq(
    "uk.gov.hmrc"             %% "bootstrap-backend-play-28"  % "7.1.0",
    "uk.gov.hmrc.mongo"       %% "hmrc-mongo-play-28"         % "0.71.0",
    "org.typelevel"           %% "cats-core"                  % "2.6.1"
  )

  val test = Seq(
    "uk.gov.hmrc"             %% "bootstrap-test-play-28"     % "7.1.0"             % "test, it",
    "uk.gov.hmrc.mongo"       %% "hmrc-mongo-test-play-28"    % "0.71.0"            % Test,
    "com.vladsch.flexmark"    %  "flexmark-all"               % "0.36.8"            % "test, it",
    "org.mockito"             %% "mockito-scala-scalatest"    % "1.16.46"           % Test,
    "uk.gov.hmrc"             %% "service-integration-test"   % "1.3.0-play-28"     % "test,it"
  )
}
