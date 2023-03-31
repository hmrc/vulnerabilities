import play.sbt.routes.RoutesKeys
import uk.gov.hmrc.DefaultBuildSettings.integrationTestSettings
import uk.gov.hmrc.sbtdistributables.SbtDistributablesPlugin.publishingSettings

lazy val microservice = Project("vulnerabilities", file("."))
  .enablePlugins(play.sbt.PlayScala, SbtDistributablesPlugin)
  .settings(
    majorVersion                     := 0,
    scalaVersion                     := "2.13.8",
    libraryDependencies              ++= AppDependencies.compile ++ AppDependencies.test,
    RoutesKeys.routesImport ++= Seq(
      "uk.gov.hmrc.vulnerabilities.model.Environment",
      "uk.gov.hmrc.vulnerabilities.binders.Binders._"
    )
  )
  .settings(scalacOptions += "-Wconf:src=routes/.*:s")
  .settings(PlayKeys.playDefaultPort := 8857)
  .configs(IntegrationTest)
  .settings(integrationTestSettings(): _*)
  .settings(resolvers += Resolver.jcenterRepo)
  .settings(CodeCoverageSettings.settings: _*)
