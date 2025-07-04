import play.sbt.routes.RoutesKeys
import uk.gov.hmrc.DefaultBuildSettings

ThisBuild / majorVersion  := 0
ThisBuild / scalaVersion  := "3.3.6"
ThisBuild / scalacOptions += "-Wconf:msg=Flag.*repeatedly:s"

lazy val microservice = Project("vulnerabilities", file("."))
  .enablePlugins(PlayScala, SbtDistributablesPlugin)
  .disablePlugins(JUnitXmlReportPlugin)
  .settings(
    libraryDependencies     ++= AppDependencies.compile ++ AppDependencies.test,
    RoutesKeys.routesImport ++= Seq(
      "uk.gov.hmrc.vulnerabilities.binders.Binders.given"
    , "uk.gov.hmrc.vulnerabilities.model.{CurationStatus, DigitalService, ServiceName, TeamName, SlugInfoFlag, Version}"
    ),
    scalacOptions += "-Wconf:src=routes/.*:s"
  )
  .settings(PlayKeys.playDefaultPort := 8857)
  .settings(CodeCoverageSettings.settings: _*)

lazy val it =
  (project in file("it"))
    .enablePlugins(PlayScala)
    .dependsOn(microservice % "test->test")
    .settings(DefaultBuildSettings.itSettings())
