import play.sbt.routes.RoutesKeys

ThisBuild / majorVersion := 0
ThisBuild / scalaVersion := "2.13.12"

lazy val microservice = Project("vulnerabilities", file("."))
  .enablePlugins(play.sbt.PlayScala, SbtDistributablesPlugin)
  .disablePlugins(JUnitXmlReportPlugin)
  .settings(
    libraryDependencies     ++= AppDependencies.compile ++ AppDependencies.test,
    RoutesKeys.routesImport ++= Seq(
      "uk.gov.hmrc.vulnerabilities.model.{CurationStatus, ServiceName, SlugInfoFlag, Version}",
      "uk.gov.hmrc.vulnerabilities.binders.Binders._"
    )
  )
  .settings(scalacOptions += "-Wconf:src=routes/.*:s")
  .settings(PlayKeys.playDefaultPort := 8857)
  .settings(resolvers += Resolver.jcenterRepo)
  .settings(CodeCoverageSettings.settings: _*)

  lazy val it =
  (project in file("it"))
    .enablePlugins(PlayScala)
    .dependsOn(microservice % "test->test")
