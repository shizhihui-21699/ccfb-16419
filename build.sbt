ThisBuild / organization := "com.broker"
ThisBuild / version := "0.1.0"
ThisBuild / scalaVersion := "2.13.16"

lazy val root = (project in file("."))
  .settings(
    name := "fixguard-session",
    Compile / scalacOptions ++= Seq(
      "-deprecation",
      "-feature",
      "-unchecked",
      "-Xlint:unused"
    ),
    // Zero external dependencies: the self-check is a plain JVM main so that
    // `sbt test` works in restricted/offline environments without a test framework.
    Test / test := {
      (Test / runMain).toTask(" com.broker.fixguard.SelfTest").value
    }
  )
