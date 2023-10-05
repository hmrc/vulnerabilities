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

package uk.gov.hmrc.vulnerabilities.config

import java.net.URL
import javax.inject.{Inject, Singleton}
import play.api.Configuration

trait SqsConfig {
  def queueUrl           : URL
  def maxNumberOfMessages: Int
  def waitTimeSeconds    : Int
}

@Singleton
class DeploymentSqsConfig @Inject()(configuration: Configuration) extends SqsConfig {
  override lazy val queueUrl           : URL = new URL(configuration.get[String]("aws.sqs.deployment.queueUrl"))
  override lazy val maxNumberOfMessages: Int = configuration.get[Int]("aws.sqs.deployment.maxNumberOfMessages")
  override lazy val waitTimeSeconds    : Int = configuration.get[Int]("aws.sqs.deployment.waitTimeSeconds")
}

@Singleton
class DeploymentDeadLetterSqsConfig @Inject()(configuration: Configuration) extends SqsConfig {
  override lazy val queueUrl           : URL = new URL(configuration.get[String]("aws.sqs.deploymentDeadLetter.queueUrl"))
  override lazy val maxNumberOfMessages: Int = configuration.get[Int]("aws.sqs.deploymentDeadLetter.maxNumberOfMessages")
  override lazy val waitTimeSeconds    : Int = configuration.get[Int]("aws.sqs.deploymentDeadLetter.waitTimeSeconds")
}
