package uk.gov.hmrc.vulnerabilities.persistence

import com.mongodb.client.model.Indexes
import org.mongodb.scala.model.{IndexModel, IndexOptions}
import uk.gov.hmrc.mongo.MongoComponent
import uk.gov.hmrc.mongo.play.json.PlayMongoRepository
import uk.gov.hmrc.vulnerabilities.model.ServiceVulnerability

import javax.inject.{Inject, Singleton}
import scala.concurrent.ExecutionContext

@Singleton
class VulnerabilitiesTimelineRepository @Inject()(
                                      mongoComponent: MongoComponent,
                                    )(implicit ec: ExecutionContext
                                    ) extends PlayMongoRepository(
  collectionName = "vulnerabilitiesTimeline",
  mongoComponent = mongoComponent,
  domainFormat   = ServiceVulnerability.mongoFormat,
  indexes        = Seq(
    IndexModel(Indexes.descending("weekBeginning", "service", "issue"), IndexOptions().unique(true))
  )
)
{

}