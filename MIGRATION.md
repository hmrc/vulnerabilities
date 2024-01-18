# Migration Guide

## Populate vulnerabilityAge using the existing rawReports collection:

```javascript
db.getCollection("rawReports").aggregate([
    {
        $unwind: {
            path: "$rows"
        }
    },
    {
        $unwind: {
            path: "$rows.cves"
        }
    },
    {
        $project: {
            "service": {
                $arrayElemAt: [
                    { $split: ["$rows.path", "/"] },
                    2
                ]
            },
            "vulnerabilityId": {
                $ifNull: ["$rows.cves.cve", "$rows.issue_id"]
            },
            "firstScanned": "$rows.artifact_scan_time"
        }
    },
    {
        $group: {
            _id: {
                "service": "$service",
                "vulnerabilityId": "$vulnerabilityId"
            },
            firstScanned: {
                $min: "$firstScanned"
            }
        }
    },
    {
        $project: {
            _id: 0,
            "service": "$_id.service",
            "vulnerabilityId": "$_id.vulnerabilityId",
            "firstScanned": "$firstScanned"
        }
    },
    {
        $out: "vulnerabilityAge"
    }
])
```

## Populate service name and version on the existing rawReports collection:

```javascript
db.rawReports.find({}).forEach(function(rawReport){
    if (rawReport.rows.length > 0 && rawReport.rows[0].path) {
        let pathSegments = rawReport.rows[0].path.split("/");
        let [serviceName, serviceVersion, _] = pathSegments[pathSegments.length - 1].replace(".tgz", "").split("_")
        db.rawReports.updateOne({_id : rawReport._id}, {$set : {serviceName:  serviceName, serviceVersion: serviceVersion}})
    }
})
```