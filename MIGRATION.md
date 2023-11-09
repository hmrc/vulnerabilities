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