# Migration Guide

## Add scanned status

```javascript
db.rawReports.updateMany({}, [
    {$set: {"scanned": {$gt: [{$size: "$rows"}, 0]}}},
    {$set: {"slugUri": {$concat:["https://artefacts.tax.service.gov.uk/artifactory/webstore/slugs/", "$serviceName", "/", "$serviceName", "_",  "$serviceVersion", "_0.5.2.tgz"]}}}
])
```

## Add deployment flags

```javascript
// stop the vulnerabilities task
db.rawReports.aggregate([{ $out: "rawReports-bk" }])

// Removes duplicates - Takes it down from 783624 to 20423
db.getCollection('rawReports').aggregate([
{ $group: {_id: {"serviceName": "$serviceName", "serviceVersion": "$serviceVersion" }, "last": { $last: "$$ROOT" } } },
{ $unwind: "$last"},
{ $replaceRoot: { newRoot: "$last" }},
{ $out: "rawReports" }
], { allowDiskUse: true })

// Add default flags for missing deployments - shouldn't be any
db.rawReports.updateMany({}, [
    {$set: {
        "latest":       false,
        "production":   false,
        "integration":  false,
        "qa":           false,
        "externaltest": false,
        "staging":      false,
        "development":  false
    }}
])

// Add deployments flags to raw reports
use service-dependencies
db.deployments.find({$or: [{"latest": true},{"production": true},{"integration": true},{"qa": true},{"external test": true},{"staging": true},{"development": true}]}).forEach(d => {
    db.getSiblingDB('vulnerabilities')['rawReports'].updateOne({"serviceName": d.name, "serviceVersion": d.version}, [{$set: {"latest": d.latest, "production": d.production, "integration": d.integration, "qa": d.qa, "externaltest": d['external test'], "staging": d.staging, "development": d.development}}])
})
```

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
