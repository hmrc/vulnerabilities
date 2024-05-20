
# vulnerabilities

This service provides information about the Vulnerabilities that affect services deployed on the platform.

It only provides information for services deployed in the following environments: Production, ExternalTest, Staging and QA.

# How the data gets updated

## Collections

There are 3 collections:

* **`assessments`:** contains AppSec's assessment of each unqiue vulnerability, and whether it requires further action/investigation. Updated manually via `connect-mongo` Nix command in `platops-infrastructure`.
* **`rawReports`:** Xray report of a slug. Each report has flags that are updated when a slug is deployed into a new environment or the latest version
* **`vulnerabilityAge`:** Stores when a vulnerability was first detected per service
* **`vulnerabilityTimeline`:** Point in time summaries, updated by a timeline scheduler. The data is used in Catalogue to graph trend on a weekly basis.

## Scheduler

A re-scan scheduler runs every `scheduler.rescan.interval`. Processing a stale reports (before `scheduler.rescan.stale-report`) for a service version that is either deployed or the latest.

## End-to-end Xray process

* For each report:
  * A payload will be generated to create a Vulnerabilities report in the Xray UI
  * Check if the report is ready for download from Xray
  * Attempt to download the zipped report if its ready to download & contains data
  * Delete the report from Xray (as it can only store 100 reports at any one time.)
  * unzip the report - each report is given a `generatedDate` field upon being parsed by the model.
  * Insert the report into the rawReports collection
  * If, after `maxRetries` attempts to generate a report and wait for it to be ready, the report is still not ready to be downloaded. This indicates an issue on the Xray side, so the process will quit with an exception, and retry in 3 hours time.

### License

This code is open source software licensed under the [Apache 2.0 License]("http://www.apache.org/licenses/LICENSE-2.0.html").
