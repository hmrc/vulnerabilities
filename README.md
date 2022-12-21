
# vulnerabilities

This service provides information about the Vulnerabilities that affect services deployed on the platform. 

It only provides information for services deployed in the following environments: Production, ExternalTest, Staging and QA. 

# How the data gets updated

## Collections

There are 3 collections:

* **`RawReports`:** This contains raw vulnerability reports for a unique Service and Version (e.g. hello-world-stub_0.39.0). Each report contains all the known vulnerabilities that are present in that service version.
* **`VulnerabilitySummaries`:** This is what rawReports are eventually transformed into. Each document contains details about a unique vulnerability (e.g. XRAY-00001), as well as a list of all the different service versions affected by it on the platform. This is the collection consumed by the Vulnerabilities page in Catalogue Frontend.
* **`Assessments`:** This collection contains AppSec's assessment of each unqiue vulnerability, and whether it requires further action/investigation. It is currently updated manually (See the Surfacing Vulnerabilities Process Document), but will be automated following the addition of an admin frontend for the service. 

## Scheduler

A scheduler runs every `scheduler.interval` hours, and checks whether the most recent `generatedDate` in the VulnerabilitySummaries collection is older than `data.refresh-cutoff` days. It only attempts to update the data if this is true.

Alternatively, the process can be triggered manually by hitting the following endpoint: `vulnerabilities/api/vulnerabilities/admin/reload `

## End-to-end process

* Interrogates releases-api to get current deployments, and transforms them to a list of unique services & version (`ServiceVersionDeployments`).
* Filters out any `ServiceVersionDeployments` that have a report < 7 days old in the `rawReportsRepository`, so we don't attempt to download them again. This is so that we don't have to repeat the entire process if it falls over due to a transient error, so it will pick up where it left off on the next run.
* For each filtered `ServiceVersionDeployments`:
  * A payload will be generated to create a Vulnerabilities report in the Xray UI
  * Check if the report is ready for download from Xray
  * Attempt to download the zipped report if its ready to download & contains data
  * Delete the report from Xray (as it can only store 100 reports at any one time.)
  * unzip the report - each report is given a `generatedDate` field upon being parsed by the model. 
  * Insert the report into the rawReports collection
  * If, after `maxRetries` attempts to generate a report and wait for it to be ready, the report is still not ready to be downloaded. This indicates an issue on the Xray side, so the process will quit with an exception, and retry in 3 hours time.  
* We then transform raw reports into Vulnerability Summaries (only those less than `data.refresh-cutoff` days old, in order to prevent duplicates).
* We add Teams, environments and assessments to the VulnerabilitySummaries, creating our final summaries.
* Finally, we use a Mongo transaction to delete the current summaries in `vulnerabilitySummaries`, and add the new Summaries that we have just generated. 
### License

This code is open source software licensed under the [Apache 2.0 License]("http://www.apache.org/licenses/LICENSE-2.0.html").