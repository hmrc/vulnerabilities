
# vulnerabilities

This service provides information about the Vulnerabilities that affect services deployed on the platform.

It only provides information for services deployed in the following environments: Production, ExternalTest, Staging and QA.

## V2 ingestion

V2 is an isolated, transactional ingestion path. It is disabled by default and has no connected production trigger. The existing V1 schedulers and endpoints are unchanged.

### Data model

V2 separates scanner observations from service workflow decisions:

* Xray findings provide scanner evidence.
* Global vulnerability details are stored independently from deployment evidence.
* Application-version evidence records the component, imported-by data and scanner observation.
* Service-level occurrences own workflow State, Priority and SLA.
* Scan metadata, publication receipts and technical/workflow history are persisted separately.

The V2 MongoDB collections are:

| Collection | Purpose |
| --- | --- |
| `vulnerabilities_v2` | Global vulnerability details |
| `vulnerability_occurrences_v2` | Service/application-version evidence |
| `service_occurrences_v2` | Service-level State, Priority and SLA |
| `scan_records_v2` | Last successful scan |
| `scan_attempts_v2` | Run identity, generation, fingerprint and receipt |
| `vulnerability_history_v2` | Technical vulnerability history |
| `occurrence_history_v2` | Workflow and occurrence history |

### Ingestion flow

```text
Ingestion trigger
  -> admit runId
  -> request Xray vulnerability report
  -> poll and download
  -> verify artefact coverage
  -> validate/map findings
  -> obtain dependency evidence
  -> publish to MongoDB transactionally
  -> clean up temporary Xray report
```

The production trigger is not connected and Xray scanning currently occurs independently. `/v2/team` remains sample-backed; its behaviour is unchanged and is not evidence of Mongo ingestion or production policy.

### Current workflow placeholders

New service occurrences are initialised with:

* State `actionable`
* Priority `monitor`
* SLA `deadline = None`, `breached = false`, `nearBreach = false`, with all optional status and clock fields unset

Existing State, Priority and SLA survive rescans. A valid incoming CVSS score replaces the stored technical score, including when it decreases. A confirmed numeric CVSS increase reopens the current service occurrence by resetting State to `actionable`. Both the previous and new CVSS values must be present, and the new value must be greater; missing scores are never treated as zero. Equal scores, decreases, newly known scores and changes to other technical evidence do not reopen an occurrence. Empty successful scans do not resolve workflows.

These are temporary placeholders, not remediation or SLA assessments. Priority calculation, SLA calculation and manual State-management endpoints belong to future tickets and this branch must not be used as production remediation policy.

### Current limitations

* `v2.ingestion.enabled` remains `false` by default.
* Production JFrog coverage verification is not implemented.
* Production imported-by/dependency evidence is outstanding.
* Build and scheduled V2 ingestion triggers are unconnected.
* Manual workflow update endpoints are not part of V2 yet.
* Cross-service CVSS reassessment policy is not yet defined; reopening is limited to the service occurrence being processed.
* Existing V1 schedulers and endpoints remain unchanged.

The controlled WireMock tests use test fixtures and do not verify behaviour against live HMRC JFrog.

### Running tests

Unit tests can be run with:

```bash
sbt compile
sbt "testOnly *IngestionProvidersV2Spec *ScanPublicationFingerprintV2Spec"
```

Mongo-backed integration tests require a local transaction-capable MongoDB replica set:

```bash
sbt "it/testOnly *ScanPublisherV2ISpec"
sbt "it/testOnly *VulnerabilityIngestionV2ISpec"
sbt compile test it/test
```

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

## Manually triggered re-scan

A re-scan of all services that are `latest` or deployed in an environment can be manually triggered via the `POST   /vulnerabilities/admin/rescan` endpoint.

## Testing

# Test external source - EPSS and KEV
The EPSS is scores for vulnerabilities that are used to determine the likelihood of exploitation. The KEV is a list of known exploited vulnerabilities.
To test the services download of these external sources a test-only endpoint can be used locally.
```
GET localhost:8057/test-only/vuln-updates?limit=100&offset=0
```
This will give a summary with a sample of the updated likelihood score / percentile from EPSS and whether the vulnerability is in the KEV list.
Limit and offset can be used to page through the results, if not specified the default is 100 and 0 respectively.


### License

This code is open source software licensed under the [Apache 2.0 License]("http://www.apache.org/licenses/LICENSE-2.0.html").
