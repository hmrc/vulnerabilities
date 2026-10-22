# BDOG-3994: V2 ingestion developer handover

Status: 22 October 2026. Baseline: `BDOG-3994`, `73a6e72` (Checkpoint C), following `3dad61d`.

**Not production-ready. No scan trigger is connected.** The documented JFrog artefact-status transport is implemented, but has not been exercised against HMRC JFrog. Production coverage, initial workflow policy and dependency evidence deliberately return typed unavailable/unverified errors. Tests explicitly inject fixtures; normal configuration cannot select them.

**Known pre-existing exception:** `/v2/team` uses `SampleVulnerabilityData` without an enablement gate. It is unchanged. Do not confuse that response, manually seeded data, or the frontend's own stub with completed ingestion.

## 1. Delivery history and scope

BDOG-3994 extends the existing vulnerability service with V2 scanner findings, service/version evidence, service workflow/history and consumer reads alongside V1. Legacy ingestion, `rawReports`, notifications, token refresh and schedulers remain unchanged.

| Checkpoint | Delivered | Qualification |
|---|---|---|
| A | Mongo-backed Catalogue deployment GET; independent Xray wire connector; pure `XrayFindingMapperV2.map`; reviewed write contract | No ingestion trigger or production policy |
| B | `ScanPublisherV2.admit/publish`, conservative global compatibility, transactional writes/history/receipts and snapshot reads | Live JFrog and production operations not established |
| C | Locally exercised Xray -> mapper -> publisher -> Mongo -> GET, bounded polling and cleanup | Previously used Python coverage metadata and application-level development policy values |
| This cleanup | Real documented artefact-status operation; three explicit providers; versioned/legacy fingerprints; Scala/WireMock fixtures and one embedded-server runner | Replaces C's tooling, not its historical validation evidence; does not implement missing business/coverage rules |

The original ticket is not complete: live contract verification, approved policy/dependency/enrichment, production integration and operational rollout remain. Unsupported findings and global reconciliation are explicitly deferred follow-ups (F1/F2), not permission to drop evidence. Mongo readiness O1 remains outstanding.

The authoritative shared notes are in a separate repository at `../notes/shared/vulnerabilities-backend/`. They were not modified from this backend task. `v2-ingestion-notes-amendments.patch` contains exact proposed amendments, including superseding the old Python instructions and W7/C2-C6 mechanics. Apply/review that patch separately in the notes repository; the older approvals still govern all unchanged contracts.

The proposed patch has been checked, without applying it:

```bash
git -C ../notes/shared apply --check "$PWD/v2-ingestion-notes-amendments.patch"
```

Application paths below are relative to `app/uk/gov/hmrc/vulnerabilities/`.

## 2. Actual call flow

```text
Scan trigger -- NOT YET CONNECTED
    |
    v
VulnerabilityIngestionServiceV2.ingest
    |
    +--> ScanPublisherV2.admit                         Mongo admission/generation
    |
    +--> XrayConnectorV2
    |       generateReport / checkStatus / downloadAndUnzipReport / checkArtifactStatus
    |
    +--> ArtifactCoverageVerifierV2.verify
    |       JfrogArtifactCoverageVerifierV2: CoverageUnverified
    |
    +--> XrayFindingMapperV2.map                        implemented, pure
    |
    +--> DependencyEvidenceServiceV2.importedBy
    |       UnavailableDependencyEvidenceServiceV2: unavailable for nonempty findings
    |
    +--> ScanPublisherV2.publish
    |       |
    |       +--> InitialWorkflowPolicyV2.initialValues  missing workflows only
    |       |       UnavailableInitialWorkflowPolicyV2: WorkflowPolicyUnavailable
    |       |
    |       +--> V2 Mongo transaction: details/evidence/workflow/history/scan/receipt
    |
    +--> XrayConnectorV2.deleteReportFromXray            separate cleanup outcome

V2 Mongo collections
    -> DeploymentStoreV2.read                           single transaction snapshot
    -> DeploymentOccurrencesService.get
    -> VulnerabilitiesController.deploymentOccurrences
    -> Catalogue GET                                   IMPLEMENTED, read-only
```

`Module.bindings` selects the three production implementations explicitly. `v2.ingestion.enabled=false` is the ordinary gate; enabling it does not bypass any provider. No route, notification or scheduler calls `ingest`. There is no V2 HTTP ingestion endpoint.

### Models and ownership boundaries

`model/v2/xray` contains wire DTOs. `model/v2/ingestion` contains validated findings, explicit requests and typed outcomes. `persistence/v2/RecordsV2.scala` contains Mongo projections. `DeploymentOccurrences` is the Catalogue response envelope, not an ingestion input.

The policy uses the existing shared persisted `Priority`, `OccurrenceState` and `DeploymentSla` value types: `ServiceOccurrenceRecordV2` already stores these. `DeploymentSla` is data plus JSON formatting, not a rule calculator. `InitialWorkflowValuesV2` composes them without duplicating SLA fields or constructing frontend responses. Its single `synthetic` flag supplies existing provenance; it is not a new policy framework.

## 3. Execution walkthrough

### Entry, admission and request identity

`VulnerabilityIngestionServiceV2.ingest(IngestScanV2)(ArtifactoryToken)` returns `Future[IngestionOutcomeV2]`. Inputs are an explicit logical `runId`, `ScanContextV2(serviceName, appVersion)`, exact `expectedArtefact` and `WorkflowInitialisationV2`.

The existing accepted scope is an exact `webstore-local/.../filename` without empty/traversal/wildcard segments. It is not normalised or inferred from findings. Application version is distinct from installed dependency version and fixed versions.

The enablement/input checks precede `ScanPublisherV2.admit`. Admission is asynchronous Mongo IO in a transaction. It reserves a per-deployment increasing generation or returns the existing admission for the same run/context. A conflicting run identity rejects before JFrog work.

An admitted record without a receipt is unpublished/retryable, not a durable failed scan. Later failures must not overwrite the last-success scan record.

### Report generation, polling and export

`XrayConnectorV2.generateReport` makes one POST. There is no automatic POST retry. The report name has the `AppSec-v2-report-` prefix. Its existing `*/basename` filter remains: it is **not** proof of full-path scope.

Once a positive report ID exists, orchestration retains it for cleanup regardless of subsequent outcome. `poll` makes at most ten checks, delaying asynchronously through `IngestionPollDelayV2.pause`; it does not sleep a thread. `pending`/`in_progress` continue; `completed` proceeds; `failed`, unknown status and exhaustion have distinct typed failures.

These are retained local-development bounds (`250 milliseconds` by default), not approved production polling policy. Public report documentation also mentions `running`; deployed status vocabulary still needs confirmation rather than an assumed expansion.

`downloadAndUnzipReport` streams the compressed response and limits compressed and expanded bytes separately through `v2.xray.max-export-bytes` (32 MiB). Invalid/multiple/empty archive contents or invalid JSON reject, not an empty-success fallback. Missing `generatedDate` stays absent.

### Artefact status and coverage

`checkArtifactStatus(repo, path)` POSTs `/xray/api/v1/artifact/status` with the supplied repository and repository-relative path, unchanged. Orchestration splits its previously validated full expected path once; it does not prepend the repository again.

The HTTP operation uses the existing `HttpClientV2`, `xray-v2` base URL, bearer token and error conventions. It validates nonblank input. `XrayArtifactStatusV2` decodes required nonblank overall status, optional timestamps and optional SCA details. A supplied malformed SCA/status/time rejects decoding. Unknown strings remain wire data, never a successful verification result. There is no invented report/checksum/correlation field.

Official documentation:

- [Artefact scan status](https://docs.jfrog.com/security/reference/artifact-scan-status)
- [Generate vulnerability report](https://docs.jfrog.com/security/reference/generate-vulnerabilities-report)
- [Report details](https://docs.jfrog.com/security/reference/get-report-details-by-id)

`ArtifactCoverageInputV2` supplies the whole explicit scan request/run, report ID, terminal report details, downloaded report and artefact-status result to `ArtifactCoverageVerifierV2.verify`. That method is synchronous and pure: transport has already happened.

The default `JfrogArtifactCoverageVerifierV2` always returns `CoverageUnverified`, including for `DONE`/`DONE`. HMRC authentication/permissions, full-path scope, correct revision, SCA freshness and report correlation are unverified. `total_artifacts` is documented as scope count, not necessarily processed count. Timestamps or zero rows do not prove freshness or complete scanning.

Do not replace the report filter with documented `include_path_patterns` without validating its semantics against HMRC. Do not add an "assume coverage" flag. Empty reports need approved positive coverage as much as populated reports do.

### Mapping and dependency evidence

After verified completion, pure `XrayFindingMapperV2.map(report, context)` returns either all validation errors or `ScannerFindingsV2`. Maven/GAV-only, strict CVEs, optional per-CVE CVSS, multi-CVE expansion and complete-report rejection remain unchanged. It creates no timestamps, guidance, UUIDs, ownership or policy.

For nonempty findings, `DependencyEvidenceServiceV2.importedBy` is asynchronous, before the publication transaction. The production provider returns `DependencyEvidenceUnavailable`. Empty findings bypass dependency lookup; an empty map then means there are no findings, not that unknown importers were declared absent.

The publisher still distinguishes explicit `CVE -> []`, omitted old evidence and missing new evidence. Do not convert unavailable enrichment into omitted input. The future source/mapping is deliberately not implemented.

### Publication, replay and workflow policy

`ScanPublisherV2.publish(PublishScanV2)` validates completion and input bounds. It fixes one millisecond-precision server publication time and allocates candidate occurrence UUIDs outside transaction retries. Neither changes during a retried publication operation.

The transaction first loads the admitted run and checks an existing receipt/digest. A compatible committed replay returns its receipt before invoking policy or modifying data, even after a newer generation has published. Changed payloads reject.

For a new publication, it checks generation supersession, reads the affected details/evidence/workflows in one snapshot and prepares the write plan. Incompatible global component/summary/fix/supplied-score evidence rejects the whole publication. Unprovenanced existing data requires explicit adoption.

Only missing workflows reach `InitialWorkflowPolicyV2.initialValues(InitialWorkflowContextV2)`, and only with explicit `UsePolicy` intent. `ExistingOnly` rejects missing workflow creation. The pure policy context supplies the finding, scan context and stable observation time. No network/async/clock work belongs inside this method.

The production policy returns `WorkflowPolicyUnavailable`. Existing workflows, committed receipts and empty reports need no initial policy. A failure aborts publication atomically; admission may remain. First detection, UUIDs, human workflow, guidance and separately owned enrichment are not regenerated/overwritten.

Writes and actual change history, success metadata and receipt commit together. Mongo errors are not all proof of rollback: `StorageFailure(..., commitMayHaveSucceeded=true)` requires reconciliation with the same run and compatible validated payload.

### Futures, cleanup and output

`flatMap` is used when the next operation itself returns a `Future` (HTTP, Mongo, asynchronous provider or delay). `map` transforms an already completed value, such as interpreting a provider's `Either`. Pure mapper/policy/verifier decisions do not require another independent IO layer.

The internal stopped-error control flow preserves typed ingestion/publication failures across this chain. Unexpected failures remain failures, not fixture selection or successful empty output.

After obtaining a report ID, success or failure leads to `deleteReportFromXray` for **that exact ID only**. `IngestionOutcomeV2` contains the primary result and independent `ReportCleanupV2`. Cleanup failure cannot imply rollback of committed Mongo data or replace an earlier report/mapping failure.

There is no durable upstream-report recovery. Re-running ingestion can create a new report; a durable receipt is not permission to accept a newly changed payload under an old logical identity. Production retry/report ownership still needs design.

## 4. Mongo ownership and compatibility

| Collection | Owner/data | Unique key |
|---|---|---|
| `vulnerabilities_v2` | Global scanner details, references/revision; separately owned guidance/enrichment preserved | `vuln_id` |
| `vulnerability_occurrences_v2` | Exact service/application-version scanner evidence, installed component version, imported-by and source observation | `vuln_id, service, service_version` |
| `service_occurrences_v2` | Stable service workflow/UUID, insert-only first detection, priority/state/SLA; existing decisions preserved | `vuln_id, service`; separately `occurrence_id` |
| `scan_records_v2` | Latest successful publication for one deployment | `service_name, service_version` |
| `vulnerability_history_v2` | Actual technical detail creation/change events | `event_id` |
| `occurrence_history_v2` | Actual service workflow creation events | `event_id` |
| `scan_attempts_v2` | Additional admission/generation, digest/version, committed receipt/evidence diff | `run_id`; separately `service_name, service_version, generation` |

The first six collection identities predate attempt tracking. This cleanup changes no collection names, unique keys or indexes. No dependency on legacy Mongo or `rawReports` is introduced.

`MongoTransactionsV2` uses snapshot read concern, majority write concern and primary reads. `DeploymentStoreV2.read` joins scan/evidence/details/workflows in one transaction snapshot. GET returns 404 for no successful scan, or 200 with `results: []` for a verified successful empty deployment. It never initiates ingestion.

Only exact-version evidence is replaced/removed. Shared global vulnerability and service workflow records are not deleted or resolved because one version no longer reports a CVE. Targeted writes preserve unmodelled guidance, enrichment and workflow fields. Concurrent admissions/publications use existing uniqueness, retry and revision/snapshot protection.

### Fingerprint formats and receipts

`ScanPublicationFingerprintV2` defines both formats:

- **Historical:** missing `fingerprint_version` means the original SHA-256 payload from `73a6e72`, including original field order, Mongo observation encoding and `"SyntheticSeed"` / `"ExistingOnly"` labels. `UsePolicy` maps to that old creation-intent label solely when checking a historical receipt. It cannot create fixture values.
- **Version 2:** SHA-256 of compact JSON `{"format":2,"payload":...}` with recursively lexicographically sorted object keys; finding order sorted by CVE. Intent tags are explicitly `configured-policy` and `existing-only`, not Scala `toString`. Imported-by lookup is keyed by CVE, independent of map iteration.

Both retain run, service/application version, intent, generated timestamp, finding ID/installed version, complete scanner observation and explicit-versus-omitted imported-by evidence. Existing array order remains significant where it was before; this is not new set canonicalisation. Completion assertions must validate as true; policy output/config/processing clock are not newly included in the request digest.

New receipts add only optional `fingerprint_version=2`, set atomically with digest/receipt. Old committed records are neither rewritten nor accepted unconditionally. Unsupported future versions reject explicitly. This is forward read/replay compatibility, not a guarantee that an old binary can replay newly versioned digests.

`HistoricalPublicationV1` in test support freezes the old algorithm independently of the new codec. Its regression hash for the committed multi-CVE JSON fixture and fixed test request was calculated by executing that old algorithm: `23dc615031227d59cdd30a7e59c50bbd3c1aaf2b23714e17cbb835a53dcbb407`.

Existing synthetic workflow/history markers remain untouched. New creation markers derive from the policy result's `synthetic` value; they are not hardcoded true or inferred from the initialisation enum. No existing history is relabelled.

## 5. Outstanding implementation points

All listed production blockers remain outstanding; completing this cleanup does not approve their rules.

| Requirement | Current class/method | Current behaviour | Required information/decision | How to implement it | Tests to extend | Disposition |
|---|---|---|---|---|---|---|
| Real HMRC status contract | `XrayConnectorV2.checkArtifactStatus` | Documented HTTP operation only | Endpoint/version, bearer acceptance, permissions, response/status vocabulary | Validate authorised sanitised HMRC responses; update separate wire DTO/tests if needed | `XrayConnectorV2ISpec` | Production blocker |
| Exact full-path/report scope | `generateReport`, `ArtifactCoverageVerifierV2.verify` | Basename filter; verification rejects | Exact path/filter semantics, include-path support | Establish approved scope evidence, without guessing from basenames | Connector/provider/ingestion specs | Production blocker |
| Revision, freshness and report correlation | `JfrogArtifactCoverageVerifierV2.verify` | `CoverageUnverified`, even DONE/DONE | SCA freshness, intended revision, completed export correlation | Replace rejection only with verified semantics and negative-path tests | `IngestionProvidersV2Spec`, ingestion IT | Production blocker |
| Safe empty publication | Same verifier | Zero rows alone never authorise it | Positive complete-artefact proof and count meanings | Reuse `ScanCompletionV2`; test failed/incomplete/stale empty scans | Provider/ingestion/publisher IT | Production blocker |
| Initial priority/state | `UnavailableInitialWorkflowPolicyV2.initialValues` | `WorkflowPolicyUnavailable` | Approved rules and authoritative inputs | Pure deterministic calculation, missing workflows only | Provider/publisher specs | Production blocker |
| SLA calculation | Same policy, existing `DeploymentSla` | No production duration/start/pause/breach/near-breach rules | Business ownership, timing inputs and rules | Construct the existing data value using stable supplied observation time; no clock per retry | Provider/publisher specs | Production blocker |
| Dependency source and identity | `UnavailableDependencyEvidenceServiceV2.importedBy` | Typed unavailable for nonempty findings | Authoritative repo/source, GAV and Scala suffix matching | Likely `ArtefactProcessorConnector.getMetaArtefact -> dependencyDotCompile -> DependencyGraphParser -> ImportedDependencyV2` | Provider/graph/ingestion specs | Production blocker |
| Importer meaning and missing data | Same provider | No guessed/empty fallback | Multiple importers, direct/transitive semantics, scopes, incomplete metadata, freshness/replacement | Approved mapping outside Mongo transaction; do not copy V1 JAR fallback/one-shortest-path defaults | Provider/publisher/ingestion specs | Production blocker |
| Shared token lifecycle | V2 caller; V1 `XrayService.withToken/refreshToken` | Explicit V2 token, unchanged encrypted V1 management | Refresh ownership and sharing | Integrate safely without competing refresh or calling private V1 methods | Connector/token/legacy regressions | Production blocker |
| Report cleanup ownership/recovery | Ingestion cleanup; V1 `getStaleReportIds/deleteStaleReports` | Own-ID cleanup only; no durable upstream recovery | Legacy author-based cleanup coexistence, retry/recovery | Coordinate ownership before enabling live reports; name prefix alone is insufficient | Ingestion/legacy tests | Production blocker |
| Stable notification identity/build scans | `SlugInfoHandler`, future trusted ingestion caller | V1 only; V2 not connected | Logical run identity, duplicates, desired triggers and admission semantics | Separately approved integration; no new HTTP endpoint required by this cleanup | Notification/ingestion/replay tests | Production blocker |
| Scheduled V2 rescans | Existing scheduler area | Legacy only | Cadence, selection, concurrency and policy | Separately approved V2 trigger using the same private boundary | Scheduler/order tests | Production blocker |
| Mongo operations and retention | `MongoTransactionsV2`, repositories | Local snapshot/majority tests pass; guardrails only | O1 topology, load, transaction budgets, failover/uncertainty, attempt/history retention | Operational verification and approved retention; do not drop history | Concurrency/load/failover tests | Production blocker O1 |
| Enrichment/adoption/migration | Publisher preservation/adoption guards | Preserve enrichment/user data; reject unprovenanced records | Sources/ownership, EPSS/KEV/team/exposure and migration provenance | Approved enrichment/adoption path; never infer from Xray vectors/project keys | Preservation/adoption tests | Production blocker |
| Consumer APIs/guidance/rollout | Existing Catalogue GET; other V2 APIs | Catalogue read implemented; `/v2/team` sample-backed | Frontend API, trusted guidance writes, cutover, rollback and rollout plan | Separate consumer implementation plus full regression/load sign-off | HTTP/consumer/system tests | Remaining delivery |
| Unsupported findings | `XrayFindingMapperV2.map` | Complete-report rejection | F1 non-Maven/non-CVE/multi-component requirements and observed frequency | Separate ticket; no dropping rows or fabricated identity | Mapper/representative data | Deferred F1; no ticket ID assigned |
| Global CVE reconciliation | `ScanPublisherV2.prepare` | Conservative conflict rejection | F2 source precedence/reconciliation | Separate ticket; no last-writer-wins overwrite | Publisher conflict/concurrency tests | Deferred F2; no ticket ID assigned |

## 6. Tests and reproduction

### Prerequisites

Use the installed SDKMAN setup; do not upgrade tools. `build.sbt` pins Scala **3.3.6**, `project/build.properties` pins sbt **1.10.10**. Validation used **Java 21.0.6-tem**; there is no repository Java/SDKMAN version file. The shell's default Java 11 is not the validated toolchain.

```bash
cd /Users/nick/Dev/platops/vulnerabilities
source "$HOME/.sdkman/bin/sdkman-init.sh"
sdk use java 21.0.6-tem
sbt compile
```

Mongo-backed tests/demo require an existing writable replica-set Mongo with sessions/snapshot transactions on local port 27017 (locally `rs0`). Do not start/stop or reset a shared Mongo instance to make tests pass. The integration test harness uses suite-specific test databases. Only the demonstration database intentionally remains.

### Exact suite commands

```bash
sbt "testOnly *XrayFindingMapperV2Spec"
sbt "it/testOnly *XrayConnectorV2ISpec"
sbt "testOnly *IngestionProvidersV2Spec *ScanPublicationFingerprintV2Spec"
sbt "testOnly *VulnerabilityIngestionServiceV2Spec"
sbt "it/testOnly *ScanPublisherV2ISpec"
sbt "it/testOnly *DeploymentOccurrencesControllerISpec"
sbt "testOnly *XrayConnectorSpec *XrayServiceSpec"
sbt "it/testOnly *VulnerabilityIngestionV2ISpec"
sbt compile test it/test
```

Mapper/fingerprint/provider tests are pure or use explicit fixtures; orchestration units mock HTTP/publisher/delay. Connector IT uses actual HTTP and WireMock, not live JFrog. Publisher/GET IT uses real local Mongo transactions. Ingestion IT combines WireMock, real connector/mapper/publisher/Mongo and actual HTTP Catalogue GET.

The full 22 October invocation `sbt compile test it/test` passed **234 unit tests (16 suites)** and **170 integration tests (5 suites)**, with no failed/cancelled/ignored/pending tests. Initial Scala test syntax/body-reader errors were corrected before this final run; none are waived. This does not establish live HMRC compatibility or production load/failover behaviour.

The old 243 focused Scala plus five Python results are historical, not a current test-count target. Python behaviours now live in Scala: distinct IDs/exact deletion/other-report survival, wrong requested artefact, positive controlled empty coverage, raw rows versus expanded CVEs, and unknown-report rejection. Marker/proprietary-HTTP self-tests were retired with that protocol, not preserved as fake JFrog contracts.

Historical digest replay/rejection, versioned receipts, unchanged history, unavailable-policy replay and a forced aborted transaction retry are covered in `ScanPublisherV2ISpec`; ordering and rollback/uncertain-commit/snapshot regressions remain. The legacy 11-row ZIP remains a parser test and a mapper unsupported-ID regression, not a successful ingestion fixture.

### Self-contained local demonstration

One runner remains: `it/Test/runMain uk.gov.hmrc.vulnerabilities.VulnerabilityIngestionV2ManualCheck`.

It starts loopback WireMock on a dynamic port, supplies dummy credentials and explicitly binds controlled coverage, workflow and dependency fixtures. It uses the real publisher. It checks writable replica-set status and an actual snapshot transaction, ensures existing indexes, and closes its application/WireMock resources on exit. It neither starts a Catalogue HTTP server nor selects fixture providers for ordinary startup.

The strict URI guard allows only a credential-free single-loopback `mongodb://` URI, exact `directConnection=true`, and explicit database `vulnerabilities_bdog3994_ingestion` or a suffixed name. Remote/SRV/ordinary application databases are rejected before connecting. There is no database reset.

Choose an unused isolated suffix; the example below is a developer fixture database, never production:

```bash
sbt "it/Test/runMain uk.gov.hmrc.vulnerabilities.VulnerabilityIngestionV2ManualCheck --mongo-uri mongodb://127.0.0.1:27017/vulnerabilities_bdog3994_ingestion_demo?directConnection=true --service example-service --version 1.8.0 --artefact webstore-local/example-service/example-service_1.8.0_0.5.2.tgz --scenario populated"
```

Repeat that command changing `--scenario`:

| Scenario | Expected typed outcome |
|---|---|
| `populated` | Published one fixture CVE; report deleted |
| `repeat` | Two populated publications; established identity/workflow retained (asserted in IT) |
| `empty` | Verified controlled zero-row publication; no dependency values invented |
| `failed` | `ReportFailed`; previous success preserved |
| `missing-coverage` | `CoverageRejected`; no controlled proof supplied |
| `missing-policy` | `PublicationRejected(WorkflowPolicyUnavailable)`; use a fresh isolated database without existing service workflows |
| `missing-dependencies` | `DependencyEvidenceUnavailable`; not confirmed empty |
| `cleanup-failed` | Published data remains; separate `failed-warning` cleanup |

Expected negative scenarios assert their typed failure and exit successfully as developer checks; unexpected outcomes exit nonzero. Output always says `"testFixtures":true`. `--run-id` optionally supplies explicit stable run identity; never reuse one for a different payload. `--imported-by-file` optionally loads an explicit JSON fixture map; unknown data is never filled with `[]`.

To see failure preserve a populated response: run populated, read/save GET, run failed or missing-coverage, and compare GET. Use a fresh database for missing-policy: an existing workflow correctly bypasses initial policy. Equivalent exact behaviour is asserted in the ingestion IT, so the runner does not duplicate that assertion suite.

All eight scenarios were executed after refactoring; repeat was also executed after the initial populated run. Local databases used were `vulnerabilities_bdog3994_ingestion_boundary_978e1693` and separate `vulnerabilities_bdog3994_ingestion_policy_978e1693`. They are explicitly synthetic demonstration data, not migration/adoption inputs. A temporary normal application against the former database returned populated Catalogue HTTP 200 and never-successful HTTP 404 with ingestion disabled; that check server was stopped.

### Read the demonstration through the unchanged Catalogue endpoint

In a separate terminal using the same isolated database and SDKMAN JDK:

```bash
sbt "-Dmongodb.uri=mongodb://127.0.0.1:27017/vulnerabilities_bdog3994_ingestion_demo?directConnection=true" \
  -Daws.sqs.enabled=false -Dxray.enabled=false -Dv2.ingestion.enabled=false \
  'run 18861'
```

Leave legacy scheduler defaults disabled. Read:

```bash
curl --fail-with-body -sS \
  http://127.0.0.1:18861/vulnerabilities/api/v2/services/example-service/app-versions/1.8.0/occurrences
```

Expect 200, `scanStatus: "succeeded"`, one CVE after populated, or 200 with empty results after empty. A never-successful service/version returns 404. `lastSuccessfulScan` is publisher operation time, not Xray source time. UUID/workflow/first detection remain stable across populated/empty/repopulate, as integration tests assert.

Stop only your own read server when finished. The runner stops its own HTTP/application resources; shared Mongo and deliberately retained fixture data are not removed.

## 7. Handover boundaries

No live HMRC calls, production trigger, scheduled V2 rescan, policy calculation, graph interpretation, consumer cutover or legacy rewrite was performed. Production imported-by enrichment and workflow initialisation remain deliberately unavailable. HTTP success is not coverage.

The existing `/v2/team` sample behaviour and other frontend/guidance API work remain separate. Full production Mongo topology/capacity/failover/load verification is still O1. F1/F2 have no assigned ticket IDs in the shared register.

Before declaring BDOG-3994 complete, review every blocker in section 5, obtain the missing contracts/rules, extend the exact methods named there, and repeat operational/consumer sign-off. Passing controlled fixture tests is evidence of the implementation boundaries, not approval to enable production ingestion.
