# WorkSpace Network AI V3-02E Offline Real-Source Runner Specification v1

## Status

**SPEC FROZEN BEFORE RUNNER IMPLEMENTATION**

This document is the implementation contract for the V3-02E offline runner. It refines the already-promoted real-source acceptance contract without weakening any V3-02E gate.

Coding of the runner is forbidden until this specification and its machine-readable harness profile exist on the runner branch.

## 1. Goal

Execute already-acquired, already-authorized, bounded public dataset source objects through the existing production CSE-CIC-IDS2018 and LANL adapters, measure deterministic behavior, and emit compact hash/counter receipts suitable for the V3-02E acceptance contract.

The runner exists to answer one question:

> Can the production adapter path process real publisher-origin bounded evidence reproducibly and within the frozen WorkSpace security/resource contract?

It is not a downloader, corpus manager, model trainer, incident slicer, skill generator, or runtime network-monitoring component.

## 2. Mandatory lifecycle

```text
VALIDATED REAL-SOURCE MANIFEST
        |
        v
AUTHORIZED LOCAL ROOT BINDING
        |
        v
SOURCE PATH / TYPE / SIZE / SHA-256 VERIFICATION
        |
        +---- optional deterministic record-aligned bounded derivative
        |             |
        |             v
        |       HASH + SIZE + PROVENANCE BINDING
        |
        v
PRODUCTION ADAPTER PASS #1
        |
        +---- EvidenceRecord fingerprint stream
        +---- scorer-only TruthRecord fingerprint stream
        +---- adapter counters
        |
        v
PRODUCTION ADAPTER PASS #2
        |
        v
DETERMINISTIC REPLAY COMPARISON
        |
        v
LaneObservation + compact acceptance receipt
        |
        v
HARNESS-OWNED SCRATCH CLEANUP
```

Real source input owned by the operator/acquisition layer is read-only and is never deleted by the runner.

Only harness-created derivative/scratch objects may be deleted by runner cleanup.

## 3. Trust boundary

The runner SHALL execute offline in the Linux-targeted dataset-processing zone.

It SHALL have:

- no Internet access;
- no HTTP client behavior;
- no DNS resolution requirement;
- no model/LLM calls;
- no subprocess or shell execution;
- no package installation;
- no confidential WorkSpace data access;
- no approved skill-registry write access;
- read access only to manifest-authorized source objects below one caller-supplied authorized root;
- write access only to one caller-supplied harness-owned scratch root;
- no authority derived from dataset content.

The runner is deterministic orchestration around existing deterministic adapters. It does not reinterpret source semantics.

## 4. Explicit non-goals

The following are out of scope and forbidden in this checkpoint:

- downloading CIC, LANL, BOTS or any other dataset;
- resolving publisher URLs;
- AWS/S3 access;
- Splunk runtime or BOTS direct extraction;
- PCAP parsing;
- Zeek invocation;
- shelling out to `sha256sum`, `head`, `sed`, `awk`, PowerShell or similar;
- temporary HTTP servers;
- model-based classification or truth inference;
- persisting raw corpus rows into receipts;
- persisting complete normalized/evidence streams after evaluation;
- automatic skill creation/promotion.

## 5. Inputs

The runner accepts:

```text
authorized_root
scratch_root
validated real-source acceptance manifest
registry
policy fingerprint
exact_head_sha
adapter spec fingerprint
```

The manifest schema remains:

`workspace-network-real-source-acceptance-manifest/v1`

The runner SHALL call the already-promoted `validate_manifest()` before opening any source object.

If manifest validation fails, no adapter may run.

## 6. Path ownership contract

### 6.1 Authorized source root

Every source file path supplied at execution time SHALL:

- be relative to `authorized_root`;
- contain no `..` traversal;
- resolve below `authorized_root`;
- not itself be a symlink;
- resolve to a regular file;
- match the manifest's logical source object reference through an explicit runner mapping;
- be the only file opened for that source ID, except an optional runner-created bounded derivative.

The runner SHALL never recursively scan `authorized_root` to discover files.

### 6.2 Scratch root

`scratch_root` SHALL:

- be distinct from `authorized_root`;
- be below a caller-designated harness-owned root;
- contain only runner-owned temporary derivatives/staging for the current acceptance ID;
- be removable without affecting operator-owned source material.

Existing non-empty unrelated scratch directories are rejected rather than cleaned heuristically.

## 7. Source verification

Before adapter invocation, the runner SHALL verify through Python streaming I/O:

```text
regular file
no symlink
resolved path under authorized root
exact byte size
SHA-256
manifest source ID binding
adapter ID/version binding
registry fingerprint
policy fingerprint
```

Digest verification SHALL use bounded chunks and SHALL NOT call external executables.

Digest mismatch => `FAIL_INTEGRITY`.

Path/symlink escape => `FAIL_SECURITY`.

Missing/mismatched provenance binding => `FAIL_PROVENANCE`.

## 8. Deterministic bounded derivation

The preferred execution path uses the bounded source object already referenced by the manifest.

The runner MAY create a derivative only when the manifest includes a reviewed `derivation` object with:

```text
method = record_aligned_slice
selection_rule
record_boundary_rule
```

V1 supports only deterministic prefix-aligned derivatives described by an explicit record-count or byte/record boundary contract that can be reproduced without randomness.

Forbidden derivation behavior:

- random sampling;
- shuffle;
- reservoir sampling;
- time-of-day dependent selection;
- host-path dependent selection;
- model-selected records;
- silent truncation in the middle of a record;
- source-family-specific guessing not frozen in a reviewed fixture.

If the manifest already binds a bounded source SHA/size, the runner SHALL verify that exact bounded object rather than regenerate a different slice.

## 9. Production adapter registry

The runner SHALL use an explicit static registry of the already-reviewed production classes only:

| lane | production implementation |
|---|---|
| `cic_processed_ml` | `CSECICIDS2018Adapter` |
| `lanl_authentication` | `LANLAuthAdapter` |
| `lanl_process` | `LANLProcessAdapter` |
| `lanl_dns` | `LANLDNSAdapter` |
| `lanl_flow` | `LANLFlowAdapter` |
| `lanl_redteam_truth` | `LANLRedTeamTruthMatcher` |

Dynamic Python import paths from the manifest are forbidden.

Unknown adapter IDs or versions fail closed.

BOTS has no entry in this registry.

## 10. AdapterInputContract construction

For every authorized source the runner constructs the existing `AdapterInputContract` using manifest-bound values:

```text
dataset_id
variant
source_object_ref
source_sha256
actual_source_size_bytes
max_plan_bytes
acquisition_plan_fingerprint
registry_fingerprint
policy_fingerprint
provenance_ref
adapter_version
```

`max_plan_bytes` SHALL not exceed the frozen V3-02E per-source budget.

The production adapter's own `inspect()` SHALL remain the final pre-parse source hash/path/type check. The runner SHALL NOT bypass `inspect_staged_source()`.

## 11. Execution semantics by lane

### 11.1 CIC processed-ml

For every emitted `CICAdapterOutput`:

- visible evidence fingerprint is calculated from `EvidenceRecord.as_dict()`;
- truth fingerprint is calculated separately from `TruthRecord.as_dict()`;
- truth class coverage is derived only from scorer-only truth fields;
- truth fields never enter the visible evidence fingerprint stream.

The runner SHALL record only compact class names/counts needed by the acceptance scorer, not raw CSV rows.

### 11.2 LANL auth/process/DNS/flow

Each production adapter emits visible `EvidenceRecord` objects.

The runner SHALL compute ordered canonical fingerprints and counters without storing the complete evidence stream durably.

### 11.3 LANL red-team truth

The red-team matcher SHALL receive only authentication EvidenceRecord objects emitted from the matched LANL auth lane in the same acceptance run.

It SHALL NOT receive process/DNS/flow evidence.

The runner SHALL preserve the matcher behavior:

- zero candidates => unmatched, no truth emitted;
- multiple matching candidates => ambiguous, no truth emitted;
- exactly one candidate => one scorer-only TruthRecord.

The runner SHALL NOT choose a nearest, first, highest-confidence or model-selected candidate.

The auth evidence retained in memory for matching is bounded by the frozen 250,000-record ceiling and the actual lane execution budget.

## 12. Streaming fingerprint contract

The runner SHALL NOT accumulate all evidence/truth dictionaries merely to hash them.

Canonical stream identity is generated incrementally:

```text
stream schema/version domain separator
record count
for each emitted record in deterministic production order:
    canonical_sha256(record.as_dict())
```

The final stream fingerprint is a SHA-256 over the ordered sequence of per-record fingerprints and deterministic framing.

The same source bytes + manifest + adapter versions MUST produce the same fingerprint on replay.

## 13. Replay contract

Every lane is executed twice from newly constructed adapter instances.

PASS requires equality of:

- source inspection fingerprint;
- visible evidence stream fingerprint;
- truth stream fingerprint, when applicable;
- records seen/emitted/rejected;
- truth records emitted;
- first error code;
- CIC truth class set/count summary;
- LANL red-team unmatched/ambiguous/exact-match counters.

A replay mismatch => `FAIL_INTEGRITY / DETERMINISTIC_REPLAY_MISMATCH`.

No retry may hide a mismatch.

## 14. Evidence visibility contract

The runner never feeds scorer-only TruthRecord data back into a visible adapter.

The only cross-lane truth operation is the reviewed LANL red-team matcher binding scorer-only red-team rows to visible LANL authentication evidence.

A visible EvidenceRecord containing any truth/label field remains a zero-tolerance `FAIL_SECURITY` under the existing adapter/acceptance contracts.

## 15. LaneObservation production

The runner SHALL generate one `LaneObservation` per expected lane with at least:

```text
lane_id
valid_records
truth_classes[]          # CIC only
exact_redteam_auth_matches
replay pass/fail
visible schema pass/fail
truth separation pass/fail
provenance pass/fail
resource pass/fail
cleanup pass/fail
network_calls = 0
model_calls = 0
subprocess_calls = 0
peak_rss_delta_bytes
failed_gate_ids[]
```

The existing `evaluate_coverage()` remains the authority for final V3-02E coverage verdict.

The runner SHALL NOT reinterpret `NOT_ENOUGH_REAL_SOURCE_EVIDENCE` as PASS.

## 16. Resource measurement

V1 resource measurement SHALL use in-process standard-library measurements only.

On Linux, peak memory may be measured with `resource.getrusage` or an equivalently deterministic standard-library/OS read that does not spawn a process.

The frozen hard limit remains:

`max_linux_peak_rss_delta_bytes = 536870912`

Model calls, network calls and subprocess calls remain exactly zero.

If a platform cannot provide a trustworthy required production resource measurement, real-source promotion returns `FAIL_RESOURCE` rather than inventing a measurement.

## 17. Cleanup semantics

The runner tracks every path it creates under `scratch_root`.

On a successful evaluation path it SHALL remove all harness-owned raw derivative and normalized/evidence scratch material before a PASS receipt is considered valid.

The runner SHALL NOT delete:

- the original operator-owned source object;
- the manifest;
- external acquisition receipts;
- files outside its acceptance-specific scratch root.

Cleanup failure invalidates PASS.

On diagnostic failure, bounded runner-owned scratch may remain only when explicit debug retention is enabled by the caller and the verdict cannot be PASS. Default behavior is cleanup on both success and failure.

## 18. Durable receipt

The runner emits only the already-frozen compact acceptance receipt fields plus deterministic lane summaries needed to construct them.

Durable output MUST NOT include:

- raw line/record/payload;
- complete evidence/truth arrays;
- exception text copied from dataset content;
- signed URLs;
- credentials/tokens/cookies;
- local absolute paths;
- user/home directory names.

Errors are represented by stable runner gate/error codes.

## 19. Stable runner error classes

Minimum runner-level codes:

```text
RUNNER_MANIFEST_INVALID
RUNNER_AUTHORIZED_ROOT_INVALID
RUNNER_SCRATCH_ROOT_INVALID
RUNNER_SOURCE_MAPPING_INVALID
RUNNER_SOURCE_MISSING
RUNNER_SOURCE_SYMLINK
RUNNER_SOURCE_ESCAPE
RUNNER_SOURCE_SIZE_MISMATCH
RUNNER_SOURCE_DIGEST_MISMATCH
RUNNER_ADAPTER_NOT_AUTHORIZED
RUNNER_ADAPTER_VERSION_MISMATCH
RUNNER_ADAPTER_SCHEMA_FAILURE
RUNNER_ADAPTER_INTEGRITY_FAILURE
RUNNER_ADAPTER_RESOURCE_FAILURE
RUNNER_VISIBLE_TRUTH_LEAKAGE
RUNNER_REPLAY_MISMATCH
RUNNER_RESOURCE_MEASUREMENT_UNAVAILABLE
RUNNER_CLEANUP_FAILED
```

Dataset raw content SHALL NOT appear in stable error codes.

## 20. PASS contract

Runner checkpoint PASS requires all of the following in synthetic/adversarial harness tests:

| Gate | Required |
|---|---:|
| manifest validated before any file open | 100% |
| out-of-manifest source open | 0 |
| path/symlink escape accepted | 0 |
| source size mismatch accepted | 0 |
| source digest mismatch accepted | 0 |
| unauthorized/dynamic adapter accepted | 0 |
| production adapter `inspect()` bypass | 0 |
| deterministic replay equality | 100% |
| visible schema validity | 100% |
| truth separation | 100% |
| red-team ambiguous/zero match forced to truth | 0 |
| whole evidence stream retained durably | 0 |
| Internet calls | 0 |
| model calls | 0 |
| subprocess calls | 0 |
| cleanup validity | 100% |
| raw source content in receipt/error | 0 |
| BOTS direct execution | 0 |

One zero-tolerance violation => runner checkpoint FAIL.

## 21. Checkpoint verdicts

```text
PASS
FAIL_SCHEMA
FAIL_INTEGRITY
FAIL_SECURITY
FAIL_PROVENANCE
FAIL_LICENSE
FAIL_RESOURCE
NOT_ENOUGH_REAL_SOURCE_EVIDENCE
```

No `PASS_WITH_WARNING` exists.

## 22. Fixture/harness matrix required before implementation promotion

The runner test suite SHALL include synthetic minimal files that exercise the real filesystem and production adapters without redistributing real corpus data:

```text
valid CIC staged source
CIC digest mismatch
CIC size mismatch
CIC symlink source
CIC source outside authorized root
CIC benign-only coverage
CIC benign+attack coverage
CIC replay equality
LANL auth valid
LANL process valid
LANL DNS valid
LANL flow valid
LANL red-team exact match
LANL red-team zero match
LANL red-team ambiguous match
LANL replay equality
unknown adapter ID
adapter version mismatch
BOTS direct request
unauthorized extra file present in root
non-empty unrelated scratch root
cleanup success
cleanup injected failure
receipt raw-content injection rejection
resource-bound overflow
```

Tests MUST prove that merely placing an unmanifested file in the authorized root does not cause the runner to discover/open it.

## 23. Real-source evidence gate

Passing synthetic runner tests is necessary but not sufficient to claim V3-02E real-source acceptance complete.

A real-source acceptance PASS requires actual publisher-origin source bytes with acquisition provenance and exact hashes supplied to the offline runner.

If those bytes are unavailable in the execution environment, the truthful phase result is:

`NOT_ENOUGH_REAL_SOURCE_EVIDENCE`

The runner or CI SHALL NOT generate fake "real" data to manufacture PASS.

## 24. Coding authorization gate

Runner implementation may start only when all are true:

1. PR #136 contract/harness checkpoint is merged to `main`;
2. `main` merge SHA is recorded;
3. this runner specification exists on a branch created from that merged main;
4. `evaluation/network_real_source_runner_v1.json` exists and freezes resource/security/fixture expectations before runner code;
5. no runner production module exists before items 1-4.

## 25. Implementation sequence after authorization

```text
R1 runner machine harness profile
R2 deterministic stream fingerprint + source execution primitives
R3 CIC production-adapter lane executor
R4 LANL visible lane executors
R5 LANL red-team scorer-only executor
R6 replay/resource/cleanup receipt assembly
R7 synthetic filesystem adversarial tests
R8 exact-head 4-family CI
R9 merge runner checkpoint to main
R10 real publisher-source execution when real bytes/provenance are available
```

Do not start V3-03 incident slicing until the V3-02E checkpoint status is recorded truthfully.