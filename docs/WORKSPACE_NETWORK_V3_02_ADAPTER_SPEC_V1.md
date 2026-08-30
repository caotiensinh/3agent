# WorkSpace Network AI V3-02 Corpus Adapter Specification v1

## Status

**SPEC FROZEN BEFORE V3-02 IMPLEMENTATION**

V3-02 may not start coding until V3-01 exact-head CI is fully green.

This specification defines the objective, trust boundary, adapter harness, canonical output, per-corpus behavior and PASS/FAIL gates for the first approved public corpus adapters.

## 1. Objective

Convert bounded, already-acquired public dataset shards into deterministic compact evidence records suitable for incident slicing and specialist evaluation.

Adapters are **not downloaders**, **not model calls**, **not durable log stores**, and **not skill generators**.

```text
APPROVED STAGED OBJECT
        |
        v
TYPE/HASH/BOUND CHECK
        |
        v
CORPUS ADAPTER
        |
        +------ visible observations ------> evidence staging
        |
        +------ labels / answer truth ------> scorer-only truth staging
        |
        v
PROVENANCE RECEIPT
```

The critical rule is that dataset labels and answer keys never enter specialist-visible evidence.

## 2. Authorized corpora

V3-02 production-adapter scope is limited to registry entries with `enterprise_approved` status:

1. `cse-cic-ids2018`
2. `lanl-comprehensive`
3. `splunk-bots-v2`

Research-only or review-required sources are not accepted by these adapters for enterprise extraction.

## 3. Trust and execution boundary

Adapters run in the future offline `workspace-dataset` processing zone.

They SHALL have:

- no Internet access;
- no confidential WorkSpace data access;
- read-only access to the exact staged source object(s) authorized by an acquisition plan;
- write access only to bounded normalized/evidence staging and scorer-only truth staging;
- no access to the approved skill registry;
- no shell/network authority obtained from dataset content.

Dataset bytes are untrusted data.

## 4. Platform scope

The acquisition/processing service is Linux-targeted in V1 because its deployment contract uses Linux service identities, `/var/...` storage roots, systemd hardening and nftables.

The corpus manifest, hidden-truth boundary, evidence schemas and scorer contracts remain host-independent and continue to be unit-tested on supported Python platforms.

Windows deployment CI must not reinterpret Linux deployment roots using Windows path semantics as a product failure; Windows still executes cross-platform harness/security tests.

## 5. Adapter interface

Every adapter SHALL implement the semantic interface:

```text
inspect(source, plan, provenance) -> AdapterInspection
iterate(source, inspection) -> EvidenceRecord stream + TruthRecord stream
receipt() -> AdapterReceipt
```

Implementation naming may differ, but semantics may not.

No adapter may require loading the complete source file into RAM.

## 6. Input contract

Required before parsing:

```text
dataset_id
variant
source_object_ref
source_sha256
actual_source_size_bytes
acquisition_plan_fingerprint
registry_fingerprint
policy_fingerprint
license/provenance reference
adapter version
```

The adapter must reject input when:

- dataset ID does not match adapter;
- source SHA-256 does not match the supplied verified digest;
- source is outside the authorized staged root;
- source is a symlink or resolves outside the authorized staging root;
- source exceeds the bounded job plan;
- variant is not allowed for the requested purpose;
- required provenance is missing.

## 7. Canonical visible EvidenceRecord

Minimum schema:

```text
schema_version = workspace-network-evidence-record/v1
evidence_id
dataset_id
source_domain
source_object_ref
source_sha256
record_ordinal
timestamp | interval_start+interval_end
asset_refs[]
account_refs[]
network_refs[]
event_family
event_type
observation_fields{}
provenance_ref
```

Rules:

- `evidence_id` is deterministic from source hash + adapter version + record ordinal/canonical content;
- records contain observations, not answers;
- no dataset attack label, red-team flag, expected root cause, answer key or remediation truth may appear in visible records;
- arbitrary raw line text is not a required durable field;
- unknown fields are dropped or placed only in a bounded reviewed namespace; never copied wholesale.

## 8. Scorer-only TruthRecord

When the source provides labels/ground truth, the adapter may emit a separate scorer-only object:

```text
schema_version = workspace-network-truth-record/v1
truth_id
evidence_refs[]
truth_class
truth_fields{}
source_object_ref
source_sha256
provenance_ref
```

Truth records must be physically/logically separated from specialist-visible evidence staging.

A dataset without reliable truth may emit no TruthRecord; lack of truth must not be replaced with model inference.

## 9. Determinism

For identical:

```text
source bytes
adapter version
registry/policy fingerprints
adapter configuration
```

outputs must have identical canonical evidence/truth fingerprints, independent of wall-clock execution time or host OS path formatting.

Runtime timestamps belong only in receipts and are excluded from content identity.

## 10. Streaming/resource contract

Initial hard limits:

- no whole-file `read()` for corpus payloads;
- bounded line/record buffers;
- default emitted visible records per invocation: <= 250,000 unless plan explicitly lowers it;
- no adapter-created object may exceed 1 MiB;
- malformed-record examples retained only as bounded metadata/counts, not bulk raw data;
- model calls: 0;
- Internet calls: 0;
- package installation: 0.

Peak-RAM acceptance is measured in V3-02 fixtures; a candidate that scales peak RAM linearly with total source size fails the streaming contract.

## 11. Malformed-data policy

Adapters fail closed on structural uncertainty that can alter semantic interpretation.

Receipt counters:

```text
records_seen
records_emitted
truth_records_emitted
records_skipped_benign
records_malformed
records_rejected
first_error_code
```

No raw exception/string from untrusted dataset content enters durable audit metadata.

For fixtures and promoted extraction jobs:

- unknown required schema/column layout -> FAIL_SCHEMA;
- invalid required timestamp -> record rejected;
- truncated compressed stream -> FAIL_INTEGRITY;
- source digest mismatch -> FAIL_INTEGRITY;
- label leakage into visible evidence -> FAIL_SECURITY;
- parser silently guessing incompatible schema -> FAIL_SCHEMA.

## 12. CSE-CIC-IDS2018 adapter

### Preferred V3 input

`processed-ml` CSV shards.

### Visible evidence

Use flow observations such as timestamps, endpoints/ports/protocol when present, duration, packet/byte counters and reviewed flow features necessary for later evidence pattern extraction.

### Hidden truth

Attack/benign labels are scorer-only.

The label column must be removed before visible EvidenceRecord construction.

### Explicit non-goal

Raw PCAP parsing is not required for first V3-02 PASS. A packet-level adapter is a separate reviewed task.

### CIC fatal failures

- label appears in visible evidence;
- CSV column drift is guessed rather than rejected/mapped by reviewed schema;
- numeric parse failure silently becomes zero;
- flow identity depends on host-local path.

## 13. LANL Comprehensive adapter

### Input families

Bounded shards/streams from:

- authentication;
- process;
- DNS;
- network flow;
- red-team ground truth.

### Visible evidence

Authentication/process/DNS/flow observations are emitted as separate evidence domains with deterministic entity references and timestamps.

### Hidden truth

Red-team ground-truth records are scorer-only and must never be merged into specialist-visible events.

### Correlation rule

V3-02 performs parsing and entity/time normalization only. Cross-source attack-chain correlation belongs to later incident slicing/pattern stages.

### LANL fatal failures

- red-team truth exposed to specialist-visible records;
- source family confused without explicit schema mapping;
- missing/invalid timestamp silently synthesized;
- account/host/process identifiers accidentally treated as instructions or authority.

## 14. Splunk BOTS v2 adapter

BOTS v2 is high-value but its pre-indexed archive format can create a heavy Splunk dependency.

V3-02 therefore has a **feasibility gate before implementation**.

Allowed outcomes:

1. `SUPPORTED_LIGHTWEIGHT` — deterministic bounded extraction from an officially supplied or reproducibly exported structured representation without adding a heavy production dependency; or
2. `BLOCKED_DEPENDENCY_COST` — evidence shows reliable extraction would require Splunk or another heavy runtime that violates the WorkSpace lean baseline.

The adapter must never fake support by interpreting opaque pre-indexed bytes heuristically.

If an offline conversion tool is evaluated, it must be isolated to the dataset-processing zone and separately reviewed for license, dependency, resource and supply-chain cost.

BOTS labels/answer keys remain scorer-only.

## 15. Adapter harness

Each adapter is tested with:

```text
valid minimal fixture
valid multi-record fixture
malformed record fixture
truncated/integrity fixture
schema-drift fixture
label-leakage fixture
path/symlink escape fixture
oversize/budget fixture
determinism replay fixture
```

Fixtures are synthetic/minimal where redistribution of source bytes is unnecessary.

Real source validation later uses recorded source hashes and bounded sampled shards without committing large datasets to Git.

## 16. Shared PASS criteria

An adapter candidate passes only if all are true:

| Gate | PASS |
|---|---:|
| deterministic fixture replay | 100% identical |
| visible output schema validity | 100% |
| evidence ID uniqueness within case/source | 100% |
| source/provenance binding | 100% |
| hidden-label leakage | 0 |
| out-of-plan source reads | 0 |
| Internet/model calls | 0 |
| raw exception/content in receipt | 0 |
| silent required-field coercion | 0 |
| source digest mismatch accepted | 0 |
| truncated integrity failure accepted | 0 |
| path/symlink escape accepted | 0 |
| whole-file corpus buffering | 0 |

One violation of a zero-tolerance gate => adapter FAIL regardless of record throughput.

## 17. Adapter verdicts

```text
PASS
FAIL_SCHEMA
FAIL_INTEGRITY
FAIL_SECURITY
FAIL_PROVENANCE
FAIL_LICENSE
FAIL_RESOURCE
BLOCKED_DEPENDENCY_COST
NOT_ENOUGH_REAL_SOURCE_EVIDENCE
```

No `PASS_WITH_WARNING` is valid for promoted extraction.

## 18. Evidence receipt

Every adapter test/evaluation receipt records:

```text
exact_head_sha
adapter_id
adapter_version
adapter_spec_sha256
fixture_or_source_manifest_sha256
source_sha256
registry_fingerprint
policy_fingerprint
records_seen/emitted/rejected
truth_records_emitted
determinism result
zero-tolerance gate results
resource measurements
verdict
failed_gate_ids
```

## 19. Coding authorization

V3-02 code may begin only after:

1. V3-01 exact-head `harness-ci` PASS;
2. V3-01 exact-head `installer-ci` PASS;
3. V3-01 exact-head `portable-deploy-ci` PASS;
4. V3-01 exact-head `windows-deploy-ci` PASS;
5. this V3-02 spec exists before the first adapter implementation commit.

After authorization, implementation order is:

```text
V3-02A canonical evidence/truth schemas + adapter base harness
V3-02B CSE-CIC-IDS2018 processed CSV adapter
V3-02C LANL multi-source adapters
V3-02D BOTS v2 feasibility gate
V3-02E real bounded-source evidence + exact-head CI
```

Do not start model training or the multi-skill coordinator in V3-02.
