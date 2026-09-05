# WorkSpace Network AI V3-02E Real-Source Acceptance Specification v1

## Status

**CONTRACT FROZEN BEFORE V3-02E HARNESS / IMPLEMENTATION**

V3-02E is the final acceptance gate for the V3-02 corpus-adapter phase. It exists to prove that the already-tested CIC and LANL adapters behave correctly on bounded bytes that originate from the real publisher datasets, without turning WorkSpace or Git into a raw-log warehouse.

The mandatory development order remains:

```text
GOAL
  -> SPEC
  -> HARNESS
  -> PASS / FAIL CONTRACT
  -> REAL-SOURCE MANIFEST EXPECTATIONS
  -> ACCEPTANCE CODE
  -> TEST
  -> REVIEW
  -> MAIN CHECKPOINT
```

No V3-02E acceptance-runner implementation may be added before this specification is committed.

---

## 1. Goal

Prove, using bounded real publisher-origin source material, that WorkSpace can deterministically transform the approved CIC and LANL corpora into compact evidence/truth artifacts while preserving all V3-02 security, provenance, resource and cleanup boundaries.

V3-02E SHALL answer these questions with evidence:

1. Did the tested bytes originate from an enterprise-approved publisher source recorded in the dataset registry?
2. Are source identity and lineage cryptographically bound to the acceptance receipt?
3. Does the production adapter parse the real source schema without guessing or synthetic-only assumptions?
4. Are labels/ground truth physically and logically separated from specialist-visible evidence?
5. Is deterministic replay identical for the same source bytes and adapter/configuration fingerprints?
6. Does bounded execution stay within the resource contract?
7. Are harness-owned raw/normalized working copies removed after the acceptance run?
8. Can a later reviewer reproduce exactly what was accepted without storing the raw corpus in Git?

V3-02E is **not model training**, **not incident slicing**, **not skill extraction**, **not a downloader**, and **not a reason to retain public raw logs durably**.

---

## 2. Scope

### In scope

Only these real-source acceptance lanes are authorized:

- `cse-cic-ids2018 / processed-ml`
- `lanl-comprehensive / authentication`
- `lanl-comprehensive / process`
- `lanl-comprehensive / DNS`
- `lanl-comprehensive / flow`
- `lanl-comprehensive / red-team truth` as scorer-only truth material

### Explicitly excluded

- Splunk BOTS v2 direct adapter acceptance.
- Research-only or review-required datasets.
- CIC raw-PCAP acceptance.
- Model calls, embeddings, LLM diagnosis or training.
- Incident correlation beyond the already-reviewed LANL red-team matcher.
- Any autonomous remediation or skill promotion.

BOTS v2 remains:

```text
license/content status: enterprise_approved
runtime feasibility: BLOCKED_DEPENDENCY_COST
direct_adapter_authorized: false
```

Any V3-02E attempt to treat BOTS as a supported direct adapter is `FAIL_SECURITY`.

---

## 3. Trust boundary

The acceptance runner executes in the offline dataset-processing boundary.

It SHALL have:

- Internet calls: `0`
- model calls: `0`
- package-install calls: `0`
- shell/subprocess authority: `0`
- confidential WorkSpace data access: `0`
- approved-skill registry write authority: `0`
- read access only to source objects explicitly authorized by the acceptance manifest
- write access only to harness-owned bounded temporary acceptance staging and durable compact receipts

Publisher acquisition happens before acceptance through the reviewed acquisition boundary. The V3-02E runner never downloads source data itself.

Dataset bytes remain untrusted data and can never grant authority.

---

## 4. Definition of a real source

A source is `real` only when its lineage can be traced to a reviewed publisher source through an acquisition receipt.

A synthetic fixture, manually constructed CSV/text sample, copied documentation example, model-generated row, or unverified third-party mirror SHALL NOT be marked `real_source=true`.

Minimum source-origin binding:

```text
dataset_id
variant / source_family
publisher_reference
registry_fingerprint
policy_fingerprint
acquisition_receipt_fingerprint
parent_source_object_ref
parent_source_sha256
parent_source_size_bytes
acquisition_mode
```

The publisher reference must match the reviewed registry boundary. Secrets, signed URLs, cookies, tokens and credentials are forbidden from durable acceptance artifacts.

If publisher origin cannot be proven, verdict is `FAIL_PROVENANCE`.

---

## 5. Bounded real-source strategy

V3-02E does not require keeping or repeatedly processing an entire multi-gigabyte corpus.

Two accepted source forms exist.

### 5.1 Bounded publisher object

An already-publisher-bounded object may be evaluated directly when it is within the acceptance resource budget.

### 5.2 Deterministic bounded slice

A larger verified staged parent may be reduced offline into an acceptance slice.

A slice is acceptable only when all derivation metadata is deterministic and recorded:

```text
parent_source_sha256
parent_source_size_bytes
slice_method
slice_start / selection rule
slice_end / selection rule
record-boundary rule
slice_sha256
slice_size_bytes
```

For line/CSV sources, the derivation must align to complete records. Arbitrary partial first/last records are forbidden.

The acceptance runner validates the bounded child digest but never replaces parent provenance with child provenance.

A slice with no verified parent digest is `FAIL_PROVENANCE`.

A nondeterministic sampling rule such as random sampling without a frozen deterministic seed/algorithm is `FAIL_PROVENANCE`.

---

## 6. Acceptance source budgets

Initial V3-02E hard limits:

```text
max source objects per acceptance run: 8
max bytes per bounded source object: 256 MiB
max total bounded input bytes per acceptance run: 512 MiB
max emitted visible records per adapter invocation: 250,000
max single durable generated object: 1 MiB
max Linux peak RSS delta above runner baseline: 512 MiB
Internet calls: 0
model calls: 0
subprocess calls: 0
```

These limits are stricter than the general acquisition cache limits because V3-02E is an acceptance test, not corpus synchronization.

Exceeding a hard resource bound is `FAIL_RESOURCE`.

The thresholds may be tightened later. They SHALL NOT be relaxed merely to make an existing candidate pass.

---

## 7. Real-source acceptance manifest

Machine-readable acceptance manifests SHALL use:

```text
schema_version = workspace-network-real-source-acceptance-manifest/v1
```

Minimum top-level fields:

```text
acceptance_id
spec_version
created_by_role
registry_fingerprint
policy_fingerprint
sources[]
expected_lanes[]
bots_direct_adapter_authorized = false
```

Each source entry SHALL contain:

```text
source_id
dataset_id
variant
source_family | null
real_source = true
publisher_reference
acquisition_mode
acquisition_receipt_fingerprint
parent_source_object_ref
parent_source_sha256
parent_source_size_bytes
bounded_source_object_ref
bounded_source_sha256
bounded_source_size_bytes
derivation | null
adapter_id
adapter_version
provenance_ref
```

No raw record body, attack payload, authentication credential, signed download URL or source secret may appear in this manifest.

---

## 8. Acceptance runner stages

The mandatory harness flow is:

```text
REAL-SOURCE MANIFEST
      |
      v
MANIFEST / LICENSE / REGISTRY ADMISSION
      |
      v
SOURCE ORIGIN + SHA BINDING
      |
      v
PATH / SYMLINK / SIZE BOUND CHECK
      |
      v
PRODUCTION ADAPTER INSPECTION
      |
      v
PASS 1 STREAMING EXECUTION
      |
      +---- visible EvidenceRecord fingerprint
      +---- scorer-only TruthRecord fingerprint
      |
      v
PASS 2 DETERMINISTIC REPLAY
      |
      v
LEAKAGE + PROVENANCE + RESOURCE VALIDATORS
      |
      v
HARNESS-OWNED STAGING CLEANUP
      |
      v
COMPACT ACCEPTANCE RECEIPT
```

The acceptance runner MUST call the reviewed production adapters, not duplicate their parsing logic in a special acceptance parser.

---

## 9. Deterministic replay contract

For the same:

```text
bounded source bytes
source SHA-256
adapter version
registry fingerprint
policy fingerprint
acceptance configuration
```

Pass 1 and Pass 2 SHALL produce identical canonical:

```text
evidence_record_count
evidence_fingerprint
truth_record_count
truth_fingerprint
rejected/malformed counters
```

Wall-clock timestamps and temporary host paths are excluded from content identity.

Any content fingerprint mismatch is `FAIL_INTEGRITY`.

---

## 10. CIC real-source lane

### Source

`cse-cic-ids2018`, variant `processed-ml`.

The source must originate through the reviewed CIC/AWS acquisition boundary recorded in the registry.

### Required real-source evidence before PASS

At minimum the admitted real-source set SHALL provide:

- >= 1,000 valid parsed real flow rows total;
- at least one `BENIGN` truth class;
- at least one non-benign attack truth class;
- production CIC schema accepted without schema guessing;
- zero label leakage to visible `EvidenceRecord` fields;
- deterministic evidence/truth replay;
- no numeric parse error silently coerced to zero;
- exact source SHA/provenance binding.

If the available real source is structurally valid but does not contain both benign and attack truth classes, verdict is `NOT_ENOUGH_REAL_SOURCE_EVIDENCE`, not PASS.

### CIC zero-tolerance failures

- `Label` or canonicalized attack class appears in specialist-visible observation fields;
- source schema is silently remapped by column position/name guessing outside the reviewed adapter mapping;
- source identity is inferred from local path instead of provenance;
- malformed numeric value becomes zero or another invented value;
- synthetic fixture is represented as real source.

---

## 11. LANL real-source lanes

### Required visible families

Real bounded material SHALL exercise all four visible source families:

- authentication
- process
- DNS
- flow

### Required scorer-only truth lane

Real red-team material SHALL exercise the existing scorer-only matcher.

### Minimum real-source evidence before PASS

At minimum the admitted real-source set SHALL provide:

- >= 100 valid authentication records;
- >= 100 valid process records;
- >= 100 valid DNS records;
- >= 100 valid flow records;
- >= 1 real red-team truth record that deterministically matches exactly one real authentication evidence record;
- zero red-team truth leakage into visible evidence;
- exact source-family namespace binding;
- logical LANL time preserved as logical offset, never fabricated UTC;
- deterministic replay for every lane;
- exact parent/bounded source SHA and provenance binding.

A valid real dataset sample that lacks a deterministic red-team→authentication match SHALL receive `NOT_ENOUGH_REAL_SOURCE_EVIDENCE` until a bounded targeted source set with a real match is supplied.

### LANL zero-tolerance failures

- red-team truth enters visible evidence;
- 0-match or >1-match truth is auto-resolved;
- source family is guessed from field count/content instead of manifest namespace;
- LANL logical time is converted to fabricated absolute time;
- `?` is silently converted to invented identity/value;
- auth/process/DNS/flow bytes are interpreted as instructions or authority.

---

## 12. Hidden-truth / visible-evidence leakage audit

The acceptance harness SHALL validate every emitted visible record against the reviewed forbidden-key/semantic boundary.

Leakage testing includes:

- forbidden field names;
- known truth values appearing in reviewed visible fields where they are not legitimate observations;
- direct copy of raw label/red-team source lines;
- truth IDs appearing in specialist-visible payloads;
- answer/root-cause/remediation keys.

Any hidden-truth leakage is `FAIL_SECURITY` and cannot be overridden by otherwise correct parsing.

---

## 13. Provenance contract

Every accepted lane must bind:

```text
publisher source identity
registry fingerprint
policy fingerprint
acquisition receipt fingerprint
parent source SHA-256
bounded source SHA-256
adapter ID/version
V3-02E spec fingerprint
acceptance manifest fingerprint
```

A receipt missing any required provenance field cannot PASS.

No user-specific local absolute path is part of canonical identity.

---

## 14. Cleanup contract

Harness-owned acceptance raw/normalized working copies are temporary.

After both replay passes and receipt construction:

```text
acceptance scratch source copy -> DELETE
acceptance normalized scratch   -> DELETE
```

The durable cleanup evidence stores only bounded metadata:

```text
scratch_object_id
expected_digest
removed = true
cleanup_error_code | null
```

It SHALL NOT store deleted content.

The runner must never delete a parent acquisition object it does not own. Parent-object lifecycle remains governed by the acquisition/cache policy.

If a harness-owned raw or normalized acceptance object remains after a run that otherwise claims PASS, verdict is `FAIL_SECURITY`.

---

## 15. Git/repository retention rule

No real CIC/LANL raw corpus bytes may be committed to Git as part of V3-02E.

Git may contain only:

- specification;
- machine-readable contracts;
- synthetic adversarial fixtures;
- real-source manifests containing hashes/metadata only;
- compact acceptance receipts containing hashes/counters only;
- deterministic harness/test code.

A committed real raw-log/CSV dataset sample is a zero-tolerance `FAIL_SECURITY` for this phase.

---

## 16. Acceptance receipt

Machine-readable receipts SHALL use:

```text
schema_version = workspace-network-real-source-acceptance-receipt/v1
```

Minimum fields:

```text
acceptance_id
exact_head_sha
spec_fingerprint
manifest_fingerprint
dataset_id
variant
source_family
real_source_verified
publisher_reference_fingerprint
acquisition_receipt_fingerprint
parent_source_sha256
bounded_source_sha256
adapter_id
adapter_version
records_seen
records_emitted
records_rejected
truth_records_emitted
evidence_fingerprint
truth_fingerprint
deterministic_replay_pass
visible_schema_pass
truth_separation_pass
provenance_pass
resource_pass
cleanup_pass
network_calls
model_calls
subprocess_calls
peak_rss_delta_bytes
verdict
failed_gate_ids[]
```

Runtime timestamps may exist for operational audit but are excluded from receipt content identity.

Raw exceptions and raw source lines are forbidden in durable receipts.

---

## 17. Verdicts

Only these verdicts are valid:

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

`PASS_WITH_WARNING` does not exist.

BOTS remains governed by the already-recorded `BLOCKED_DEPENDENCY_COST` feasibility verdict and is not a V3-02E acceptance lane.

---

## 18. Shared PASS criteria

A V3-02E lane may PASS only when every applicable criterion is true:

| Gate | Required PASS |
|---|---:|
| real publisher-origin provenance | 100% |
| source SHA binding | 100% |
| manifest schema validity | 100% |
| registry/license eligibility | 100% |
| production adapter used | 100% |
| deterministic replay | 100% identical |
| visible schema validity | 100% |
| evidence IDs unique | 100% |
| truth separation | 100% |
| hidden-truth leakage | 0 |
| out-of-manifest reads | 0 |
| path/symlink escapes | 0 |
| Internet calls | 0 |
| model calls | 0 |
| subprocess calls | 0 |
| raw source content in durable receipt | 0 |
| silent required-field coercion | 0 |
| digest mismatch accepted | 0 |
| hard resource-bound violation | 0 |
| harness-owned raw/normalized leftovers after claimed PASS | 0 |
| cleanup receipt validity | 100% |

One zero-tolerance violation causes FAIL regardless of record count or parser accuracy.

---

## 19. `NOT_ENOUGH_REAL_SOURCE_EVIDENCE`

This is a non-PASS state, not a failure to be hidden.

It is used when:

- CIC real material is valid but does not include both benign and attack truth classes;
- CIC has fewer than the minimum accepted real records;
- one or more required LANL visible families do not meet the minimum real record count;
- no exactly-one real red-team→authentication match is available;
- the source is otherwise valid but cannot yet satisfy the acceptance coverage contract.

The remedy is to acquire a better bounded real-source set, not to lower thresholds or invent ground truth.

---

## 20. Harness fixtures required before acceptance code

The V3-02E harness SHALL have synthetic metadata/adversarial fixtures for at least:

1. valid CIC real-source manifest metadata;
2. valid LANL multi-family manifest metadata;
3. synthetic source falsely marked as real;
4. unreviewed publisher/mirror;
5. registry fingerprint mismatch;
6. acquisition receipt fingerprint missing;
7. parent digest missing;
8. bounded-source digest mismatch;
9. nondeterministic slice derivation;
10. source-family mismatch;
11. BOTS direct-adapter attempt;
12. label/red-team leakage;
13. path/symlink escape;
14. resource-budget overflow;
15. deterministic replay mismatch;
16. cleanup leftover after claimed PASS;
17. raw source line inserted into receipt;
18. insufficient CIC class coverage;
19. insufficient LANL family coverage;
20. LANL no-match / ambiguous red-team truth.

These fixtures contain metadata/synthetic minimal content only and are not substitutes for the later real-source acceptance evidence.

---

## 21. Coding authorization gate

Production V3-02E acceptance-runner code may begin only after all of the following are true:

1. V3-01/V3-02A-D checkpoint exists on `main`;
2. the main checkpoint was produced from an exact-head candidate with:
   - `harness-ci = PASS`
   - `installer-ci = PASS`
   - `portable-deploy-ci = PASS`
   - `windows-deploy-ci = PASS`;
3. this V3-02E spec is committed before acceptance-runner code;
4. the V3-02E machine-readable harness profile exists;
5. manifest/receipt validators and adversarial fixture expectations are defined before real-source execution code.

The V3-02E runner SHALL NOT implement downloading, model use, skill promotion, incident slicing or BOTS parsing.

---

## 22. Definition of Done

V3-02E is complete only when:

1. CIC real-source acceptance has a `PASS` receipt meeting this contract;
2. LANL real-source acceptance has a `PASS` receipt meeting this contract;
3. BOTS remains explicitly blocked for direct adapter use;
4. no real raw corpus bytes are committed to Git;
5. exact-head CI is green across the required workflow families;
6. all durable evidence is compact, hash/provenance based and replayable;
7. the completed V3-02E checkpoint is merged to `main` before V3-03 incident-slicer development begins.

Until both CIC and LANL real-source receipts PASS, V3-03 remains blocked.
