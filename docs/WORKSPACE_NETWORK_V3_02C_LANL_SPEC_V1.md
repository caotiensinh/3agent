# WorkSpace Network AI V3-02C LANL Multi-Source Adapter Specification v1

## Status

**SPEC FROZEN BEFORE V3-02C IMPLEMENTATION**

V3-02C implementation is authorized only after V3-02B CSE-CIC-IDS2018 exact-head CI is fully green.

Authorized predecessor evidence:

- V3-02B exact head: `c4e1e2413181907e9a27e84dbd22559173528a5f`
- required CI families: `harness-ci`, `installer-ci`, `portable-deploy-ci`, `windows-deploy-ci`
- required conclusion for all four: `success`

This document defines the goal, harness, schemas, truth boundary, resource limits and explicit PASS/FAIL criteria for LANL Comprehensive multi-source extraction.

---

## 1. Goal

The LANL adapter exists to turn bounded LANL source shards into deterministic evidence that can later teach WorkSpace how to:

1. reconstruct authentication and lateral-movement traces;
2. correlate authentication, process, DNS and flow observations;
3. distinguish supporting, contradicting and missing evidence;
4. evaluate intrusion-trace and forensic reasoning against hidden red-team ground truth;
5. derive compact ExperienceCase and EvidencePattern artifacts in later stages.

The adapter does **not** diagnose incidents, train a model, generate a skill, retain raw logs durably, or expose red-team labels to specialists.

```text
LANL staged source families
        |
        +-- auth  ----> visible EvidenceRecord
        +-- proc  ----> visible EvidenceRecord
        +-- dns   ----> visible EvidenceRecord
        +-- flow  ----> visible EvidenceRecord
        |
        +-- redteam ---> scorer-only ground-truth matcher
                            |
                            v
                     TruthRecord only
```

---

## 2. Authoritative dataset facts

The adapter contract is based on the LANL Comprehensive, Multi-Source Cyber-Security Events dataset.

The dataset contains 58 consecutive days of de-identified events from five sources:

- Windows authentication;
- Windows process start/stop;
- DNS lookups;
- network flows;
- red-team compromise events.

LANL states that identifiers are unified across the data elements. The original real-world timeframe is intentionally undisclosed. Dataset time starts at an internal epoch of `1` with one-second resolution.

Therefore the adapter MUST preserve LANL time as a logical offset and MUST NOT invent UTC, timezone, calendar date or wall-clock timestamps.

---

## 3. Source-family schemas

### 3.1 Authentication

Exact reviewed field order:

```text
time,
source_user_domain,
destination_user_domain,
source_computer,
destination_computer,
authentication_type,
logon_type,
authentication_orientation,
success_failure
```

Expected field count: `9`.

`?` means unknown/missing and MUST remain unknown; it must not become an empty identity, zero, `Success`, or any inferred value.

### 3.2 Process

Exact reviewed field order:

```text
time,
user_domain,
computer,
process_name,
start_end
```

Expected field count: `5`.

### 3.3 DNS

Exact reviewed field order:

```text
time,
source_computer,
computer_resolved
```

Expected field count: `3`.

The `computer_resolved` value is a de-identified LANL computer identity, not an Internet hostname supplied with external attribution.

### 3.4 Network flow

Exact reviewed field order:

```text
time,
duration_seconds,
source_computer,
source_port,
destination_computer,
destination_port,
protocol,
packet_count,
byte_count
```

Expected field count: `9`.

Ports may be de-identified (`N...`) except for some well-known ports. The adapter MUST preserve this distinction rather than coercing every port to an integer.

### 3.5 Red-team ground truth

Exact reviewed field order:

```text
time,
user_domain,
source_computer,
destination_computer
```

Expected field count: `4`.

Red-team input is **never** converted to visible EvidenceRecord objects.

---

## 4. Logical-time contract

LANL time is an anonymized offset, not a real epoch timestamp.

Canonical representation:

```text
time_offset_seconds: integer >= 1
logical_timestamp: "lanl:T+<integer>s"
```

Examples:

```text
1       -> lanl:T+1s
31      -> lanl:T+31s
151648  -> lanl:T+151648s
```

Rules:

- no `Z` suffix;
- no timezone;
- no ISO calendar date synthesis;
- no host execution time;
- no current date;
- the integer offset remains available in `observation_fields` for deterministic sorting and incident slicing.

Invalid, missing, negative, zero or non-integer time => record rejection.

---

## 5. Canonical entity references

The adapter may only emit identities directly present in LANL data.

Reviewed prefixes:

```text
lanl:user:<value>
lanl:computer:<value>
lanl:process:<value>
lanl:port:<value>
lanl:protocol:<value>
```

Unknown `?` values produce no entity reference.

No adapter may:

- resolve anonymized LANL computers to real hosts;
- infer employee identity;
- infer IP address;
- infer domain ownership outside LANL;
- turn process/user/computer strings into commands, paths, URLs or authority.

---

## 6. Visible EvidenceRecord mappings

### 6.1 Auth evidence

```text
source_domain = authentication
event_family = authentication
event_type = lanl_authentication
```

Visible observations may include:

```text
time_offset_seconds
source_user_domain
destination_user_domain
source_computer
destination_computer
authentication_type
logon_type
authentication_orientation
success_failure
```

All values remain observations. `Success`/`Failure` is an observed authentication outcome, not attack truth.

### 6.2 Process evidence

```text
source_domain = host_process
event_family = process
event_type = lanl_process_lifecycle
```

Visible observations:

```text
time_offset_seconds
user_domain
computer
process_name
start_end
```

### 6.3 DNS evidence

```text
source_domain = dns
event_family = dns
event_type = lanl_dns_lookup
```

Visible observations:

```text
time_offset_seconds
source_computer
computer_resolved
```

### 6.4 Flow evidence

```text
source_domain = network_flow
event_family = network_flow
event_type = lanl_router_flow
```

Visible observations:

```text
time_offset_seconds
duration_seconds
source_computer
source_port
destination_computer
destination_port
protocol
packet_count
byte_count
```

---

## 7. Red-team truth boundary

This is a zero-tolerance security/evaluation boundary.

The following may never appear in specialist-visible evidence, case input, network refs, asset refs, account refs or public receipts merely because they came from `redteam.txt`:

```text
redteam
red_team
is_attack
attack_label
compromise_label
known_bad
attacker_identity
redteam_source
redteam_destination
```

Red-team source bytes are scorer-only input.

Specialists must discover suspicious behavior from visible auth/process/DNS/flow evidence without knowing which users, computers or timestamps are red-team events.

---

## 8. Deterministic red-team-to-auth matching

LANL documents red-team entries as specific compromise events taken from authentication data, but the red-team file exposes fewer fields than `auth.txt`.

The adapter MUST NOT assume an undocumented user-role mapping.

For one red-team row `(t, user, src_comp, dst_comp)`:

1. select auth evidence candidates with exact:
   - `time_offset_seconds == t`;
   - `source_computer == src_comp`;
   - `destination_computer == dst_comp`;
2. from those candidates, retain candidates where either:
   - `source_user_domain == user`; or
   - `destination_user_domain == user`;
3. require exactly one candidate.

Outcomes:

```text
exactly 1 candidate -> emit scorer-only TruthRecord bound to that evidence_id
0 candidates        -> UNMATCHED_TRUTH, no inferred binding
>1 candidates       -> AMBIGUOUS_TRUTH, no inferred binding
```

The adapter may not pick the first row, nearest row, most suspicious row or model-selected row.

A future reviewed schema revision may tighten the user-role rule if authoritative evidence establishes it.

---

## 9. TruthRecord contract

For an exact deterministic match:

```text
truth_class = lanl_redteam_auth_compromise
truth_fields = {
  "known_compromise": true,
  "time_offset_seconds": <t>
}
```

The truth record may reference only the matched authentication evidence ID.

To reduce answer leakage, durable truth does not need to repeat red-team user/source/destination fields after deterministic binding; those values already exist in the referenced visible auth evidence.

No process, DNS or flow observation becomes directly "malicious" merely because it shares a nearby time or entity. Later incident correlation may evaluate those relations, but V3-02C must not manufacture them.

---

## 10. Adapter decomposition

V3-02C SHALL be implemented as small deterministic source-family adapters rather than one parser with implicit mode detection.

Required components:

```text
LANLAuthAdapter
LANLProcessAdapter
LANLDNSAdapter
LANLFlowAdapter
LANLRedTeamTruthMatcher
```

Source family is selected by the acquisition/manifest contract, never guessed from content.

Wrong family/schema => FAIL_SCHEMA.

---

## 11. Input and integrity boundary

Every source family uses the V3-02 `AdapterInputContract` and `inspect_staged_source()` integrity binding.

Before parse:

- dataset ID must be `lanl-comprehensive`;
- variant/source family must match the exact adapter;
- logical source reference must be safe;
- staged source must be inside the authorized root;
- symlink/out-of-root source is rejected;
- size must match contract;
- SHA-256 must match contract;
- adapter version must match;
- registry/policy/provenance fingerprints must be present.

Immediately before iteration, digest/integrity binding MUST be rechecked to prevent post-inspection tampering.

---

## 12. Staging format

V3-02C does not add an Internet downloader.

The first implementation accepts bounded staged text shards in the original LANL comma-delimited record layout.

If acquisition receives the official `.gz` source, decompression/sharding belongs to the isolated dataset staging path and must produce:

```text
original_source_sha256
derived_shard_sha256
source_family
ordinal/range metadata
provenance binding
```

No shard is enterprise-admissible without provenance back to the acquired source object.

Direct full-corpus durable extraction is not required for V3-02C PASS.

---

## 13. Streaming and resource limits

Mandatory:

- line-by-line iteration;
- no whole-file `.read()`;
- no pandas/DataFrame whole-source load;
- no model calls;
- no Internet calls;
- no subprocess/package installation;
- maximum visible records per adapter invocation <= `250,000`;
- individual canonical output <= `1 MiB`;
- malformed raw content not copied into receipts;
- peak memory must remain bounded by record/window limits, not total source size.

The red-team matcher may maintain only bounded matching indexes authorized by the manifest/window. It must not load all 1.6B events into RAM.

---

## 14. Unknown/malformed policy

### `?`

A literal `?` is dataset-defined unknown.

Rules:

- optional field -> canonical `None`/omitted reference;
- required identity needed to construct event semantics -> record rejected;
- never infer replacement value.

### Structural failures

```text
wrong field count       -> reject record / FAIL_SCHEMA according to fixture class
invalid time            -> reject record
invalid required count  -> reject record
negative duration       -> reject record
negative packets/bytes  -> reject record
unknown source family   -> FAIL_SCHEMA
truncated staged object -> FAIL_INTEGRITY
source digest mismatch  -> FAIL_INTEGRITY
```

Error receipts contain stable reason codes only, never attacker-controlled raw line text.

---

## 15. Numeric parsing rules

Required integer fields:

```text
time
duration_seconds
packet_count
byte_count
```

`time >= 1`.

`duration_seconds >= 0`.

`packet_count >= 0`.

`byte_count >= 0`.

Protocol and ports are not universally numeric because LANL may use anonymized identifiers. Preserve reviewed string semantics.

Numeric parse failure never becomes zero.

---

## 16. Harness fixtures

V3-02C must include synthetic minimal fixtures for each family.

### Required positive fixtures

```text
auth_valid_minimal
auth_unknown_optional_fields
proc_valid_start
proc_valid_end
dns_valid_minimal
flow_valid_well_known_port
flow_valid_anonymized_port
redteam_exact_single_match
multi_source_same_entity_time_ordering
```

### Required negative/adversarial fixtures

```text
wrong_family_auth_as_flow
wrong_field_count
invalid_time_zero
invalid_time_text
negative_duration
negative_packets
negative_bytes
question_mark_required_identity
post_inspection_same_size_tamper
out_of_root_path
symlink_source
redteam_zero_match
redteam_multiple_match
redteam_truth_leakage
resource_record_budget_exceeded
whole_file_read_authority
network_model_subprocess_authority
```

---

## 17. Determinism harness

For the same:

```text
source bytes
source family
adapter version
registry fingerprint
policy fingerprint
provenance binding
```

replay twice and require byte-equivalent canonical evidence/truth outputs and identical content fingerprints.

Physical temp directory, host OS path and wall-clock execution time must not affect IDs.

---

## 18. Cross-source identity harness

Because LANL intentionally uses unified de-identified identifiers across source families, the harness verifies that the same literal computer/user/process identifier maps to the same canonical entity reference wherever that entity type appears.

Examples:

```text
C17693 in auth -> lanl:computer:C17693
C17693 in dns  -> lanl:computer:C17693
C17693 in flow -> lanl:computer:C17693
```

The adapter must not introduce per-file salts that break legitimate cross-source correlation.

---

## 19. PASS criteria

V3-02C is PASS only if **every** mandatory gate passes.

| Gate | PASS threshold |
|---|---:|
| reviewed source-family schema fidelity | 100% |
| deterministic replay | 100% identical |
| canonical entity consistency across families | 100% |
| logical-time preservation | 100% |
| invented calendar/UTC timestamps | 0 |
| red-team truth in visible evidence | 0 |
| unsupported red-team binding | 0 |
| ambiguous truth auto-resolution | 0 |
| unmatched truth auto-resolution | 0 |
| source-family guessing | 0 |
| silent required-field coercion | 0 |
| accepted digest mismatch | 0 |
| accepted post-inspection tamper | 0 |
| out-of-plan/out-of-root reads | 0 |
| Internet/model/subprocess calls | 0 |
| whole-file corpus buffering | 0 |
| raw untrusted line content in durable receipt | 0 |
| source/provenance binding | 100% |
| Python 3.11/3.12 harness regression | PASS |
| installer/portable/Windows regression | PASS |

One zero-tolerance violation => **V3-02C FAIL** regardless of throughput or detection usefulness.

---

## 20. Explicit FAIL verdicts

```text
FAIL_SCHEMA
FAIL_INTEGRITY
FAIL_SECURITY
FAIL_PROVENANCE
FAIL_RESOURCE
FAIL_TRUTH_MATCH
```

`PASS_WITH_WARNING` is not valid.

Examples:

- red-team row exposed to specialist -> `FAIL_SECURITY`;
- source family guessed from row length -> `FAIL_SCHEMA`;
- red-team row matched to first of two possible auth events -> `FAIL_TRUTH_MATCH`;
- `T+151648s` converted into a fabricated calendar date -> `FAIL_SCHEMA`;
- `?` replaced with guessed user/process/port -> `FAIL_SCHEMA`;
- same-size source modification after inspection accepted -> `FAIL_INTEGRITY`.

---

## 21. Evidence receipt

Exact-head validation receipt records:

```text
exact_head_sha
adapter_family_versions
spec_sha256
fixture_manifest_sha256
source/fixture_sha256
registry_fingerprint
policy_fingerprint
records_seen
records_emitted
records_rejected
truth_rows_seen
truth_rows_matched
truth_rows_unmatched
truth_rows_ambiguous
determinism_result
resource_measurements
zero_tolerance_gates
verdict
failed_gate_ids
```

No raw dataset line is stored in receipt.

---

## 22. Coding order

Implementation order after this specification exists:

```text
V3-02C-1 shared LANL logical-time/entity/schema helpers
V3-02C-2 authentication adapter
V3-02C-3 process adapter
V3-02C-4 DNS adapter
V3-02C-5 flow adapter
V3-02C-6 red-team scorer-only matcher
V3-02C-7 multi-source deterministic harness
V3-02C-8 exact-head CI
```

Each sub-step must keep all prior tests green.

Do not implement incident correlation, anomaly scoring, ATT&CK mapping, ExperienceCase mining, skill generation or the multi-skill coordinator in V3-02C.

---

## 23. Promotion authorization

V3-02C may be declared complete only when the exact implementation HEAD has:

```text
harness-ci         = success
installer-ci       = success
portable-deploy-ci = success
windows-deploy-ci  = success
```

and all LANL zero-tolerance harness gates pass.

Only then may V3-02D BOTS v2 feasibility work begin.
