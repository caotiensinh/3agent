# WorkSpace Network AI — V3-02D BOTS v2 Feasibility Gate v1

## 1. Purpose

V3-02D determines whether the official Splunk Boss of the SOC v2 distribution can enter the WorkSpace Network AI experience pipeline through a **bounded, deterministic, vendor-runtime-free** path.

This phase is a feasibility gate, not a parser implementation phase.

The gate exists because an enterprise-approved license does not imply that the distributed storage format is suitable for a lean local WorkSpace runtime.

## 2. Goal

Answer exactly one question:

> Can the reviewed BOTS v2 source be converted into canonical WorkSpace evidence using a documented, deterministic, bounded path that does not require Splunk Enterprise, separately licensed Splunk add-ons, undocumented vendor index decoding, network/model authority, or whole-corpus buffering inside WorkSpace?

Exactly two source-feasibility verdicts are allowed:

```text
SUPPORTED_LIGHTWEIGHT
BLOCKED_DEPENDENCY_COST
```

A `BLOCKED_DEPENDENCY_COST` verdict is a successful safety outcome when the reviewed source cannot meet the lightweight boundary. It is not permission to bypass the boundary.

## 3. Reviewed publisher facts

The v1 gate freezes the following publisher facts from the official `splunk/botsv2` README:

- dataset ID: `splunk-bots-v2`;
- full distribution size: `16.4GB`;
- attack-only distribution size: `3.2GB`;
- both distributions are described as `Pre-indexed Splunk`;
- official integrity values are MD5 values published by the source;
- the publisher installation path requires Splunk Enterprise and a versioned set of Splunk apps/add-ons;
- dataset copyright/license is CC0/public-domain dedication;
- attack-only is a subset of the full dataset and is the preferred WorkSpace candidate if a lightweight path is ever approved.

These facts are source metadata only. The feasibility evaluator may not infer undocumented Splunk bucket/index internals from them.

## 4. Non-goals

V3-02D does **not**:

- install Splunk Enterprise;
- install any Splunk app/add-on;
- launch a Splunk service;
- download either BOTS archive;
- decode proprietary/undocumented Splunk index buckets;
- scrape a running Splunk instance;
- call a Splunk REST API;
- add a Docker image containing Splunk;
- add network access to Confidential Core;
- add model/LLM calls;
- build ExperienceCase objects;
- train or evaluate specialist models;
- mark attack-only events as specialist-visible ground truth;
- treat CC0 licensing as proof of runtime feasibility.

## 5. Architectural boundary

```text
official BOTS v2 metadata
        |
        v
V3-02D feasibility profile
        |
        v
Deterministic Feasibility Evaluator
        |
        +-----------------------------+
        |                             |
        v                             v
SUPPORTED_LIGHTWEIGHT        BLOCKED_DEPENDENCY_COST
        |                             |
        v                             v
future reviewed adapter      no direct BOTS parser
                              no Splunk dependency
```

The evaluator operates on reviewed metadata/profile objects only. It never opens, installs, runs, imports, or executes vendor software.

## 6. Feasibility profile contract

A source profile must explicitly record at least:

```text
dataset_id
variant
distribution_format
compressed_size_bytes_or_reviewed_size
license_enterprise_compatible
official_integrity_scheme
vendor_runtime_required
separately_licensed_addons_required
documented_vendor_free_event_schema
vendor_free_streaming_reader_available
undocumented_index_decoding_required
whole_corpus_buffer_required
bounded_conversion_possible
source_to_derived_provenance_possible
network_service_required
```

Missing material fields fail closed.

No profile field may be supplied by model inference.

## 7. SUPPORTED_LIGHTWEIGHT criteria

`SUPPORTED_LIGHTWEIGHT` is allowed only when **every** condition below is true:

1. dataset license is enterprise-compatible;
2. the staged variant has a documented event/schema representation usable outside the vendor runtime;
3. no Splunk Enterprise process/service is required to expose the events;
4. no separately licensed Splunk app/add-on is required to expose or normalize the events;
5. no undocumented/proprietary index decoding is required;
6. iteration can be streaming/bounded rather than whole-corpus buffering;
7. conversion can stay within WorkSpace resource policy;
8. deterministic source -> derived-shard provenance can be preserved;
9. conversion does not require an Internet service after acquisition;
10. conversion does not require model/LLM interpretation;
11. a reviewed schema can reject malformed data without guessing;
12. the resulting adapter can be tested on synthetic fixtures without installing vendor software.

Failure of any mandatory criterion denies `SUPPORTED_LIGHTWEIGHT`.

## 8. BLOCKED_DEPENDENCY_COST criteria

Return `BLOCKED_DEPENDENCY_COST` when any mandatory blocker is present, including:

```text
PREINDEXED_VENDOR_FORMAT
VENDOR_RUNTIME_REQUIRED
SEPARATELY_LICENSED_ADDONS_REQUIRED
NO_DOCUMENTED_VENDOR_FREE_EVENT_SCHEMA
UNDOCUMENTED_INDEX_DECODING_REQUIRED
UNBOUNDED_CONVERSION
PROVENANCE_NOT_PRESERVABLE
NETWORK_SERVICE_REQUIRED_FOR_PARSE
```

The evaluator returns stable blocker codes only. It must not copy arbitrary untrusted source text into durable receipts.

## 9. Current reviewed BOTS v2 expectation

Under the official distribution documented in the reviewed publisher README, the expected v1 source verdict is:

```text
BLOCKED_DEPENDENCY_COST
```

Expected minimum blocker set:

```text
PREINDEXED_VENDOR_FORMAT
VENDOR_RUNTIME_REQUIRED
SEPARATELY_LICENSED_ADDONS_REQUIRED
NO_DOCUMENTED_VENDOR_FREE_EVENT_SCHEMA
```

This expected verdict may change only after a new reviewed source variant or authoritative documentation establishes a vendor-runtime-free, deterministic event representation.

## 10. Derived-export escape hatch

A future operator-produced export may be reviewed as a **new derived source variant**, not silently treated as the official pre-indexed distribution.

A derived variant must carry:

```text
original archive source reference
original archive digest
conversion recipe/version
conversion environment identity
derived shard digest
schema version
sourcetype mapping
record/window range
provenance binding
```

If the conversion itself requires Splunk, that requirement remains outside the WorkSpace runtime and must be explicitly reviewed. The existence of an operator export does not retroactively make the official pre-indexed distribution `SUPPORTED_LIGHTWEIGHT`.

## 11. Harness design

The V3-02D harness must run entirely from synthetic/reviewed metadata profiles. It must never fetch the 3.2GB or 16.4GB archives.

Required fixtures:

### Positive feasibility fixture

`lightweight_documented_export`

Expected:

```text
SUPPORTED_LIGHTWEIGHT
blockers = []
```

The fixture represents a hypothetical reviewed JSON/CSV/NDJSON-like source with no vendor runtime.

### Current official BOTS v2 fixture

`bots_v2_official_preindexed`

Expected:

```text
BLOCKED_DEPENDENCY_COST
```

with the mandatory blockers from section 9.

### Negative/adversarial fixtures

```text
license_not_enterprise_compatible
vendor_runtime_required
separate_addons_required
undocumented_index_decoder_claimed
missing_schema_evidence
network_service_required
whole_corpus_buffer_required
provenance_missing
missing_material_profile_field
model_inferred_profile_value
unknown_verdict
```

## 12. Determinism contract

For the same canonical feasibility profile and evaluator version:

```text
verdict
sorted blocker codes
profile fingerprint
receipt fingerprint
```

must be byte-equivalent across replays and independent of:

- temp directory;
- host OS path;
- wall-clock time;
- Python hash ordering;
- current network state.

## 13. Authority harness

The evaluator implementation must fail static/AST review if it imports or invokes capabilities that provide:

```text
requests
urllib
socket
subprocess
openai
ollama
splunk SDK/client
package installers
shell execution
```

No whole-file corpus read is needed because V3-02D evaluates metadata only.

## 14. V3-02D gate PASS criteria

V3-02D itself is PASS only if all conditions below hold:

| Gate | PASS threshold |
|---|---:|
| exact two source verdicts | 100% |
| current official BOTS profile -> `BLOCKED_DEPENDENCY_COST` | required |
| required current blocker codes present | 100% |
| synthetic lightweight profile -> `SUPPORTED_LIGHTWEIGHT` | required |
| missing material profile field accepted | 0 |
| vendor-runtime-required profile marked supported | 0 |
| separate-add-on-required profile marked supported | 0 |
| undocumented decoder marked supported | 0 |
| network-service parse marked supported | 0 |
| unbounded conversion marked supported | 0 |
| provenance-less conversion marked supported | 0 |
| model-inferred source fact accepted | 0 |
| deterministic replay | 100% identical |
| network/model/subprocess/package-install authority | 0 |
| BOTS archive download in test | 0 |
| Python 3.11/3.12 harness regression | PASS |
| installer/portable/Windows regression | PASS |

One zero-tolerance violation => V3-02D FAIL.

## 15. V3-02D gate FAIL criteria

The gate is FAIL if implementation does any of the following:

- claims direct BOTS v2 support merely because the license is CC0;
- installs or launches Splunk to make the test pass;
- parses undocumented Splunk index internals as if they were a stable public schema;
- silently depends on separately licensed add-ons;
- downloads the real BOTS archive during CI;
- turns attack-only status into specialist-visible truth;
- returns `SUPPORTED_LIGHTWEIGHT` while any mandatory blocker remains;
- produces nondeterministic blocker/verdict receipts;
- weakens WorkSpace egress/resource/provenance boundaries.

## 16. Implementation order

Only after this SPEC is committed may implementation proceed:

```text
V3-02D-1  Feasibility profile + canonical receipt
V3-02D-2  Deterministic evaluator
V3-02D-3  Synthetic/adversarial harness
V3-02D-4  Exact-head CI
V3-02D-5  Record source verdict in registry/PR evidence
```

No BOTS event parser is authorized by V3-02D unless a future source profile earns `SUPPORTED_LIGHTWEIGHT`.
