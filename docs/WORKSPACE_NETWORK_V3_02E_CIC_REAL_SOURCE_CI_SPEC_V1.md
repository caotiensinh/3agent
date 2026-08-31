# WorkSpace Network AI V3-02E — CIC Real Publisher-Source CI Evidence Specification v1

Status: **CONTRACT AMENDED AND RE-FROZEN BEFORE REAL ACQUISITION/EXECUTION**

## 1. Goal

Produce the first real publisher-origin V3-02E acceptance evidence for the already-reviewed CSE-CIC-IDS2018 `processed-ml` adapter by acquiring one exact parent object from the official public AWS Open Data bucket, deriving one deterministic record-aligned bounded shard, and executing the already-promoted offline runner against that shard.

This phase proves source provenance + real parent bytes + deterministic bounded derivation + production adapter execution. It does **not** train a model, create a skill, promote a specialist, or authorize V3-03.

## 2. Prerequisite checkpoint

Required `main` checkpoint before this phase:

`033b67b7531d4cd24adaa5f258c5aa42b71bdc11`

That checkpoint contains the promoted V3-02E acceptance contract and offline CIC/LANL runner.

## 3. Exact parent source

Dataset: `cse-cic-ids2018`

Variant: `processed-ml`

Official bucket:

`cse-cic-ids2018`

Region:

`ca-central-1`

Exact object key:

`Processed Traffic Data for ML Algorithms/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`

The workflow MUST obtain the parent bytes from the official bucket using unsigned AWS S3 access. A mirror, Kaggle copy, Hugging Face copy, GitHub copy, signed third-party URL, or manually substituted local copy is not valid for this gate.

## 4. Why a bounded derivation is required

The production `CSECICIDS2018Adapter` has a frozen maximum of `250000` visible records per invocation. Publicly documented counts for this parent CSV exceed that limit, so feeding the complete parent object to the adapter would correctly fail the resource contract.

The resource limit MUST NOT be increased merely to make the real-source gate pass.

The authorized bounded derivation is therefore:

- method: `record_aligned_slice`;
- selection rule: copy the header plus the **first 250000 logical CSV data records in original order**;
- selection MUST NOT inspect or depend on `Label`, attack class, benign status, model output, randomness, shuffle, or wall clock;
- record-boundary rule: parse logical CSV records with Python's standard `csv.reader` and deterministically serialize selected field values with `csv.writer(..., lineterminator="\n")`;
- the parent and bounded SHA-256/size MUST both be recorded;
- the parent object itself remains the publisher-origin provenance anchor.

This rule is deterministic and label-blind. Ground truth remains scorer-only after the bounded shard enters the production adapter.

## 5. Trust boundary

Allowed network authority exists **only in the acquisition step** and only for the exact public S3 bucket/object.

Bounded derivation and the production `OfflineRealSourceRunner` are offline. The production runner MUST report:

- `network_calls = 0`
- `model_calls = 0`
- `subprocess_calls = 0`

The acquisition process may invoke AWS CLI before bounded derivation/runner execution. That acquisition authority MUST NOT be attributed to or exposed through the production runner.

## 6. Acquisition and derivation contract

The job MUST:

1. use unsigned S3 access;
2. use the exact bucket, region and object key in this spec;
3. capture parent S3 metadata before/with acquisition;
4. download the parent into a job-scoped temporary source root;
5. compute SHA-256 locally from the complete parent bytes;
6. measure exact parent byte size locally;
7. reject symlinks and non-regular parent files;
8. reject a parent object larger than 268435456 bytes;
9. derive exactly one label-blind bounded shard using the frozen rule in section 4;
10. compute SHA-256 and exact byte size of the bounded shard;
11. fail if the bounded shard has zero data records, more than 250000 data records, or is larger than the parent;
12. generate a compact acquisition/derivation receipt containing only metadata/fingerprints, never raw CSV rows;
13. bind the V3-02E manifest to both parent and bounded SHA-256/size and the deterministic derivation rule;
14. delete both parent and bounded CSV bytes in an always-run cleanup step.

No credentials are allowed or required.

## 7. Acquisition/derivation receipt minimum fields

The compact receipt MUST include:

- schema version;
- dataset ID;
- variant;
- bucket;
- region;
- exact parent object key;
- acquisition mode `public_s3_unsigned`;
- parent source size bytes;
- parent source SHA-256;
- bounded source size bytes;
- bounded source SHA-256;
- bounded data-record count;
- derivation method;
- derivation selection rule;
- derivation record-boundary rule;
- S3 ETag when available;
- S3 LastModified when available;
- exact Git commit SHA executing the evidence workflow;
- registry fingerprint;
- policy fingerprint;
- receipt fingerprint.

Wall-clock execution time may be recorded as non-identity metadata but MUST NOT be part of deterministic source identity.

## 8. V3-02E manifest binding

The generated runtime manifest MUST:

- set `real_source=true`;
- set dataset `cse-cic-ids2018`;
- set variant `processed-ml`;
- use production adapter ID `cse-cic-ids2018-processed-ml`;
- use production adapter version `cse-cic-ids2018-processed-ml/0.1`;
- bind `parent_source_*` to the complete official S3 object;
- bind `bounded_source_*` to the deterministic bounded shard;
- set `derivation.method=record_aligned_slice`;
- bind the exact frozen selection and record-boundary rules from section 4;
- use the official S3 HTTPS publisher reference without query parameters or credentials;
- set acquisition mode `public_s3_unsigned`;
- bind `acquisition_receipt_fingerprint` to the generated receipt;
- use exactly one expected lane: `cic_processed_ml`;
- keep `bots_direct_adapter_authorized=false`.

No random sampling, class balancing, label-aware filtering, or alternate derivation is authorized.

## 9. Production execution contract

The evidence job MUST execute the production `OfflineRealSourceRunner` from the exact checked-out commit against the bounded shard only.

The parent object may coexist in the job-scoped acquisition directory but MUST NOT be recursively discovered or parsed by the runner.

The job MUST NOT copy adapter logic into the CI script.

Required production path:

`official parent -> deterministic bounded shard -> OfflineRealSourceRunner -> CSECICIDS2018Adapter -> EvidenceRecord + scorer-only TruthRecord -> V3-02E coverage decision`

The runner must remain on Linux so the required peak-RSS measurement is real rather than fabricated.

## 10. PASS contract

A CIC real-source evidence run is `PASS` only if all conditions below hold:

- parent came from the exact official S3 bucket/object;
- parent is <= 268435456 bytes;
- parent SHA-256/size are valid and bound to the receipt/manifest;
- bounded shard was produced by the exact label-blind deterministic rule;
- bounded shard contains 1..250000 data records and is bound by SHA-256/size;
- registry fingerprint matches the exact checked-out registry;
- policy fingerprint is present and bound to the manifest;
- production adapter schema inspection succeeds;
- at least 1000 valid visible evidence records are emitted;
- scorer-only truth contains at least one benign class;
- scorer-only truth contains at least one non-benign class;
- hidden truth never appears in visible evidence;
- two-pass deterministic replay succeeds;
- production runner network/model/subprocess counters remain zero;
- Linux peak-RSS gate passes;
- runner-owned scratch cleanup passes;
- acquisition-owned parent and bounded CSVs are deleted after execution;
- durable evidence artifact contains metadata/receipts only, never raw CSV content.

There is no `PASS_WITH_WARNING`.

## 11. Insufficient evidence

If the official parent and deterministic bounded shard are valid but the shard does not satisfy minimum record/truth coverage, the result MUST remain:

`NOT_ENOUGH_REAL_SOURCE_EVIDENCE`

The workflow MUST NOT lower thresholds, increase the 250000-record adapter budget, inspect labels to choose records, or select synthetic/mirror data to force PASS.

## 12. Hard FAIL classes

Any one of the following blocks promotion:

- wrong bucket or parent object key;
- authenticated/signed acquisition substituted for unsigned public source without a new review;
- mirror or alternate host used;
- parent > resource bound;
- parent/bounded path or symlink escape;
- parent digest/size mismatch after binding;
- bounded digest/size mismatch after derivation;
- derivation differs from the frozen label-blind record-aligned rule;
- bounded data-record count >250000;
- registry or policy fingerprint mismatch;
- production adapter ID/version drift;
- schema drift silently guessed;
- hidden label/truth leakage;
- deterministic replay mismatch;
- production runner network/model/subprocess authority nonzero;
- Linux RSS measurement unavailable/fabricated;
- raw CSV row/content appears in durable receipt/artifact;
- parent or bounded CSV remains after workflow cleanup;
- BOTS direct adapter introduced;
- exact-head source lineage not proven.

## 13. Durable outputs

Allowed durable artifacts:

- acquisition/derivation receipt JSON;
- V3-02E acceptance manifest JSON;
- production runner receipt JSON;
- compact evidence summary JSON;
- CI logs containing bounded metadata only.

Forbidden durable artifacts:

- downloaded parent CSV;
- bounded CSV shard;
- extracted raw rows;
- normalized evidence corpus;
- scorer-only per-row truth corpus;
- credentials/tokens/signed URLs.

## 14. CI gate

The feature checkpoint is promotable only after:

1. CIC real-source evidence workflow completes with `PASS` on the exact feature HEAD;
2. `harness-ci` succeeds on that same exact HEAD;
3. `installer-ci` succeeds on that same exact HEAD;
4. `portable-deploy-ci` succeeds on that same exact HEAD;
5. `windows-deploy-ci` succeeds on that same exact HEAD;
6. `main` has not advanced, or `main` has been reconciled and all exact-head gates rerun.

## 15. LANL boundary

This spec does not authorize LANL acquisition. The registry classifies LANL as `operator_enrollment_required`; LANL stays `NOT_ENOUGH_REAL_SOURCE_EVIDENCE` until an operator-provided publisher link is reviewed and bound to a separate evidence plan.

## 16. Next-step rule

Passing this CIC gate proves only the CIC portion of V3-02E real-source evidence.

Do not mark the complete multi-dataset V3-02E phase closed and do not start V3-03 until the required LANL real publisher-source evidence is independently resolved under its own publisher-access boundary.
