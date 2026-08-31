# WorkSpace Network AI V3-02E — CIC Real Publisher-Source CI Evidence Specification v1

Status: **CONTRACT-FROZEN BEFORE ACQUISITION/EXECUTION CODE**

## 1. Goal

Produce the first real publisher-origin V3-02E acceptance evidence for the already-reviewed CSE-CIC-IDS2018 `processed-ml` adapter by executing the already-promoted offline runner against a bounded object fetched directly from the official public AWS Open Data bucket.

This phase proves source provenance + real bytes + production adapter execution. It does **not** train a model, create a skill, promote a specialist, or authorize V3-03.

## 2. Prerequisite checkpoint

Required `main` checkpoint before this phase:

`033b67b7531d4cd24adaa5f258c5aa42b71bdc11`

That checkpoint contains the promoted V3-02E acceptance contract and offline CIC/LANL runner.

## 3. Exact source candidate

Dataset: `cse-cic-ids2018`

Variant: `processed-ml`

Official bucket:

`cse-cic-ids2018`

Region:

`ca-central-1`

Exact object key:

`Processed Traffic Data for ML Algorithms/Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv`

The workflow MUST obtain the bytes from the official bucket using unsigned AWS S3 access. A mirror, Kaggle copy, Hugging Face copy, GitHub copy, signed third-party URL, or manually substituted local copy is not valid for this gate.

## 4. Why this object

The candidate is a reviewed `processed-ml` CSV compatible with the production `CSECICIDS2018Adapter` and is expected to remain below the V3-02E per-object bound of 256 MiB.

The final gate does not trust the expected size from documentation. It MUST measure the real object and fail closed if the object is absent, changed beyond resource limits, or incompatible with the reviewed schema.

## 5. Trust boundary

Allowed network authority exists **only in the acquisition step** and only for the exact public S3 bucket/object.

The production `OfflineRealSourceRunner` itself remains offline and MUST report:

- `network_calls = 0`
- `model_calls = 0`
- `subprocess_calls = 0`

The acquisition process may invoke AWS CLI before the runner starts. That acquisition authority MUST NOT be attributed to or exposed through the production runner.

## 6. Acquisition contract

The acquisition step MUST:

1. use unsigned S3 access;
2. use the exact bucket, region and object key in this spec;
3. capture source metadata before/with acquisition;
4. download into a job-scoped temporary source root;
5. compute SHA-256 locally from the downloaded bytes;
6. measure exact byte size locally;
7. reject symlinks and non-regular files;
8. reject an object larger than 268435456 bytes;
9. generate a compact acquisition receipt containing only metadata/fingerprints, never raw CSV rows;
10. bind the V3-02E manifest to the observed SHA-256 and size;
11. delete the downloaded source in an always-run cleanup step.

No credentials are allowed or required.

## 7. Acquisition receipt minimum fields

The compact acquisition receipt MUST include:

- schema version;
- dataset ID;
- variant;
- bucket;
- region;
- exact object key;
- acquisition mode `public_s3_unsigned`;
- source size bytes;
- source SHA-256;
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
- use the exact observed source SHA-256 and size;
- use the official S3 HTTPS publisher reference without query parameters or credentials;
- set acquisition mode `public_s3_unsigned`;
- bind `acquisition_receipt_fingerprint` to the generated receipt;
- use exactly one expected lane: `cic_processed_ml`;
- keep `bots_direct_adapter_authorized=false`.

Because the entire selected source object is already within the resource bound, parent and bounded source may be the same object. No random sampling is authorized.

## 9. Production execution contract

The evidence job MUST execute the production `OfflineRealSourceRunner` from the exact checked-out commit.

It MUST NOT copy adapter logic into the CI script.

Required production path:

`OfflineRealSourceRunner -> CSECICIDS2018Adapter -> EvidenceRecord + scorer-only TruthRecord -> V3-02E coverage decision`

The runner must remain on Linux so the required peak-RSS measurement is real rather than fabricated.

## 10. PASS contract

A CIC real-source evidence run is `PASS` only if all conditions below hold:

- source came from the exact official S3 bucket/object;
- source is <= 268435456 bytes;
- local SHA-256 is valid and bound to the manifest;
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
- acquisition-owned downloaded raw CSV is deleted after execution;
- durable evidence artifact contains metadata/receipts only, never raw CSV content.

There is no `PASS_WITH_WARNING`.

## 11. Insufficient evidence

If the real official file is valid but does not satisfy minimum record/truth coverage, the result MUST remain:

`NOT_ENOUGH_REAL_SOURCE_EVIDENCE`

The workflow MUST NOT lower coverage thresholds or select synthetic/mirror data to force PASS.

## 12. Hard FAIL classes

Any one of the following blocks promotion:

- wrong bucket or object key;
- authenticated/signed acquisition substituted for unsigned public source without a new review;
- mirror or alternate host used;
- source > resource bound;
- source path/symlink escape;
- source digest/size mismatch after binding;
- registry or policy fingerprint mismatch;
- production adapter ID/version drift;
- schema drift silently guessed;
- hidden label/truth leakage;
- deterministic replay mismatch;
- production runner network/model/subprocess authority nonzero;
- Linux RSS measurement unavailable/fabricated;
- raw CSV row/content appears in durable receipt/artifact;
- downloaded raw source remains after workflow cleanup;
- BOTS direct adapter introduced;
- exact-head source lineage not proven.

## 13. Durable outputs

Allowed durable artifacts:

- acquisition receipt JSON;
- V3-02E acceptance manifest JSON;
- production runner receipt JSON;
- compact evidence summary JSON;
- CI logs containing bounded metadata only.

Forbidden durable artifacts:

- downloaded source CSV;
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