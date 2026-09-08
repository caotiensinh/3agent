# Adaptive Learning Evidence Diversity Policy v0.1

## Goal

Define P-04: a deterministic minimum evidence-diversity and independent-source policy for adaptive-learning skill evaluation, using canonical `ExperienceRecord` and `EvidenceReference` provenance.

This version defines and evaluates policy only. It does not change `AdaptiveLearningStore.stage()`, promotion behavior, production materialization, or runtime authority.

## Independence semantics

The only canonical independence identity currently available in adaptive-learning provenance is `source_task_id` / `ExperienceRecord.task_id`.

Therefore v0.1 defines an independent observation as a **distinct source task ID**.

It intentionally does **not** claim that different vendors, devices, interfaces, files, or evidence types are independent physical sources because the current contract does not carry a stable source-device identity that could prove that claim.

Multiple evidence references collected within the same task may increase evidence diversity, but they count as **one** independent observation.

## Canonical input

The evaluator consumes:

- one exact `KnowledgeCandidate`;
- the exact `ExperienceRecord` objects from which that candidate claims provenance;
- one explicit `EvidenceDiversityPolicy`.

Before any diversity calculation, the evaluator reconstructs candidate lineage from those experiences and requires exact equality for:

- source experience IDs;
- source experience SHA-256 values;
- source domains;
- source sensitivities;
- source outcomes;
- de-duplicated source task IDs;
- de-duplicated evidence reference IDs;
- de-duplicated evidence SHA-256 values.

A mismatch fails closed. This prevents substituting unrelated or more diverse evidence for the evidence that actually produced the candidate.

## Policy profiles

### `validated`

Minimums:

- 1 independent source task;
- 1 unique evidence SHA-256;
- 1 source type;
- 1 collection mode;
- no minimum non-synthetic task requirement.

### `approved`

Minimums:

- 2 independent source tasks;
- 2 unique evidence SHA-256 values;
- 1 source type;
- 1 collection mode;
- at least 1 non-synthetic source task;
- synthetic-only provenance is rejected.

### `enterprise`

Minimums:

- 3 independent source tasks;
- 3 unique evidence SHA-256 values;
- 2 source types;
- 1 collection mode;
- at least 2 non-synthetic source tasks;
- synthetic-only provenance is rejected.

The profile values are deterministic defaults, not authority grants. Callers may construct a stricter valid policy explicitly.

## Synthetic evidence

A source task is classified as synthetic only when all evidence attached to that task is either:

- `source_type == synthetic_fixture`, or
- `collection_mode == synthetic`.

Mixed synthetic/real provenance remains visible through separate synthetic and non-synthetic task counts. Approved/enterprise policy cannot be satisfied by synthetic-only provenance.

## Assessment output

`EvidenceDiversityAssessment` is metadata-only and content-addressed. It records:

- exact candidate ID and SHA;
- exact policy SHA;
- profile/domain;
- experience and evidence-reference counts;
- independent task count;
- unique evidence-hash count;
- source-type count;
- collection-mode count;
- synthetic/non-synthetic task counts;
- pass/fail and bounded reason codes;
- deterministic assessment SHA-256.

It does not contain experience summaries, candidate body content, evidence bytes, paths, credentials, prompts, or model output.

## Reason codes

Current deterministic failures include:

- `INSUFFICIENT_INDEPENDENT_TASKS`
- `INSUFFICIENT_UNIQUE_EVIDENCE`
- `INSUFFICIENT_SOURCE_TYPE_DIVERSITY`
- `INSUFFICIENT_COLLECTION_MODE_DIVERSITY`
- `INSUFFICIENT_NON_SYNTHETIC_TASKS`
- `SYNTHETIC_ONLY_EVIDENCE`

Lineage-integrity failures are raised as fail-closed contract errors rather than converted into a weak assessment.

## Authority boundary

Authority is fixed to:

`evaluation_policy_only_no_learning_or_runtime_mutation`

This module has no API for:

- stage/promote/archive/rollback;
- production materialization;
- tool or model invocation;
- shell/network/credential access;
- filesystem mutation;
- automatic quarantine/retirement;
- changing an existing validation receipt.

A `passed=true` assessment means only that the declared minimum diversity policy is satisfied. It does not grant promotion or runtime capability.

## What P-04 closes

P-04 asks for a minimum evidence diversity / independent-source policy. This module provides the deterministic policy, exact provenance binding, default profiles, fail-closed assessment, and audit-safe result contract.

## Explicit non-goals

Separate work remains for:

- wiring this policy as a mandatory promotion check;
- P-03 held-out regression comparison against previous production;
- E-07 candidate-vs-production held-out evaluation;
- physical source/device independence once a stable canonical source identity exists;
- automatic promotion or rollback.

## Regression coverage

Focused tests prove:

- validated one-task behavior;
- approved two-task independence;
- multiple experiences from one task do not create false independence;
- enterprise source-type diversity;
- enterprise positive case;
- synthetic-only rejection;
- mixed synthetic/real accounting;
- stricter custom evidence threshold;
- experience-ID lineage mismatch rejection;
- source-task lineage mismatch rejection;
- deterministic metadata-only output / no mutation authority;
- invalid policy threshold rejection.
