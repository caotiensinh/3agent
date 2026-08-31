# Adaptive Learning Phase 4A — Deterministic Verified-Experience Admission

Status: IMPLEMENTED ADMISSION FOUNDATION / NO REFLECTION LLM

Phase 4A creates the deterministic boundary between completed WorkSpace workflows and any future Reflection Worker.

> The model must not decide which of its own past work is trustworthy enough to learn from.

Admission therefore runs without an LLM.

## Architecture

```text
TaskStore
  + exact TaskContract
  + authoritative ValidatorLedger
  + workflow-run/v1 manifest
        |
        v
DeterministicLearningAdmission
        |
        +-- deterministic rejection reason
        |
        `-- VerifiedLearningSourceEnvelope
                    |
                    v
              future Phase 4B
```

Phase 4A does not create `KnowledgeCandidate` objects and does not write the adaptive-learning store.

## Verified-success rule

A `verified_success` envelope requires all of the following:

1. authoritative task exists and current status is exactly `DONE`;
2. TaskContract exists, its canonical SHA-256 matches the stored digest, and the complete reconstructed contract passes `TaskContract.validate()`;
3. the contract requires evidence;
4. `ValidatorLedger.evaluate()` recomputes a fully verified state with every required validator passed;
5. `evidence` is one of the required validators;
6. the final evidence-validator event is passed and contains at least one content-addressed `sha256:<digest>` reference;
7. the workflow manifest is exact top-level `workflow-run/v1`, has bounded collection shapes and timezone-aware ordered timestamps;
8. manifest task identity equals the authoritative task;
9. manifest outcome is `completed` / `DONE`, business stage is `task_completed`, and `error` is null;
10. manifest verification equals the freshly recomputed authoritative verification state.

`FAILED`, `WAITING_HUMAN`, partial and intermediate states cannot become successful procedural learning.

Phase 4A currently rejects unsuccessful work rather than retaining it as reusable guidance. Any future negative-learning feature must use an explicit diagnostic type that can never satisfy the `verified_success` requirement for memory/skill creation.

## Contract integrity

Phase 4A does not trust a subset of TaskContract fields.

```text
stored contract JSON
       |
       +-> canonical SHA-256 == stored contract SHA
       |
       +-> reconstruct all nested budget/policy structures
       |
       `-> TaskContract.validate()
```

This prevents admission from silently ignoring malformed or security-invalid contract state.

## Manifest handling

The exact manifest bytes are SHA-256 hashed for audit, but manifest free-form content is not copied into the learning envelope.

The envelope excludes:

- task request, prompt and chat history;
- upload IDs/content;
- research/presentation/daily artifact paths;
- audience/purpose/options text;
- execution-budget and model-authority details;
- raw validator evidence references;
- manifest timestamps.

An added top-level field such as `raw_request` is schema-rejected. Timestamps must parse as timezone-aware ISO datetimes and completion cannot precede start.

## Authoritative verification, not manifest self-assertion

The manifest verification snapshot is audit data, not independent proof.

```text
ValidatorLedger.evaluate(task_id)
        |
        v
fresh verification
        |
        +-- must equal manifest.verification
```

Any new validator event makes the old manifest verification snapshot stale until reevaluated.

## Evidence privacy and quality

Phase 4A does not hash arbitrary local paths into the envelope. The final evidence validator must already provide content-addressed evidence references:

```text
sha256:<64 lowercase hex>
```

Non-content-addressed evidence references are rejected with `LEARNING_EVIDENCE_NOT_CONTENT_ADDRESSED`.

This avoids leaking local paths and prevents weak path identity from being treated as evidence identity.

## Idempotency and anti-self-reinforcement

The exact `manifest_sha256` remains in the envelope for audit, but **does not control trusted-experience identity**.

The deterministic `admission_id` is derived from authoritative provenance:

```text
task identity/status
 + contract SHA
 + complete validator-event provenance SHA
 + recomputed verification
 + sensitivity/risk
 + final content-addressed evidence hashes
       |
       v
provenance SHA-256
       |
       v
admission:<digest>
```

Consequences:

- repeated admission with identical authoritative provenance returns the same ID;
- changing non-authoritative manifest bytes changes `manifest_sha256` but does not manufacture a new trusted experience;
- changing validator/evidence provenance makes the old manifest stale;
- after deterministic reevaluation, genuinely changed authoritative provenance receives a new admission ID.

This specifically reduces repeated self-reinforcement from replaying the same successful task with cosmetically different manifests.

## Sensitivity monotonicity

Default envelope sensitivity equals the bound TaskContract sensitivity.

A trusted caller may request stricter classification, never weaker classification:

```text
public < internal < confidential < restricted < secret
```

## No capability transfer

`VerifiedLearningSourceEnvelope` contains no allowed tools, write scope, network scope, execution budget, model policy/authority, credentials, deployment authority, checkpoint authority or Git authority.

It carries an explicit empty `capability_grants` list.

Knowledge provenance must never be interpreted as runtime authority.

## Relationship to Phase 3.1

Phase 3.1 protects learning persistence:

```text
immutable learning versions
 -> hash-chained ledger
 -> authenticated checkpoint journal
 -> trusted-head anti-replay witness
```

Phase 4A protects source admission. Neither replaces the other.

## Phase 4B gate

A future Reflection Worker may consume only an admitted envelope plus a separately designed bounded local content summary.

It must run outside checkpoint/operator trust and must not receive direct learning-DB write, operator gateway, HMAC key, witness write, promotion/archive/rollback, shell, public/LAN network, credentials, or Git/deployment authority.

Its persistent output must terminate at the Phase 3.1 stage-only capability after producing a contract-valid `learner_managed` candidate.

## Acceptance coverage

Tests cover:

1. verified DONE admission and exact idempotency;
2. FAILED / WAITING_HUMAN / non-DONE rejection;
3. missing and failed required-validator rejection;
4. non-content-addressed evidence rejection;
5. contract-digest mismatch rejection;
6. manifest task/verification tamper rejection;
7. raw-request-field and invalid-time rejection;
8. sensitivity downgrade rejection and stricter-classification allowance;
9. raw request, credential-looking content, artifact paths, timestamps and authority fields absent from envelope;
10. non-authority manifest change changes only manifest audit SHA, not trusted-experience identity;
11. new validator provenance makes an old manifest stale;
12. reevaluated authoritative provenance produces a new admission ID.

## Still intentionally absent

Phase 4A adds no LLM reflection, autonomous memory/skill creation, automatic promotion, curation, source self-modification, Network/Security remediation, network access or credential access.
