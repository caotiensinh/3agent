# Adaptive Learning Phase 4J — Authenticated Revision Reflection

## Status

Phase 4J adds a **review-authorized, stage-only self-improvement path** for already-active learner-managed knowledge. It does not activate revised knowledge automatically.

The final boundary is:

```text
Phase 4H measured outcome
  -> Phase 4I exact-SHA curation proposal
  -> authenticated local reviewer approval
  -> bounded local revision packet
  -> isolated no-tool revision worker
  -> deterministic KnowledgeCandidate(action=patch)
  -> Phase 1 contract validation
  -> Phase 2 domain validation
  -> checkpoint-expected LearningStagingGateway.stage()
  -> STOP
```

## Why Phase 4J is separate from Phase 4B

Phase 4B starts from a Phase 4A `VerifiedLearningSourceEnvelope`, which represents a verified-success task. Phase 4J is triggered by adverse or unresolved observations after knowledge reuse. Fabricating a verified-success envelope for those observations would corrupt provenance.

Phase 4J therefore reuses the safe mechanics of Phase 4B — local loopback inference, isolated process, strict JSON, no tools and stage-only persistence — but uses separate curation revision contracts bound directly to Phase 4H/4I evidence and an authenticated reviewer approval.

## Eligible proposals

Only these Phase 4I actions may enter revision reflection:

- `REVISE_OR_ARCHIVE_REVIEW`
- `DOMAIN_REVISE_OR_ARCHIVE_REVIEW`

These actions are explicitly excluded from revision reflection:

- `OBSERVE_MORE`
- `KEEP_ACTIVE_REVIEW`

A support signal cannot silently become a rewrite request.

## Reviewer boundary

`AuthenticatedCurationRevisionApprovalService` resolves the principal from a valid local WorkSpace session and reuses the existing Phase 4E reviewer allowlist.

Important properties:

- admin role alone is not authority;
- learned content cannot nominate a reviewer;
- external profile/department text is not authority;
- the exact active knowledge level (`approved` or `enterprise`) must be present in the reviewer's Phase 4E `allowed_levels` grant;
- Network/Security requires the matching explicit domain-review entitlement;
- approval binds the exact proposal ID and SHA, proposal-set SHA, active item/knowledge/candidate SHA, curation action and exact Phase 3.1 checkpoint sequence/checkpoint SHA/state SHA;
- approval contains no capability grants.

## Locked model authority

The revision worker may propose only:

- revised title;
- revised content;
- revised scope;
- a bounded revision reason;
- or `NO_REVISION_VALUE`.

The trusted parent locks and inherits:

- domain;
- kind;
- sensitivity;
- risk level;
- ownership=`learner_managed`;
- action=`patch`;
- execution mode;
- target item ID;
- exact base knowledge SHA.

The model cannot emit those fields in the strict result schema.

## Provenance

The patch candidate preserves the active candidate's verified source-experience lineage. Phase 4J does **not** fabricate a `verified_success` experience from adverse observations.

The authenticated curation revision approval SHA is appended as metadata evidence before staging. If the existing candidate has no remaining evidence capacity, revision fails closed instead of dropping lineage.

## Active knowledge as untrusted reference data

The current active title/content/scope are included in a bounded local packet so the worker can propose a correction. They remain explicitly marked `untrusted_reference_data_only` and never become system/developer authority.

The packet excludes raw task prompts, raw conversations, credentials, arbitrary paths, arbitrary URLs and runtime capability grants. Secret-classified active knowledge fails closed until a dedicated secret revision policy exists.

## Isolated worker

`adaptive_learning_curation_revision_worker.py`:

- receives one bounded JSON packet over stdin;
- talks only to an explicitly configured loopback Ollama endpoint;
- has no task-store, learning-store, checkpoint, operator-gateway, authentication, shell, Git or deployment authority;
- returns one strict raw JSON result;
- rejects markdown wrappers and additional fields;
- uses temperature 0 and no reasoning trace request.

## Exact-state staging

A reviewer approval must remain valid while the local model is running. Phase 4J therefore adds `CurationRevisionBoundCheckpointAuthority`.

The approved checkpoint sequence, checkpoint SHA and state SHA are checked **inside the stage mutation lock** immediately before `store.stage()` executes. If any learning-store mutation occurred while the model was running, staging fails closed.

The existing `LearningStagingGateway` remains the only persistence surface exposed by the coordinator. No promotion or archive API is added.

## Replay suppression

A parent-owned metadata-only receipt records one claim/completion for the exact approval/proposal/base-SHA tuple.

This avoids repeatedly spending inference on the same reviewed proposal, including `NO_REVISION_VALUE`. The receipt is not promotion authority and is not stored inside the authenticated learning database.

## Candidate checks

Before staging, the trusted parent requires:

1. exact proposal/approval/set binding;
2. current checkpoint equals the reviewer-approved checkpoint;
3. current active item still matches the exact knowledge SHA, candidate SHA, level and domain;
4. sensitivity is not `secret`;
5. strict worker output;
6. the proposed title/content/scope actually change something;
7. exact patch target/base binding;
8. `KnowledgeCandidate.validate()` succeeds;
9. `AdaptiveLearningDomainValidator.validate()` returns no deterministic domain safety reasons;
10. exact approved checkpoint is still current inside the stage lock.

## Explicit non-goals

Phase 4J does not add:

- automatic promotion or enterprise upgrade;
- automatic archive/delete/rollback;
- unattended remediation;
- runtime network/shell/credential authority;
- public Internet research;
- Git commit/deployment authority;
- checkpoint signing/witness authority in the worker;
- arbitrary file access;
- model-weight training;
- core-code self-rewrite.

A staged revision must still pass the existing validation and authenticated promotion path before it can become active.

## Security principle

**Outcome evidence may trigger a reviewed proposal. A reviewer may authorize one bounded revision attempt. The model may propose content. Deterministic validation may stage it. Only the existing authenticated promotion boundary can make it active.**
