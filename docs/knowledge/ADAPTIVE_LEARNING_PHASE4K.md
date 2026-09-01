# Adaptive Learning Phase 4K — Deterministic Revision Evaluation and Activation Evidence

## Purpose

Phase 4K closes the lifecycle gap after Phase 4J stages an authenticated revision candidate.

It does **not** claim that a revision is semantically better merely because a model proposed it. It establishes a deterministic, evidence-bound eligibility gate before the existing authenticated promotion ceremony may be used.

```text
Phase 4J adverse curation revision
        |
        v
exact completed STAGED receipt + exact authenticated approval
        |
        v
Phase 4K deterministic revision evaluation
        |
        +-- exact active base binding
        +-- locked metadata / source-lineage preservation
        +-- Phase 1 candidate contract re-validation
        +-- Phase 2 deterministic domain re-validation
        +-- rollback-base readiness
        +-- exact Phase 3.1 checkpoint binding
        |
        v
RevisionEvaluationPackage
        |
        +-- FAIL -> STOP / no mutation
        |
        +-- PASS -> candidate -> validated only
                         |
                         v
             existing Phase 4E authenticated reviewer ceremony
                         |
                         +-- approved baseline: validated -> approved
                         |
                         +-- enterprise baseline:
                             validated -> approved (still staged)
                             -> enterprise (then active)
                         |
                         v
             Phase 4H exact-SHA post-activation observation
```

## Exact Phase 4J provenance

A Phase 4K evaluation cannot be created merely from a candidate that resembles a Phase 4J patch.

The evaluator requires:

- the exact `AuthenticatedCurationRevisionApproval`;
- the exact parent-owned Phase 4J revision receipt;
- receipt status `completed`;
- receipt result `STAGED`;
- exact candidate SHA match;
- exact base Knowledge SHA match;
- exact approval ID and proposal ID match;
- the candidate's final curation-approval evidence reference to bind the approval ID;
- the candidate's final evidence hash to equal the exact approval SHA.

This prevents an arbitrary staged candidate from entering Phase 4K by copying only the visible `curation-approval:*` reference shape.

## Deterministic evaluation

`DeterministicRevisionEvaluator` verifies the exact staged candidate against the exact active base.

The package checks:

1. candidate action is `patch`;
2. ownership remains `learner_managed`;
3. the exact active base still exists;
4. the active level is `approved` or `enterprise`;
5. target item and base Knowledge SHA still match the active base;
6. approval item/base/candidate/domain still match that active base;
7. locked metadata is unchanged:
   - domain;
   - kind;
   - sensitivity;
   - risk level;
   - ownership;
   - execution mode;
8. source experience lineage is preserved exactly;
9. Phase 4J approval evidence is the exact one-item extension of base evidence;
10. title/content/scope contain an actual revision;
11. secret knowledge remains unsupported;
12. the Phase 1 candidate contract still validates;
13. Phase 2 deterministic domain validation passes;
14. the revision introduces no new deterministic domain-safety reason relative to the base;
15. the exact active base is still available as the rollback target.

The result is metadata-only. It contains hashes, identifiers, check results, changed-field names and checkpoint metadata. It does not contain learned title/content/scope, prompts, task text, credentials, session tokens or raw evidence.

`PASS` means only:

> this exact staged revision satisfies the deterministic eligibility and safety checks required to proceed to the governed review lifecycle.

It does **not** mean:

- the model proved the revision correct;
- the revision is causally better than the old knowledge;
- the revision may activate itself;
- the reviewer may be bypassed.

## Candidate -> validated gate

A PASS package at candidate level may be persisted only as the existing `validated` level.

`RevisionEvaluationBoundCheckpointAuthority` adds one narrow expected-state check to the existing checkpoint authority. The expected checkpoint sequence, checkpoint SHA and state SHA are verified inside the mutation lock before the existing promotion operation writes `validated`.

If learning state changed after evaluation, the transition fails closed.

This step does not activate the revision.

## Activation remains Phase 4E

Phase 4K creates no parallel activation gateway.

`RevisionActivationGate` first requires a fresh Phase 4K PASS package, then delegates to `AuthenticatedLearningPromotionService` from Phase 4E.

Therefore all existing Phase 4E controls remain authoritative:

- valid local WorkSpace session;
- explicit reviewer allowlist;
- exact allowed promotion level;
- server-derived stable local principal;
- explicit Network/Security domain-review entitlement;
- exact candidate/receipt identity;
- expected checkpoint state checked inside the promotion mutation lock.

Role name such as `admin` still grants no learning-review authority by itself.

## Enterprise baseline protection

Phase 3 already prevents an `approved` patch from replacing an active `enterprise` baseline.

Phase 4K preserves that behavior deliberately.

For an enterprise base, a revision follows:

```text
candidate
   -> validated
   -> approved     # remains staged; enterprise base stays active
   -> enterprise   # only this transition can replace enterprise base
```

Each approved/enterprise transition requires a fresh Phase 4K package and the existing Phase 4E authenticated ceremony.

## Rollback readiness

Phase 4K does not execute rollback automatically.

`RevisionRollbackPlan` contains only:

- item ID;
- exact prior active Knowledge SHA as rollback target;
- exact revised Knowledge SHA expected to be current;
- `operator_only=true`;
- `automatic_rollback=false`.

Execution, if an operator chooses it, remains the existing Phase 3/3.1 checkpointed rollback capability. Rollback can target only a previously active exact version and still fails closed on stale current state.

## Post-activation effectiveness

Phase 4K reuses Phase 4H rather than creating a new telemetry subsystem.

`compare_revision_effectiveness()` accepts only Phase 4H signals bound to:

- the exact item ID;
- the exact old Knowledge SHA;
- the exact revised Knowledge SHA;
- the same domain;
- the existing `observational_non_causal` interpretation.

It reports deltas such as isolated observations, verified successes, failures and waiting-human outcomes.

The comparison remains review-only. It does not emit an automatic `better`, promotion, rollback or remediation decision because Phase 4H evidence is observational rather than causal.

## No automatic rejection mutation

A failed or rejected Phase 4K evaluation does not mutate the learning store.

The revision may remain staged for human inspection or future explicitly governed handling. Phase 4K does not invent an archive/delete path merely to make the loop look closed.

## Security invariants

Phase 4K adds no:

- LLM judge;
- automatic promotion or enterprise upgrade;
- automatic rollback/archive/delete;
- remediation;
- policy mutation;
- shell or subprocess authority;
- network authority;
- Git commit/deployment authority;
- checkpoint signing key exposure;
- witness-write authority for the model;
- model-weight training;
- trusted-core self-rewrite;
- daemon, service, database, vector store or framework.

The canonical rule remains:

```text
Model proposes.
Evidence validates.
Policy authorizes.
```

## Acceptance

Tests cover at minimum:

1. an exact Phase 4J STAGED revision produces a metadata-only PASS package;
2. a Phase 4J completed STAGED receipt is mandatory;
3. PASS can move only `candidate -> validated` before authenticated review;
4. stale evaluation fails before validation mutation;
5. approved activation reuses Phase 4E rather than bypassing it;
6. rollback readiness binds exact old/new Knowledge SHA and stays operator-only;
7. an enterprise baseline stays active when the patch reaches only approved;
8. enterprise replacement occurs only after explicit enterprise promotion;
9. Network/Security activation still requires Phase 4E domain reviewer entitlement;
10. post-activation old-vs-revised comparison stays Phase 4H observational/non-causal;
11. the Phase 4K validation expectation cannot be reused for another mutation kind;
12. existing Phase 1–4J and deployment regression gates remain green on the same exact PR head.

## Completion boundary

With Phase 4K, the controlled adaptive-learning lifecycle is:

```text
verified experience
 -> bounded reflection
 -> staged candidate
 -> authenticated promotion
 -> reuse
 -> observational effectiveness measurement
 -> deterministic curation proposal
 -> authenticated revision
 -> exact staged patch
 -> deterministic revision evaluation
 -> validated
 -> authenticated activation
 -> exact-SHA post-activation observation
 -> operator-controlled rollback if explicitly chosen
```

This is a closed learning-and-curation lifecycle without granting the learner authority to rewrite the trusted core or expand runtime capability.