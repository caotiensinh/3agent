# Adaptive Learned Skill Supersession V0.1

## Purpose

Close the production lifecycle gap after a Phase 4K revision has been deterministically evaluated and explicitly activated through the existing authenticated learning promotion boundary.

This component does not decide whether a revision is good, does not approve it, and does not mutate adaptive-learning state. It mirrors an already-authorized exact active learning version into the canonical production skill registry.

## Canonical prerequisites

A production supersession is allowed only when all of the following already exist:

1. A `RevisionEvaluationPackage` with `result=PASS` for `kind=skill`.
2. The revision candidate has been explicitly promoted by `AuthenticatedLearningPromotionService` to `approved` or `enterprise`.
3. The authenticated checkpoint currently matches that promotion result.
4. The adaptive-learning active item is the exact revised knowledge and candidate version in the Phase 4K package.
5. The learning ledger contains the exact activation transition from the base knowledge SHA to the revised knowledge SHA and binds the authenticated promotion actor.
6. Exactly one enabled canonical production skill represents the base candidate version.

No model output, prompt text, filesystem marker, or registry field may substitute for these prerequisites.

## Immutable production versions

Production `SKILL.md` bytes are immutable versions.

Supersession creates a new content-addressed skill directory and registry entry. It never edits or deletes the previous production skill directory. The previous registry entry becomes `enabled=false`; the revised entry becomes `enabled=true`.

This provides three properties:

- a runtime never observes a partially overwritten reviewed skill;
- exact previous production bytes remain available for operator rollback;
- restart recovery depends only on the canonical registry plus immutable skill packages.

## Authority invariants

Supersession must not create a second authority system.

- Adaptive-learning selection remains owned by `LearningRetrievalGateway`.
- Revision safety remains owned by Phase 4K.
- Promotion remains owned by `AuthenticatedLearningPromotionService`.
- Learning rollback remains owned by `LearningOperatorGateway`.
- Production loading remains owned by `ApprovedSkillLoader` / `ApprovedSkillCatalog`.
- The supersession manager grants no network, credential, shell, deployment, or persistent self-modification capability.
- `instruction_only=true` and all existing denied authority flags are preserved from the base production entry.
- Agent scope is preserved exactly from the base production entry.

## Supersession transaction

The production mirror performs the following fail-closed transaction:

1. Validate the exact Phase 4K PASS package and canonical promotion result.
2. Verify the current authenticated learning checkpoint and exact active revision.
3. Verify the exact activation ledger transition and promotion actor.
4. Acquire the existing production materialization lock.
5. Audit the canonical production registry.
6. Resolve exactly one enabled base skill from immutable candidate provenance.
7. Render and security-scan a new instruction-only production document using the existing candidate-skill rendering rules without relaxing the create-only CandidateSkill admission surface.
8. Stage the new skill in a hidden directory.
9. Preserve the base authority policy and agent scope; add exact supersession provenance to the revised registry entry.
10. Rename the staged directory to its final content-addressed name.
11. Atomically replace the registry, disabling the base entry and enabling the revised entry.
12. Re-audit and load the revised skill with the canonical loader.
13. If post-commit verification fails, restore the previous registry and remove only the newly-created revision directory.

The old production directory is never deleted on a successful supersession.

## Production rollback synchronization

Production rollback is a separate mirror operation and may run only after an operator has already completed the canonical adaptive-learning rollback.

The manager:

1. Validates the `RevisionRollbackPlan` (`operator_only=true`, `automatic_rollback=false`).
2. Verifies the current authenticated checkpoint.
3. Requires the adaptive-learning active item to equal `target_knowledge_sha256`.
4. Requires the latest learning-ledger event for the item to be an exact `rollback` transition from `expected_current_sha256` to `target_knowledge_sha256`.
5. Acquires the same production lock and audits current production state.
6. Resolves the disabled target production version and enabled revised production version by exact `learning-item:<item_id>:<knowledge_sha256>` provenance.
7. Fully validates the disabled target package before enabling it.
8. Atomically flips registry state: target enabled, revised disabled.
9. Re-audits and loads the restored target through `ApprovedSkillLoader`.
10. Restores the previous registry if post-commit verification fails.

No production files are rewritten or reconstructed during rollback.

## Failure semantics

All ambiguity is fail-closed:

- stale Phase 4K package;
- mismatched promotion result;
- checkpoint mismatch;
- active learning version mismatch;
- missing or mismatched activation/rollback ledger event;
- zero or multiple matching production versions;
- tampered enabled base package;
- tampered disabled rollback target package;
- agent-scope or authority-policy widening;
- production name collision;
- canonical loader rejection.

A failure before registry commit leaves current production state unchanged. A failure after registry commit restores the previous registry; supersession also removes only the newly-created revision directory.

## Non-goals

V0.1 does not:

- generate or rank revisions;
- infer effectiveness or causality;
- approve revisions;
- promote learning state;
- automatically roll back learning state;
- overwrite or delete historical production versions;
- change tool/network/credential authority;
- introduce another registry, loader, selector, or effectiveness store.
