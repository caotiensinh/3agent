# Adaptive Learning Phase 1 — Deterministic Contracts

Status: IMPLEMENTED CONTRACT FOUNDATION / NO BACKGROUND LEARNER

This phase converts the WorkSpace self-improvement doctrine into runtime-inert deterministic data contracts. It does **not** enable autonomous learning, network access, shell execution, remediation, skill writes, or core self-modification.

## Implemented boundary

`src/three_agent/adaptive_learning_contract.py` defines the first control-plane records:

- `EvidenceReference` — metadata-only evidence lineage with SHA-256, task, sensitivity and collection mode.
- `ExperienceRecord` — bounded task experience tied to authorized evidence.
- `KnowledgeCandidate` — staged memory/skill/analytical/reference proposal with scope, risk, ownership and execution mode.
- `ContradictionRecord` — explicit conflicting evidence that can block promotion.
- `LearningValidationReceipt` — validator results plus optional human/domain reviewer identity.
- `AdaptiveLearningPolicy` — monotonic `candidate -> validated -> approved -> enterprise` transition decisions.

## Fail-closed invariants

1. Payload schemas are strict; unexpected fields are rejected. Learned content cannot add a `network_authority`, shell authority, credential authority, or similar field because no such contract field exists.
2. Persistent candidate text is checked for hidden Unicode and common policy/persistence-injection patterns before it can become a candidate.
3. `memory` and `skill` candidates require source experiences whose result is `verified_success`; unresolved/failed work cannot silently become procedure.
4. `patch` and `supersede` candidates require the exact SHA-256 of the current base item. This is the deterministic read-before-write lineage requirement.
5. Evidence IDs and evidence hashes remain paired and bounded.
6. An open contradiction blocks upward promotion.
7. Promotion cannot skip levels.
8. Every promotion step requires a matching validation receipt bound to the candidate content hash and evidence lineage.
9. Network/Security promotion to `approved` or `enterprise` requires both human review and a domain reviewer.
10. `enterprise` promotion always requires human review; learner-managed material cannot silently adopt itself as an enterprise baseline.

## Relationship to existing WorkSpace promotion gate

This phase does not replace `promotion_gate.py`. The adaptive-learning gate controls **knowledge lifecycle**. The existing promotion gate remains the repository/evaluation gate for shipping software and benchmarked changes.

Future implementation should bridge the two only after the Network/Security/Analyst offline corpus exists:

```text
Experience / evidence
  -> KnowledgeCandidate
  -> adaptive validation
  -> approved knowledge candidate
  -> replay / benchmark evidence
  -> existing PromotionPipeline where software/release promotion is involved
```

A positive adaptive-learning decision never grants runtime capability.

## Verification

`tests/test_adaptive_learning_contract.py` covers the initial contract with checks for:

- candidate round-trip and stable hash;
- unexpected authority-field rejection;
- unresolved failure not becoming memory/skill;
- analytical unresolved candidate remaining non-authoritative;
- patch read-before-write hash;
- persistence/policy injection rejection;
- validation receipt requirement;
- contradiction blocking;
- Network/Security human + domain approval;
- no skipped promotion levels;
- mandatory human adoption for enterprise level.

The next phase is an **offline/synthetic validation corpus**, not a background reflection agent.