# Adaptive Learning Held-Out Skill Benchmark Contract v0.1

## Goal

Define the missing P-01 contract for a content-addressed held-out skill benchmark without introducing a benchmark runner, promotion decision, or runtime authority.

The contract answers only:

1. Which immutable benchmark cases belong to the precommitted held-out set?
2. Which exact candidate is being bound to that set?
3. Can the system prove that candidate learning-source task/evidence lineage does not overlap the held-out cases?

## Canonical reuse

This contract reuses `KnowledgeCandidate` as the candidate identity and lineage source. It does not introduce a second candidate object, learning store, skill registry, or evaluator.

The existing `adaptive_learning_evaluation.py` remains the deterministic offline/synthetic evaluation foundation. This PR does not redefine its corpus semantics or claim that the existing corpus is automatically held out.

## Contracts

### `HeldOutBenchmarkCaseRef`

Metadata-only reference to one immutable case:

- `case_id`
- `case_sha256`
- `source_task_id`
- `domain`
- `kind`

No prompt, expected answer, skill body, credential, evidence bytes, or execution instruction is stored in the held-out identity contract.

### `HeldOutSkillBenchmark`

Precommitted benchmark identity:

- exact 40-hex Git `source_ref`
- exact domain and kind
- bounded 1..128 immutable case references
- unique case IDs, case hashes, and held-out task IDs
- deterministic `benchmark_sha256`
- fixed selection policy: `precommitted_content_addressed_before_candidate_evaluation`

The benchmark has `evaluation_contract_only_no_learning_or_runtime_mutation` authority.

### `HeldOutSkillBenchmarkBinding`

Binds one exact `KnowledgeCandidate(kind="skill")` to one exact benchmark SHA and records only lineage metadata required to prove separation:

- candidate ID and SHA
- target/base knowledge identity where present
- candidate source task IDs
- candidate source experience hashes
- candidate evidence hashes
- held-out task IDs and held-out case hashes
- deterministic binding SHA

Binding fails closed when any held-out task is already part of the candidate's source-task lineage or when a held-out case hash overlaps candidate evidence/source-experience hashes.

## Security and authority boundary

This module has no API for:

- benchmark execution;
- model/tool invocation;
- candidate stage/promote/archive/rollback;
- production materialization;
- filesystem mutation;
- network access;
- credential access;
- pass/fail or promotion decisions.

A successful binding proves only separation of the exact declared identities. It does not prove candidate quality.

## What P-01 closes

P-01 requires a held-out skill benchmark contract. This PR provides the immutable case-set and candidate-separation contract required before candidate-vs-production regression evaluation can be trusted.

## Explicit non-goals

The following remain separate work:

- **P-03** regression comparison with the previous production version;
- **E-07** candidate revision versus current production skill on held-out cases;
- **P-04** minimum evidence diversity / independent-source policy;
- benchmark runner implementation;
- score aggregation and acceptance thresholds;
- automatic promotion, rollback, quarantine, or retirement.

## Acceptance tests

Focused regressions prove:

- deterministic content-addressed benchmark identity;
- exact candidate-to-benchmark binding;
- training-task overlap rejection;
- evidence/hash overlap rejection;
- duplicate case/task rejection;
- domain/kind mismatch rejection;
- exact Git source-ref enforcement;
- nonzero/forged overlap rejection;
- empty benchmark rejection;
- metadata-only output with no production mutation authority.
