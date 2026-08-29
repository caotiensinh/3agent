# D7-03 / D7-04 — Regression and Adversarial Evaluation Corpora

## Scope

This layer extends the existing deterministic `workspace-eval` replay engine. It does not add a second evaluation framework and it does not claim model/GPU benchmark evidence that has not run.

## Corpus classes

`workspace-evaluation-corpus/v1` now supports explicit repository-owned classes:

- `golden` — D7-01 control-plane expected behavior;
- `regression` — D7-03 known production invariants that must not drift;
- `adversarial_security` — D7-04 deny/fail-closed security cases.

The original D7-01 golden file intentionally remains in its legacy shape without a `corpus_class` field. The loader resolves that shape as `golden` while preserving the exact canonical payload used for its existing SHA-256 identity.

## D7-03 regression coverage

The regression corpus protects deterministic behavior that is security- or production-critical:

- restricted sensitive-query routing remains internal-only;
- secret analysis retains denied egress, denied cache sharing and denied raw logging;
- code-fix source/write scope and write-capable tool set remain explicit;
- public-web document summary remains public/allowlisted and does not become trusted-local-only;
- confidential retrieval remains local, evidence-required and small-first.

Replay assertions now include source scope, write scope, cache policy, raw logging policy and model-locality in addition to the original network/tool/validator/route/budget checks.

## D7-04 adversarial/security coverage

The adversarial corpus requires deterministic rejection of attempts to:

- enable public web for restricted or secret work;
- combine NO_LLM retrieval with public web;
- use NO_LLM outside the authorized retrieval task type;
- attach a model output schema to the NO_LLM lane;
- add write authority to NO_LLM retrieval;
- invoke the web gateway without public allowlisted egress;
- expose the web gateway to internal tasks;
- introduce unknown tool authority.

A rejection is an expected replay outcome. Evaluation fails if any of these cases becomes accepted.

## Evidence and privacy

Replay evidence is metadata-only and lineage-bound to an exact 40-hex Git source ref. These corpora contain no production prompts, business data, credentials, web content, model responses or holdout labels.

## Non-goals

This does not close D7-05 edge/large-context, D7-06 efficiency/cache/concurrency, or D7-08 production promotion admission. Those remain separate gates and must not be inferred from deterministic control-plane replay.
