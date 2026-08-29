# WorkSpace D6 Deterministic NO_LLM Retrieval v1

## Purpose

D6-01/D6-02 establish a real deterministic execution route rather than merely labelling a normal model workflow as `NO_LLM`.

The first production-safe scope is intentionally narrow:

```text
local imported public-knowledge retrieval
```

It uses no model client, no Internet gateway and no escalation path.

## Route order

The deterministic authority order is:

```text
TaskContract compiler
→ data/network/tool policy
→ deterministic_only eligibility
→ model policy = none/none
→ route decision = NO_LLM
→ local ContextEngine retrieval
→ deterministic evidence validator
→ ValidatorLedger.evaluate(task_id)
→ DONE only when verified=true
```

`DeterministicRoutePlanner` only projects the already-authoritative TaskContract into a compact reason-coded route. It does not inspect raw task content and cannot grant capabilities.

## Contract restrictions

`deterministic_only=True` is accepted only when:

- `task_type=retrieval`;
- `public_web=false`;
- no model output schema is requested;
- tools are limited to local `search_docs` / `read_file` capability.

The resulting model policy is:

```text
initial_tier = none
max_tier = none
escalation_allowed = false
```

and the execution budget has zero retries and zero escalations in v1.

A caller cannot use the NO_LLM flag to obtain Internet, write, model, shell or other authority.

## Verified execution

`workspace-retrieval` creates a normal WorkSpace task and binds an immutable retrieval TaskContract.

Required low/medium-risk validators are:

- `policy`
- `evidence`

The evidence validator passes only when ContextEngine returns local evidence and its hard-budget invariant passes. Ledger references contain only compact SHA-256 artifact identifiers, not evidence bodies or the query.

`TaskStatus.DONE` is written only after `ValidatorLedger.evaluate(task_id).verified == true`.

High/critical-risk retrieval also requires `human`. The deterministic executor cannot self-authorize that validator and therefore returns `WAITING_HUMAN` until independent human validation exists.

## Zero-inference property

The executor does not construct `Orchestrator`, Ollama clients or model workers. It directly composes:

- `TaskStore`
- `TaskContractCompiler`
- `DeterministicRoutePlanner`
- `LocalKnowledgeIndex`
- `ContextEngine`
- `ValidatorLedger`
- `ArtifactManager`

Regression coverage verifies a successful NO_LLM task creates no inference telemetry even when `WORKSPACE_INFERENCE_TELEMETRY` is configured.

## Operator command

```bash
workspace-retrieval \
  --title "Local evidence lookup" \
  --query "GPU inference efficiency" \
  --knowledge-root /var/lib/workspace-knowledge-public
```

Default sensitivity is `confidential`; the local public mirror is an inward-only evidence source and this command performs no networking.

## Security properties

- confidential task identity still has no Internet route;
- no egress broker is used;
- no model invocation or escalation occurs;
- no raw evidence/query is copied into ValidatorLedger;
- missing evidence fails closed;
- high-risk human validation cannot be synthesized by code or a model;
- route decisions can reduce authority but cannot increase it.

## Remaining D6 work

This closes the explicit NO_LLM retrieval lane and establishes reason-coded route decisions. Remaining D6 work includes binding model retry/escalation attempts to exact TaskContract execution budgets across every adaptive model path and proving security monotonicity exhaustively.
