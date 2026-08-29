# D0-05 Authoritative Failure Taxonomy

WorkSpace uses one deterministic runtime failure taxonomy for recovery decisions.

## Security rule

Failure handling is control-plane logic. Model output, prompts, retrieved text, tool output and external content cannot choose a failure family or authorize recovery.

Unknown failures fail closed.

## Stable schemas

- Registry: `workspace-failure-taxonomy/v1`
- Decision: `workspace-failure-decision/v1`
- Registry ID: `workspace-runtime-failure-taxonomy-v1`

Decision metadata is content-free: canonical failure code, observed compact reason code, exception type, family, recovery action and permitted operations. Raw exception messages are not required or logged by the taxonomy.

## Failure families

| Canonical code | Family | Default recovery |
| --- | --- | --- |
| `POLICY_DENIED` | policy | hard stop |
| `SECURITY_DENIED` | security | hard stop |
| `CAPABILITY_DENIED` | capability | hard stop |
| `CONTRACT_INVALID` | contract | hard stop |
| `EVIDENCE_MISSING` | evidence | collect evidence |
| `VALIDATION_FAILED` | validation | hard stop |
| `HUMAN_REVIEW_REQUIRED` | human gate | human review |
| `BUDGET_EXHAUSTED` | budget | hard stop |
| `TOOL_TIMEOUT` | tool | retry same tool only within budget |
| `TOOL_FAILURE` | tool | hard stop |
| `RESOURCE_BUSY` | resource | wait/fallback within authority |
| `RESOURCE_ADMISSION` | resource | fallback within authority |
| `MODEL_FAILURE` | model | retry/fallback/escalate only within TaskContract |
| `MODEL_OUTPUT_INVALID` | model output | bounded regeneration |
| `UNKNOWN_FAILURE` | unknown | hard stop |

## Recovery invariants

1. Recovery never expands TaskContract authority.
2. Security/policy/capability/contract denials are terminal.
3. Budget exhaustion is terminal; recovery cannot mint more budget.
4. Missing evidence authorizes evidence collection, not a model retry.
5. Model failure may retry/fallback/escalate only when both the taxonomy and immutable TaskContract permit it.
6. Resource admission may fall back only inside the same authority envelope.
7. Unknown errors never become retryable by default.

## Runtime integration

`MeteredOllamaWorkerPool` and `MeteredAdaptiveOllamaClient` consult the taxonomy before fallback/escalation and before retry budget consumption or fallback telemetry. Existing TaskContract model authority and persistent execution budgets remain separate required gates.

The effective order is:

```text
observed failure
  -> failure taxonomy recovery authorization
  -> immutable model/capability authority check
  -> persistent retry/escalation budget reservation
  -> metadata-only telemetry
  -> fallback/retry side effect
```

A taxonomy decision is necessary but never sufficient to expand privileges or resource limits.
