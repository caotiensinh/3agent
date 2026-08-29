# D6-04 — Model Authority Monotonicity

## Status

Implemented as the task-scoped authority boundary for model-tier selection and escalation.

## Core invariant

A stronger model may receive **more inference capability**, but never more authority.

The immutable `TaskContract` remains authoritative for:

- sensitivity and risk;
- allowed source identifiers;
- allowed tools;
- write scope;
- network scope;
- initial model tier;
- maximum model tier;
- whether escalation is allowed.

Model output, prompt text, failures, worker selection and model configuration cannot expand this envelope.

## Frozen authority envelope

`TaskModelAuthority` is projected deterministically from the already-validated TaskContract before runtime policy PASS. Its canonical fingerprint includes the authority-bearing fields above.

Only compact metadata is persisted:

- authority SHA-256 fingerprint;
- initial model tier;
- maximum model tier;
- escalation-allowed flag.

Raw request text, evidence, source bodies, credentials and business content are not copied into authority telemetry or the validator ledger.

## Runtime behavior

The same frozen authority object is passed through trusted Research and Presentation inference scopes.

### Planned deep-model selection

If deterministic prompt-size routing prefers the deep model but its conceptual tier exceeds `max_model_tier` or escalation is not authorized, WorkSpace stays on the permitted primary tier. No forbidden deep call occurs.

### Failure-driven escalation

After a primary-model failure, WorkSpace checks model authority **before** execution-budget reservation, retry/escalation telemetry, or stronger-model invocation.

A forbidden transition fails closed with a compact reason code such as:

- `MODEL_TIER_EXCEEDS_CONTRACT_MAX`;
- `MODEL_ESCALATION_NOT_AUTHORIZED`;
- `MODEL_TIER_UNKNOWN`.

A forbidden transition therefore cannot consume retry/escalation budget or manufacture telemetry for work that never ran.

### NO_LLM protection

A `none/none` TaskContract rejects any accidental model invocation before the primary model is called.

## Authority preservation across model switch

For an authorized primary → stronger-model transition, the exact same authority fingerprint remains visible in both model calls. The model switch does not reconstruct or mutate source/tool/network/write permissions.

This D6 boundary does not replace the future D0-03 typed Capability Broker. Tool and network gateways still enforce their own deterministic security policy. D6-04 specifically guarantees that model routing itself cannot mint broader authority.

## Regression requirements

Tests prove:

1. authority metadata is compact and content-free;
2. changing an authority-bearing TaskContract field changes the fingerprint;
3. an authority envelope cannot be attached to another task scope;
4. planned deep selection above the contract maximum stays on primary;
5. forbidden failure-driven escalation stops before deep invocation and telemetry;
6. authorized escalation preserves the exact authority fingerprint across both model calls;
7. NO_LLM contracts block accidental model calls before primary invocation;
8. Runtime Validator Bridge binds authority before policy PASS and stores only compact hashes/metadata.
