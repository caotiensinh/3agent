# PicoLM Philosophy Applied to WorkSpace

## Decision

WorkSpace adopts **PicoLM philosophy everywhere, PicoLM runtime only where edge constraints justify it**.

PicoLM is valuable to this project because it demonstrates that severe resource constraints should change architecture, not merely lower configuration values. Its low-memory runtime uses techniques such as memory-mapped model state, layer streaming, compact KV state, fused operations, reuse, and constrained JSON. WorkSpace does not copy PicoLM literally; it translates the same discipline upward into the agent/control-plane architecture.

## Primary law

> **The cheapest resource is the resource never allocated, retrieved, generated, transferred, recomputed, or kept resident.**

For WorkSpace this becomes:

```text
Do not load before need.
Do not retrieve before relevance.
Do not reason before deterministic checks.
Do not generate known syntax freely.
Do not keep state without reuse value.
Do not recompute verified reusable work.
Do not escalate before failure evidence.
```

## PICO engineering laws

### PICO-01 — Lazy acquisition

Everything expensive should be acquired on demand:

- model capability;
- context expansion;
- documents and source bodies;
- tools;
- indexes and embeddings;
- external access;
- stronger reasoning tiers.

The default flow is `classify need → select minimum capability → load/use only that capability`.

### PICO-02 — Small active state, durable heavy state

Large durable state should remain outside the hot working set. The active reasoning state should contain only the minimum task contract, relevant evidence, current observations, and bounded execution state.

### PICO-03 — Deterministic before probabilistic

Parsing, hashing, schema validation, policy evaluation, budgets, authorization, deduplication, arithmetic, compiler/linter/test results, and exact lookups take precedence over LLM reasoning.

A model may propose. Deterministic control decides.

### PICO-04 — Reuse before recompute

Reuse exact deterministic results and stable-prefix opportunities within the correct trust domain. Reuse is keyed by version/provenance/trust metadata, never by an unsafe global cache assumption.

### PICO-05 — Constrain known structure

If an output shape is known, encode the constraint at generation time and validate it again afterward. A syntactically valid result is not automatically a semantically correct result.

### PICO-06 — Hard resource budgets

Every meaningful task needs explicit ceilings for:

- input/retrieval/tool-output tokens;
- generated tokens;
- steps;
- tool calls;
- retries;
- model escalations;
- wall time;
- model/resource class.

Budget overflow is an explicit failure state, not permission for an unbounded loop.

### PICO-07 — Minimal control path

The normal path remains:

```text
Request
  → Policy / Task Contract
  → Context
  → Model only if needed
  → Approved tool only if needed
  → Validator
  → Verified result
```

Permanent planner/reviewer/critic/supervisor chains are rejected unless measured evidence shows they improve verified success enough to justify their cost and risk.

### PICO-08 — Measure work, not model activity

Primary optimization metrics must be normalized by successful verified work, for example:

- input tokens per verified task;
- generated tokens per verified task;
- tool calls per verified task;
- GPU seconds per verified task;
- time to verified result;
- first-pass verified success;
- escalation/retry rate;
- useful-context ratio.

More tokens or more agent turns are not evidence of more intelligence.

## What WorkSpace deliberately does not inherit literally

PicoLM is an illustrative constrained-runtime project, not the universal WorkSpace serving layer. WorkSpace therefore does **not**:

- replace the current server runtime merely because PicoLM is small;
- restrict the central system to PicoLM's model/runtime scope;
- treat CPU edge constraints as identical to GPU workstation/server constraints;
- assume grammar-valid JSON is semantically safe;
- optimize RAM while ignoring latency, task quality, security, or operator cost.

## PicoLM-derived acceptance questions

Every new subsystem must answer these questions before it is accepted:

1. Can this decision be deterministic?
2. Can this data stay unloaded until needed?
3. Can we retrieve less while preserving required evidence?
4. Can we reuse a verified result or stable prefix safely?
5. Can we remove a retry by constraining the output?
6. Is the state bounded by an explicit budget?
7. Does the new layer improve verified work per resource?
8. Can the same goal be achieved without another framework/service/model?

If the answer to the last question is yes, the smaller design wins by default.

## Runtime policy

PicoLM runtime integration is an **edge R&D lane**, not an early central milestone. A PicoLM adapter may be promoted only after target-device tests measure memory, latency, power, output correctness, supported model capability, and golden task success. Until then, the philosophy is normative while the runtime remains optional.
