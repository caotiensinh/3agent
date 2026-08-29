# WorkSpace Efficiency Playbook v3.0 — Project Execution Rules

## Purpose

This playbook converts the doctrine into a measurable implementation order. It is deliberately operational: every optimization must have a trigger, acceptance gate, and rollback/defer path.

## ROI order from the reviewed playbook

1. Make prompt prefixes stable and exploit native caching where the selected runtime actually supports it.
2. Put stable system/tool/schema/few-shot material first; put request/task/evidence-specific material last.
3. Use native JSON Schema / constrained structured output instead of free-text parsing and probabilistic syntax repair.
4. Measure reuse/cache behavior before adding more cache infrastructure.
5. Quantize only where the target workload/hardware golden tests show acceptable quality.
6. Use prompt compression only for genuinely long contexts and protect exact/critical spans.
7. Route small→large only after evaluation data exists; deterministic rules remain the initial authority.

## Current WorkSpace interpretation

WorkSpace currently uses Ollama. Therefore:

- stable-prefix fingerprints and reuse opportunity are measured;
- they are **not** labelled backend cache hits;
- Ollama native JSON Schema is preferred for current structured generation;
- vLLM/SGLang remain benchmark candidates, not prerequisites;
- LMCache/HiCache remain gated by measured KV reuse;
- learned routing remains gated by route-regret evidence;
- LLMLingua remains disabled until context-size and break-even evidence justify it.

## Prompt layout contract

```text
STABLE PREFIX
  immutable system policy
  approved local skill/profile instructions
  stable protocol/tool/schema material

DYNAMIC SUFFIX
  user request
  task-specific state
  selected evidence
  current tool observations
```

Rules:

- never put timestamp/task ID/branch-specific data into the stable prefix unless semantically required;
- version the stable template;
- fingerprint without logging raw text;
- include trust-domain metadata;
- changing policy/schema/profile must change the fingerprint/version;
- dynamic evidence remains outside the reusable stable prefix unless the runtime/trust model explicitly supports safe reuse.

## Structured-output contract

Preferred order:

```text
runtime-native schema/grammar
        ↓
JSON parse
        ↓
local deterministic schema validation
        ↓
application semantic validator
        ↓
verified result or typed failure
```

Do not use a second model call merely to make malformed JSON parseable when decoder-time constraints can prevent the structural error.

Structured output means syntax/shape compliance, not factual correctness or authorization correctness.

## Context and compression rules

Context selection happens before compression.

Protected/lossless content:

- Task Contract and security policy;
- exact user constraints;
- identifiers needed for execution;
- exact error/code fragments where exactness matters;
- citations/provenance;
- validator/test evidence.

Compression candidates:

- long retrieved prose;
- redundant history;
- long logs after deterministic event selection;
- boilerplate;
- duplicated explanations.

Compression is feature-flagged and benchmark-gated. A heuristic threshold such as ~2k–4k tokens may be used only as an experiment trigger, not as a universal truth. Break-even and critical-span retention decide promotion.

## Cache/reuse decision rules

The reviewed playbook proposes a useful starting gate:

- if measured reuse/cache-hit opportunity stays below roughly 30% over a representative period, redesign prompt layout before introducing more cache infrastructure;
- if reuse is high and TTFT/prefill dominates, benchmark a cache-capable serving alternative on exactly the same traffic trace;
- multi-tenant/shared KV reuse must be scoped by the correct trust domain; if a future vLLM path is selected, use backend isolation such as `cache_salt` rather than inventing an unsafe global shared cache.

The 30% value is a planning threshold from the reviewed playbook, not a universal constant. WorkSpace may recalibrate it from its own traffic.

## Routing rules

Initial routing is deterministic and auditable:

```text
policy / data placement
        ↓
NO_LLM possible?
        ↓
specialist requirement?
        ↓
minimum capable model tier
        ↓
validator result
        ↓
only then bounded escalation
```

A learned semantic router may begin only in shadow mode. It cannot weaken privacy/network/capability policy. Promotion requires measured under-routing, over-routing, route regret, privacy misroute and capability misroute.

## Quantization and model-family rules

The playbook's benchmark numbers are research inputs, not automatic production settings. WorkSpace must golden-test each target model/runtime/hardware combination.

General policy:

- prefer the least destructive precision reduction that materially solves a resource problem;
- do not use aggressive low-bit quantization for reasoning/code/math merely because it fits;
- classification/extraction candidates may tolerate more compression, but only verified task tests decide;
- model architecture features such as MLA/MoE/sparse attention are benchmark candidates after the control plane is stable.

## Serving-engine benchmark gate

A serving migration must replay the same WorkSpace trace across candidates and compare at least:

- Verified Task Success / task-specific quality;
- p50/p95 TTFT;
- total latency / TPOT where applicable;
- throughput under representative concurrency;
- input/output tokens;
- GPU memory and GPU active time;
- structured-output reliability;
- prefix/KV reuse;
- cross-trust-domain isolation;
- operational complexity and failure modes.

No migration from Ollama is justified by headline benchmark alone.

## Always-on hard rules

- Security policy is never compressed, learned away, or overridden by escalation.
- Raw sensitive prompts/responses are not required for efficiency telemetry.
- Every persistent/shared cache requires lifecycle + ownership + trust-domain policy.
- A model may recommend a tool; Task Contract/Capability Broker decides authorization.
- A parser/schema success is never equivalent to semantic truth.
- Optional frameworks remain absent until measured net value is positive.

## Implementation order for this repository

The authoritative detailed order is `05_MASTER_IMPLEMENTATION_CHECKLIST.md`. This playbook supplies the decision rules; the checklist maps them onto the code already present in WorkSpace.
