# WorkSpace Pico-First Engineering Philosophy

**Status:** Normative engineering doctrine  
**Scope:** WorkSpace local-AI runtime, agents, context, tools, storage, routing, serving, and optimization decisions  
**Source inspiration:** RightNow-AI PicoLM design philosophy plus WorkSpace Efficient Reasoning research R1–R4  
**Rule:** This document defines how WorkSpace interprets those ideas. It does not claim that WorkSpace is PicoLM or that PicoLM itself specifies these rules.

## 1. Precedence

Mandatory security, privacy, user authority, repository governance, and correctness contracts always win. Subject to those constraints, WorkSpace uses this design order:

1. **Pico-first resource discipline** — make the active system as small, lazy, explicit, and inspectable as practical.
2. **Efficient reasoning** — minimize probabilistic work, select only necessary context/capability, constrain outputs, verify deterministically, escalate only on evidence.
3. **Implementation playbook** — optimize in measured order; do not add infrastructure because it is fashionable.
4. **Technology choice** — Ollama, vLLM, SGLang, LMCache, LLMLingua, a model family, or any other component is replaceable implementation detail.

Security is a boundary condition, not an optimization that may be traded away.

## 2. Pico-first does not mean “rewrite WorkSpace in C”

PicoLM demonstrates a useful engineering pattern: a small legible runtime, minimal dependencies, memory-mapped/lazy model access, and a deliberately small active working set. WorkSpace adopts the **resource discipline**, not a mandatory runtime migration.

Therefore:

> **Pico philosophy everywhere; PicoLM runtime only where edge constraints and benchmarks justify it.**

A future edge worker may use PicoLM. The central WorkSpace runtime may continue using Ollama or another serving engine when that better satisfies model capability, GPU utilization, structured output, concurrency, and operational requirements.

## 3. Core laws

### PICO-L01 — No resident state without proven active need

Large durable state should remain cold. Only the minimum working state required for the current task becomes hot.

Examples:
- do not preload an entire knowledge base when a bounded retrieval result is enough;
- do not keep every model resident when one active model satisfies the task;
- do not carry full prior-agent transcripts when a typed handoff contains the required evidence;
- do not materialize large artifacts until a consumer requests them.

### PICO-L02 — Lazy acquisition before eager allocation

Acquire context, tools, model capacity, network evidence, and large artifacts only when the current state proves they are required.

Default sequence:

```text
small state → attempt → verify → expand only if evidence says insufficient
```

not:

```text
load everything → reason over everything → hope relevance emerges
```

### PICO-L03 — One small deterministic control plane

Policy, budgets, routing, capability authority, state transitions, retry limits, termination, and validation belong to deterministic code.

The model proposes or synthesizes. It does not silently acquire authority.

### PICO-L04 — Remove deterministic decisions from the LLM

If code can decide a condition exactly, code decides it.

Examples:
- schema validation;
- task-state transitions;
- source-ID membership;
- budget checks;
- trust-domain rules;
- URL/network policy;
- retry ceilings;
- artifact lineage checks.

### PICO-L05 — Constrain known structure at generation time

Known syntax should be constrained by the serving layer or decoder when possible. Semantic correctness is then checked by deterministic validators.

Do not spend a second probabilistic call repairing syntax that could have been constrained in the first call.

### PICO-L06 — Reuse before recompute

Exact reusable state should be preserved when doing so is safe and measurable:
- stable prompt prefixes;
- deterministic derived metadata;
- verified source lineage;
- immutable artifact hashes;
- cached state within the same trust domain.

Reuse must never cross a trust/security boundary merely to improve cache hit rate.

### PICO-L07 — Separate cold durable state from hot working state

WorkSpace should explicitly distinguish:

```text
COLD: repository, SQLite history, knowledge bundles, source artifacts, model files
HOT: current task contract, selected evidence, active model, tool result window, validator state
```

The hot set should be bounded and observable.

### PICO-L08 — Trust boundaries are resource boundaries

Agent handoffs, retrieval results, uploaded files, web content, tool output, and imported skills are data until policy promotes a safe capability.

Optimization must not collapse trust domains. A faster shared cache is incorrect if it permits confidential/public or agent/tool authority to bleed across boundaries.

### PICO-L09 — Escalation must have evidence and a budget

Start with the smallest sufficient path. Escalate model size, context, retrieval depth, tool count, number of agents, or serving complexity only after a named failure/evidence condition.

Every escalation should record a reason code.

### PICO-L10 — Verify externally, not by self-confidence

Prefer evidence and deterministic checks over asking a model whether its own answer is correct.

Verification examples:
- schema/contract validation;
- source-backed claim checks;
- executable tests;
- artifact reopen/parse tests;
- network/security policy tests;
- golden-task evaluation.

### PICO-L11 — Keep components replaceable

The control plane must not encode a permanent dependency on one model, inference engine, cache layer, compression package, or router.

Adapters may expose capabilities, but WorkSpace policy should remain portable.

### PICO-L12 — Optional infrastructure requires workload evidence

Do not deploy another serving engine, distributed cache, learned router, compression model, speculative decoder, or quantization mode until workload traces show the bottleneck and a benchmark demonstrates a net gain without unacceptable quality/security loss.

The correct outcome of a benchmark-gated checklist item may be **REJECT / KEEP CURRENT STACK**.

## 4. Efficient-reasoning loop under Pico-first

WorkSpace uses the following default loop:

```text
MINIMIZE
   ↓
SELECT
   ↓
CONSTRAIN
   ↓
EXECUTE
   ↓
VERIFY
   ↓
ESCALATE ONLY IF REQUIRED
```

A multi-agent or multi-model path is an evidence-triggered exception, not a default measure of intelligence.

## 5. Resource accounting

Every significant inference path should eventually make these quantities measurable:

- active model(s) and estimated/observed VRAM;
- active context size and selected-evidence size;
- stable-prefix identity/reuse opportunity;
- prompt/evaluation token counts when exposed by the backend;
- wall time and backend timing counters;
- tool calls and retrieved-source count;
- deterministic validation result;
- escalation reason;
- trust domain;
- task success/failure class.

Raw confidential prompts/responses are not required for operational telemetry.

## 6. Design-review questions

Before adding a component, answer in order:

1. What exact failure or measured bottleneck does it solve?
2. Can we solve it by deleting work instead?
3. Can we solve it deterministically instead of probabilistically?
4. Can we reduce the hot working set?
5. Can we reuse already verified state safely?
6. Can the existing runtime provide the capability natively?
7. What new attack surface, dependency, resident memory, latency, and operational burden does the component introduce?
8. What benchmark/golden-suite evidence will accept or reject it?
9. How is it removed cleanly if it does not help?

If these questions cannot be answered, the component is not ready to enter WorkSpace.

## 7. Anti-patterns

Reject by default:

- loading all documents “for completeness”;
- adding more agents to compensate for an unclear contract;
- model-based retries for deterministic format failures;
- hiding failures behind repeated self-reflection;
- sharing cache/state across confidentiality domains;
- routing to a larger model without a reason code;
- installing vLLM/SGLang/LMCache/LLMLingua merely because a benchmark from another workload is impressive;
- equating token reduction with correctness improvement without task evaluation;
- optimizing average latency while verified task success falls.

## 8. Success criterion

WorkSpace optimization is successful when it improves **verified useful work per unit resource**, not when it merely reduces a single metric.

Conceptually:

```text
Verified Intelligence
≈ Relevant Evidence × Deterministic Control × Task Success
  -------------------------------------------------------
  Probabilistic Work × Active Resources × Failure Cost
```

This is a design heuristic, not a physical law. It exists to keep engineering decisions aligned with the project goal: local, secure, resource-efficient AI that completes real internal work reliably.
