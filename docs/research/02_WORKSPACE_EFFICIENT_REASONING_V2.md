# WorkSpace Efficient Reasoning Doctrine v2.0 — Project Canonical Integration

## Purpose

This document integrates the reviewed v2 research into the WorkSpace repository as an engineering doctrine. It preserves the source report's central architecture, terminology, constraints, and implementation priorities while keeping runtime/vendor choices replaceable.

## Core thesis

> **Use probabilistic intelligence only where uncertainty genuinely exists. Minimize the amount of context, reasoning, model capacity, state, and tool authority required to complete a task; then verify the result outside the model whenever possible.**

WorkSpace should optimize verified task completion rather than model activity.

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
ESCALATE ONLY WHEN JUSTIFIED
```

A useful project-level model is:

```text
Verified Intelligence
≈ Relevant Context
× Appropriate Model
× Safe Capabilities
× External Verification
```

and waste is:

```text
Irrelevant Tokens
+ Unnecessary Reasoning
+ Duplicate Compute
+ Unbounded Iteration
+ Unnecessary Model Capacity
```

## Architecture rule

The highest-priority architectural change is not more agents. It is a deterministic control plane around a small, inspectable reasoning loop.

```text
User / Upstream
      ↓
Policy Gate
      ↓
Task Contract
      ↓
Context Engine
      ↓
Rule-first Model Router
      ↓
Minimal Agent Loop
      ↓
Capability Broker
      ↓
Validator Bus
      ↓
Verified Result
```

Recoverable failures may trigger targeted context expansion, same-tier bounded repair, specialist routing, or stronger-model escalation. Policy/DLP/network denial never becomes an escalation signal.

The normal execution path is:

```text
Request → Context → Model → Tool → Validator → Result
```

not a permanent:

```text
Planner → Researcher → Worker → Critic → Reviewer → Supervisor
```

Multi-model or multi-agent behavior is an exception triggered by measured need.

## Source-project synthesis

| Source | Principle WorkSpace retains | What WorkSpace rejects/defer |
|---|---|---|
| PicoLM | load/compute only what is needed; reuse; constrained syntax | universal runtime lock-in |
| mini-swe-agent | tiny transparent scaffold; linear trajectory | unrestricted shell authority |
| SWE-agent | observation/interface engineering | fixed-size viewer dogma |
| Aider | map/rank before reading payload | soft/unbounded production budgets |
| DSPy | metric-driven offline optimization | production self-modification |
| LLMLingua | selective long-context compression | global compression of short/authoritative text |
| Semantic Router | route by capability/risk/complexity | learned router as security authority |
| vLLM | KV/prefix reuse and serving metrics | unsalted sensitive shared cache |
| SGLang | structured generation and prefix reuse | permanent duplicate serving stacks without evidence |
| LMCache | persistent/tiered KV reuse | P0 deployment without reuse evidence |
| Outlines | structure by construction | assuming structure means truth |
| Guidance | reduce model decision space | second orchestration framework by default |
| BitNet | representation-level edge efficiency | production dependency without hardware qualification |
| PromptIntern | specialize stable repetition | encoding mutable policy into weights |

## Deterministic control plane vs probabilistic reasoning plane

### Deterministic control plane owns

- identity / trust domain;
- policy and DLP;
- Task Contract compilation;
- capability authorization;
- execution budgets;
- cache policy;
- structured schemas;
- validator requirements;
- failure codes;
- logging/retention policy;
- release/promotion decisions.

### Probabilistic reasoning plane may

- synthesize evidence;
- choose among permitted semantic alternatives;
- draft plans/results;
- request an approved tool;
- recommend escalation.

The probabilistic plane may propose an action. It may not broaden its authority.

## Task Contract requirements

Every meaningful request must compile into an immutable execution envelope before model/tool execution. At minimum it contains:

- task identity/type;
- sensitivity and risk;
- allowed sources/tools;
- write scope and network scope;
- context, generation and execution budgets;
- evidence requirement;
- required validators;
- output schema;
- model policy and escalation ceiling;
- cache mode/trust domain/TTL;
- raw-log policy.

Privilege is monotonic: a model may voluntarily narrow permissions, but no model output may broaden tool, filesystem, network, data, cache, or logging authority.

## Context Engine doctrine

Canonical pipeline:

```text
DISCOVER
  ↓
STRUCTURE
  ↓
RETRIEVE
  ↓
RERANK
  ↓
DEDUPLICATE
  ↓
PROTECT CRITICAL SPANS
  ↓
OPTIONALLY COMPRESS
  ↓
PACK TO HARD BUDGET
  ↓
ATTACH PROVENANCE
```

Map/navigation metadata should precede raw payload. Large context windows are capacity, not permission to dump a corpus.

Each selected context item should carry source identity/hash, retrieval method, relevance/authority/freshness information, sensitivity, critical/protected state, transformation/compression metadata, provenance, and token count.

Context efficiency should be measured with Context Precision/Recall or auditable proxies, duplicate-token ratio, evidence coverage, and useful-context ratio.

## Capability Broker doctrine

Agents request typed capabilities, not unrestricted execution. Authorization is derived from the Task Contract and current policy. Tool calls must remain inside resource/write/network scope and execution budgets.

Unrestricted host shell is not the WorkSpace tool model.

## Rule-first Model Router

Routing priorities:

1. Security/data placement.
2. Deterministic solution detection (`NO_LLM` when possible).
3. Task specialization.
4. Complexity/context requirement.
5. Risk affects validators, not automatically model size.
6. Escalation only after failure evidence.
7. Never escalate to bypass policy/DLP/network/tool denial.

Learned routing begins in shadow mode. It may influence production only after route accuracy, route regret, under-routing, over-routing, privacy misroute and capability misroute are measurable.

## Validator hierarchy

Prefer the least probabilistic authoritative validator that can decide:

1. policy/deterministic rules;
2. schema/type checks;
3. parser/compiler;
4. linter/static analysis;
5. unit/integration/property tests;
6. authoritative evidence / cross-source consistency;
7. independent model only where deterministic validation cannot resolve semantics;
8. human review for high-risk ambiguity.

The generating model is never its sole correctness authority.

## Failure taxonomy

Production must distinguish at least:

- policy/DLP/network/unauthorized capability;
- budget/resource/deadline;
- context missing/stale/conflicting;
- model capability/refusal/low confidence/truncation;
- structure/parse failures;
- tool invalid argument/timeout/execution/ambiguous result;
- semantic validation/test/factual failures;
- internal/platform failures.

Recovery is deterministic. Examples:

- missing context → retrieve the missing evidence;
- syntax/test failure → return exact failure evidence to a bounded repair path;
- schema failure → constrained structured generation, not generic retry loops;
- model capability limit → permitted specialist/stronger tier;
- policy denial → stop;
- tool timeout → controlled tool retry/backoff;
- conflicting high-risk evidence → human review.

**Escalation may increase intelligence. It may not silently increase authority.**

## Structured decoding abstraction

Known structure belongs in decoding, not in natural-language requests to “return valid JSON.” WorkSpace owns a stable `StructuredDecoder` concept; runtime-native schema/grammar support is preferred before adding another framework.

Structural validity is not semantic truth. Application validators remain mandatory.

## Caching and trust domains

Exact/prefix/KV reuse is derived state from potentially sensitive inputs. Cache reuse is therefore a security decision.

Cache keys/policies should include the most restrictive applicable trust domain plus model/tokenizer/template/policy/source versions and lifecycle metadata. Restricted/secret sharing defaults to deny. Persistent KV is not harmless telemetry.

Start with native exact/prefix capabilities and measurement. Add another stateful cache service only when representative traces show positive net value after hash, transfer, storage, security and operational cost.

## Compression doctrine

Lossless/protected regions include security policy, authorization, Task Contract, exact user constraints, critical identifiers, exact code/error fragments, citations/provenance and authoritative wording.

Compressible regions may include long retrieved prose, logs, duplicate history, boilerplate and noncritical examples.

Compression is allowed only when:

```text
compression cost + compressed inference cost < original inference cost
```

and quality/security/protected-span gates pass.

## Evaluation lab

Production optimization is offline and promotion-gated. Maintain separate golden, replay, regression, adversarial, edge and efficiency datasets. Deterministic acceptance and ground truth outrank an LLM judge.

Primary quality/efficiency metrics include:

- Verified Task Success Rate;
- First-Pass Verified Success;
- Evidence Coverage;
- unauthorized executed action rate = 0;
- input/output tokens per verified task;
- GPU seconds per verified task;
- tool calls per verified task;
- escalation/retry rates;
- small-model containment rate;
- verified successes per million tokens;
- context precision/recall and duplicate/unused context ratios.

Security is a hard feasibility constraint, not a small weighted penalty in a performance score.

## Serving and dependency policy

Inference engines remain adapters behind WorkSpace-owned contracts. vLLM/SGLang/LMCache/Outlines/Guidance/PicoLM/BitNet are implementation options, not control-plane authorities.

Do not deploy all options. Benchmark representative traffic and choose the smallest operational stack that materially improves verified quality, latency or resource use without weakening security.

## Normative WorkSpace doctrine

```text
Do not read everything. Find what matters.
Do not reason when deterministic computation can decide. Compute it.
Do not use the strongest model by default. Use the smallest proven capable.
Do not grant privilege because a model requested it. Authorize outside the model.
Do not give unlimited context/tools/steps/retries/cache/memory/network. Budget everything.
Do not ask for arbitrary structure when structure is known. Constrain it.
Do not ask the generator to prove itself correct. Verify externally.
Do not retry policy denial. Do not escalate around security.
Do not preserve every token. Preserve information and provenance.
Do not recompute validated reusable work. Reuse inside the correct trust domain.
Do not share sensitive derived state across trust boundaries.
Do not optimize production behavior by intuition. Measure, evaluate, promote, rollback.
Do not internalize changing policy into weights.
Do not add agents/frameworks merely to appear intelligent.
```
