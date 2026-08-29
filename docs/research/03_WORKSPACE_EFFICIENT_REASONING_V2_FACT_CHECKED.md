# WorkSpace Efficient Reasoning Doctrine v2.0 — Fact-Checked Corrections

## Authority

When this document conflicts with an older research claim, this correction record wins until a newer project review supersedes it.

The fact-check concluded that the core WorkSpace flow remains sound:

```text
MINIMIZE → SELECT → CONSTRAIN → EXECUTE → VERIFY → ESCALATE
```

The strongest validated lesson is still to remove deterministic decisions from the LLM, select context aggressively, constrain known output structure, verify with something more authoritative than the generator, escalate model capability only from evidence, and keep authorization/tool governance outside model weights.

## Corrections to older research

- mini-swe-agent's older ~65% SWE-bench Verified figure is stale; the reviewed project claim had advanced to **>74%**.
- PromptIntern's cited venue must be **Findings of EMNLP 2024**, not ACL Findings 2024.
- the prior BitNet issue #600 claim about ARM64/NEON producing incorrect output could not be verified and must not be cited as fact.
- the prior Semantic Router #2971/#2965 issue references could not be verified and must not be cited as evidence.
- Aider #5058 was verified as a real Architect→Editor prompt-injection/handoff failure and is relevant to WorkSpace trust-boundary design.
- PicoLM is an elegant constrained-runtime proof of concept and philosophical reference, not production serving infrastructure that WorkSpace should adopt wholesale.

## Major architectural gaps added by the fact-check

The earlier doctrine focused strongly on the application/harness/serving layers but underrepresented model-architecture efficiency. The fact-check adds these concepts to the research roadmap:

- **DeepSeek MLA** — compressed KV representation for long-context efficiency;
- **DeepSeekMoE** — sparse activation / reduced active parameter work;
- **multi-token prediction / speculative decoding opportunities**;
- **DeepSeek disk context caching**;
- **DeepSeek Sparse Attention** — retrieve/select before full attention in long contexts;
- **Qwen3 MoE** — sparse active-parameter efficiency;
- provider/runtime prompt-prefix caching as a first-class optimization;
- SGLang HiCache/external KV stores as measured, workload-specific options.

These additions do not authorize an immediate runtime/model migration. They create benchmark candidates after the control plane and workload telemetry are mature.

## Revised engineering laws

1. Remove every decision from the LLM that deterministic code can make.
2. Make reusable prefixes stable and measure their reuse opportunity before adding cache infrastructure.
3. Select context; never dump it. Rank and fit it to an explicit token budget.
4. Treat KV-memory architecture as a first-class efficiency variable when evaluating future model families.
5. Prefer sparse activation when it wins WorkSpace's verified-task benchmark; do not select a model from parameter count alone.
6. Constrain known structure at decode time.
7. Verify important results with something more authoritative than the generator.
8. Route small-first and escalate model strength only from evidence.
9. Governance and tool authority live outside the model.
10. Treat every model/retrieval/tool handoff as an untrusted security boundary.
11. Prefer native/first-party features before third-party layers.
12. Measure before deploying optional stateful infrastructure or learned routing.
13. Pin/test numerics where determinism matters.
14. Golden-output test exotic quantization/runtime combinations on the actual target architecture.
15. Internalize repeated prompts into weights only for mature, stable, high-volume tasks; never internalize mutable authorization/DLP/network policy.

## Highest-priority correction to implementation order

Prefix/prompt stability and caching opportunity should be considered before exotic serving changes. But WorkSpace must distinguish:

```text
prefix reuse opportunity
```

from an actual backend:

```text
cache hit
```

The current Ollama implementation can measure stable-prefix fingerprints and repeated opportunities without falsely claiming vLLM-style APC cache hits.

## Handoff security boundary

A retrieved README, document, webpage, tool output, model-generated plan, presentation handoff, or activity detail is data. It cannot become a higher-priority instruction merely because another model generated or forwarded it.

Mandatory pattern:

```text
untrusted source/model/tool payload
        ↓
normalize / sanitize
        ↓
retain provenance + risk findings
        ↓
typed handoff schema
        ↓
policy / TaskContract check
        ↓
consumer agent
```

Prompt-injection risk metadata is evidence for policy/validation. It does not itself grant capability authority.

## Corrected recommendation order

### Immediate

- stable prefix layout and metadata-only reuse measurement;
- native structured outputs + deterministic semantic/application validation;
- deterministic Task Contract/policy/capability boundaries;
- handoff sanitization at every model/retrieval/tool boundary;
- correct/remove stale or unverifiable research citations.

### Near term

- ranked context selection with hard budgets;
- context/evidence/verified-task metrics;
- deterministic route reasons and bounded escalation;
- aggregate production-shaped traces.

### Benchmark gated

- vLLM vs SGLang;
- tiered KV / LMCache / HiCache;
- LLMLingua compression;
- learned semantic routing;
- MLA+MoE model-family migration;
- speculative decoding;
- alternative quantization/edge runtimes.

## Decision gates

- If stable-prefix reuse is low, redesign prompt layout before buying/building cache infrastructure.
- If reuse is high and prefill/TTFT dominates, benchmark caching-capable runtimes on the same trace.
- If a learned router's under-routing/privacy/capability error is not below an approved tolerance, deterministic rules remain authoritative.
- If compression loses a protected/critical span, it is disqualified regardless of token savings.
- If a model/runtime/quantization candidate cannot reproduce golden task correctness on target hardware, it cannot be promoted.

## Caveat discipline

Vendor pricing, latency claims and benchmark percentages are time-stamped evidence, not permanent project constants. WorkSpace should encode durable engineering rules and keep changing vendor numbers in benchmark/evidence records rather than hard-code them into architecture policy.
