# WorkSpace Efficient Reasoning v2/v3 — Implementation Baseline

## Status

This document records the first implementation slice derived from the two v2 doctrine reports and the v3 engineering playbook reviewed on 2026-08-29.

The implementation deliberately keeps the existing Ollama runtime. It does **not** add vLLM, SGLang, LMCache, LLMLingua, a learned router, or another permanent agent. Those components remain benchmark-gated.

## Adopted now

### 1. Stable-prefix prompt envelope

WorkSpace now represents each inference request as:

```text
STABLE PREFIX
  SYSTEM + approved local skills + fixed protocol

DYNAMIC SUFFIX
  request/task/evidence specific content
```

The rendered prompt remains byte-compatible with the previous Ollama request format. The new separation exists so WorkSpace can measure repeated-prefix opportunity without retaining raw prompts.

Telemetry stores a SHA-256 prefix fingerprint, template version, trust domain and byte/token usage metadata. It does not store prompt text.

### 2. Native structured output before repair retries

`OllamaClient.generate_json()` now sends a JSON Schema object through Ollama's native `format` field. If a caller does not yet supply a task-specific schema, WorkSpace uses a generic object schema.

Structured generation uses temperature `0`. The returned object is checked again by deterministic local validation for the JSON-schema subset WorkSpace currently emits.

The former model-based JSON syntax-repair retry was removed from this path. A structural failure is now explicit failure evidence for the surrounding bounded workflow rather than an invitation to spend another probabilistic generation.

### 3. Metadata-only inference telemetry

`data/activity/inference.jsonl` (or the configured artifact root equivalent) records:

- model ID;
- structured-output/schema ID;
- prompt template version;
- trust domain;
- stable-prefix SHA-256 and sizes;
- dynamic-suffix sizes;
- Ollama input/output token counts;
- load/prompt-evaluation/generation durations;
- wall duration;
- whether the same model/trust-domain/prefix fingerprint has already been observed in the current process;
- success/error class.

It never records raw prompts, model responses, retrieved documents, credentials, source-code bodies or chain history.

`prefix_reuse_candidate` is intentionally **not** called a cache hit. Ollama's current `/api/generate` API does not expose vLLM-style APC/cache-salt hit telemetry. The trace is intended to decide whether a later vLLM/SGLang benchmark is justified.

### 4. Agent/retrieval handoff sanitizer foundation

`sanitize_untrusted_payload()` provides a deterministic boundary primitive for data crossing agent/retrieval handoffs:

- Unicode NFKC normalization;
- removal of zero-width/null/control characters that do not carry business content;
- prompt-injection signal detection;
- machine-readable risk findings;
- suspicious text remains data rather than becoming authority.

This primitive does not grant/deny tools. Task Contract, Capability Broker and network policy remain the authority boundary.

## Explicitly deferred

The following remain measurement-gated:

- vLLM Automatic Prefix Caching and `cache_salt` isolation;
- SGLang/RadixAttention/HiCache;
- LMCache persistent/tiered KV;
- LLMLingua context compression;
- learned semantic routing;
- DeepSeek/Qwen MLA/MoE serving migration;
- speculative decoding;
- BitNet/PicoLM production use;
- prompt internalization/fine-tuning.

## Decision gates

1. Collect production-shaped inference traces first.
2. If repeated stable prefixes are rare, redesign prompt layout before adding cache infrastructure.
3. If repeated prefixes are common and TTFT/prefill dominates, benchmark vLLM and SGLang on the same trace.
4. A serving-engine change should require a material measured benefit with equal verified quality and equivalent security boundaries.
5. Context compression is not enabled until a break-even test shows lower total latency/compute with zero critical-span loss.
6. Learned routing stays shadow-only until under-routing, over-routing, privacy misroute and capability misroute are measured.

## Next implementation slice

After this runtime baseline produces traces, the next code slice should integrate the handoff sanitizer and task-specific JSON schemas into every Agent 1 -> Agent 2 -> Agent 3 boundary, then add Context Precision/Recall and Verified Task Success telemetry. That work remains deterministic/control-plane work and does not require a serving-engine migration.
