# Inference and Skill Optimization Plan — 2026-08-29

## Executive decision

3Agent should optimize for useful evidence per token and per GPU-second, not for maximum context length or maximum GPU occupancy.

The current architecture already has two strong primitives: model-role routing plus resource admission; and GPU-affined Ollama workers that prefer a single RTX 5090 when the model safely fits and reserve dual-GPU execution for larger workloads.

The next optimization layer is context engineering: load only the evidence, skill instructions, and model capacity needed by the current stage.

## Why the harness improves reasoning

A harness does not make model weights smarter. It improves effective reasoning by controlling the information and actions around the model: decomposing large tasks, removing irrelevant context, exposing only allowed tools, validating structured output, preserving evidence lineage, rejecting unsupported claims, routing simple work to cheaper models, escalating difficult work selectively, and reusing artifacts instead of rediscovering them.

## GPU strategy for 2× RTX 5090

Keep single-GPU work single-GPU when it fits. A model that fits in one GPU should normally stay on one GPU; use the second card for another worker/request. Reserve the dual worker for a model that cannot safely fit one card.

```text
GPU0 -> Ollama worker A -> normal Research / heavy task
GPU1 -> Ollama worker B -> Presentation / Report / concurrent task
GPU0+1 -> dual worker -> only when one card is insufficient
```

Do not chase 100% utilization. Leave margin for K/V cache growth, rendering, Python processes, desktop services, and transient allocations. Recommended starting guardrails are 85–90% per-GPU VRAM admission, queueing rather than oversubscription, and conservative host-RAM use because system RAM is 32 GB. These are starting points, not benchmark results.

## Dynamic context budgets

A configured 64K context is a ceiling, not a requirement for every inference.

| Stage | Starting context |
| --- | ---: |
| routing/classification | 4K–8K |
| research query planning | 8K |
| language cleanup / daily report | 8K–16K |
| source suitability gate | 16K |
| presentation planning | 16K–32K |
| normal evidence synthesis | 32K |
| deep research / unusually large evidence | up to 64K |

Increase context only when retained evidence would otherwise be truncated. Larger context consumes additional memory and can reduce parallel capacity.

## Progressive skill disclosure

Skill metadata may exist in the registry without entering every system prompt.

Bad pattern: agent profile + every research/programming/Office/design skill + full evidence on every inference.

Preferred pattern: task/stage classifier -> minimal approved skill subset -> compact evidence subset -> inference -> deterministic validation.

Research planning, source screening, and final synthesis should not receive the same skill payload.

## Evidence compaction

Before LLM inference: deduplicate URLs, strip page boilerplate, rank sources by relevance/authority/time match, retain exact evidence quotes for numerical claims, cap per-source text, avoid sending full raw documents when a targeted section is enough, and reuse Agent 1 handoff for Agent 2 instead of raw web pages.

## Cache and reuse

Cache deterministic intermediates by input hashes: parsed files, cleaned web sources, source suitability results, evidence handoffs, and rendered-file checks. Cache records must include parser/policy/version identifiers so a policy update invalidates stale results. A cache hit never bypasses security validation.

## Parallelism

Parallelize independent I/O more aggressively than inference. Good candidates are independent web fetches, local file metadata inspection, hashing, and deterministic validation.

Inference parallelism must remain resource-budget-aware because parallel model requests increase K/V-cache memory. Schedule concurrent model work only when each selected GPU has capacity.

## Model routing

Use task complexity, not agent name alone. Small language cleanup can use a fast/report model; source classification uses the normal research model; long contradictory evidence may escalate to the deep model; deterministic validation should use no LLM.

Deep-model escalation should be observable: record why it occurred, selected model, prompt size, and whether the smaller model failed or evidence complexity crossed a threshold.

## Skill supply-chain policy

Use three trust tiers:

1. project-owned deterministic code;
2. project-written instruction-only skills admitted by `ApprovedSkillLoader`;
3. third-party executable skill/runtime, disabled by default and requiring a separate sandbox/dependency/security review.

Do not automatically clone or sync public skill catalogs into runtime.

## Office/PDF strategy

Prefer local libraries and inert parsing. DOCX uses local python-docx where supported; PPTX uses local python-pptx; XLSX should not accept untrusted workbook parsing until openpyxl is paired with hardened XML/ZIP controls; PDF should use a permissively licensed local parser with strict resource limits before untrusted upload support is enabled. External conversion/OCR/design services remain disabled by default.

## Metrics before further tuning

Measure prompt size/tokens, selected model, requested context, prompt/eval duration, model load duration, queue wait, selected GPU worker, peak VRAM, host RAM, source count before/after filtering, cache hit rate, rejected model claims, and end-to-end latency.

Benchmark the same fixed task set under baseline, progressive skills, progressive skills plus dynamic context, two single-GPU workers, and dual-GPU-only-when-required. Select configurations by quality and latency/resource evidence, not by GPU utilization alone.
