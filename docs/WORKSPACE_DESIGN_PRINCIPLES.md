# WorkSpace Design Principles — Constraint-First Local AI

## Source of inspiration

WorkSpace adopts engineering ideas observed in RightNow-AI/PicoLM: aggressively constrained resource budgets, minimal dependencies, mmap/lazy access, fused operations that remove intermediate buffers, lower-precision KV storage, precomputed hot-path values, grammar-constrained structured output, and persistent prompt/KV caching.

WorkSpace does not copy PicoLM's inference engine. PicoLM is MIT licensed; the value adopted here is the engineering method: start from constraints and remove unnecessary work.

## Principle 1 — Eliminate work before accelerating it

Before adding another model call, ask whether deterministic code, cached evidence, a hash, schema validation or a previous artifact already answers the question.

Target order:

```text
avoid > reuse > precompute > compact > parallelize > accelerate > scale hardware
```

## Principle 2 — The harness is the product intelligence

Model weights provide probabilistic reasoning. The harness provides reliability:

- task decomposition;
- context selection;
- skill selection;
- data classification;
- network authority;
- resource scheduling;
- schema/citation validation;
- artifact lineage;
- cache invalidation;
- measurable escalation.

A stronger harness lets smaller models do useful work safely and prevents larger models from wasting resources.

## Principle 3 — Context is working memory, not storage

Raw files, web pages and full histories live outside model context. Context should contain only the current objective, minimal approved instructions and the highest-value evidence for the current stage.

A 64K model context is a ceiling. Routing may need 4–8K; language cleanup may need 8–16K; ordinary synthesis may need ~32K. Expansion must be evidence-driven.

## Principle 4 — Deterministic constraints beat prompt requests

PicoLM constrains JSON at sampling time rather than asking a small model to "please produce valid JSON." WorkSpace applies the same philosophy above the model:

- unsupported citations are rejected;
- state transitions are code-controlled;
- skill hashes must match reviewed digests;
- file safety limits are enforced by parsers;
- egress methods/hosts/queries are policy-controlled;
- confidential Core network access is OS-controlled in high-assurance mode.

## Principle 5 — Keep data movement small

Agent/workflow stages exchange compact handoff objects instead of copying raw pages/files. Evidence is identified by stable IDs/hashes. Renderers receive structured content, not arbitrary web access.

## Principle 6 — Cache with provenance

Cache only deterministic/reproducible intermediates and include input hash, parser/policy version and producer version. Security-policy changes invalidate affected caches.

Priority caches:

- file parsing;
- web cleaning;
- source suitability;
- evidence compaction;
- document render validation;
- stable instruction/profile prefixes where inference runtime supports prompt caching.

## Principle 7 — Use both RTX 5090s as independent capacity first

If a model safely fits one GPU, prefer one GPU and use the other card for another worker. Use dual-GPU execution only when a single card cannot satisfy the VRAM budget. Do not optimize for visual 100% utilization.

## Principle 8 — Separate capability from authority

A research skill may know how to search but cannot authorize Internet access. A document skill may know how to parse DOCX but cannot fetch a remote template. A coding skill may propose commands but cannot grant shell authority.

## Principle 9 — Confidentiality is an architectural constraint

For confidential workloads, the safest outbound payload is no payload. Therefore WorkSpace's canonical secure profile disables public search. Egress is an explicit exception for public research, not a default dependency.

## Principle 10 — Measure all optimization claims

Record at least:

- commit/config/model;
- task benchmark ID;
- input/evidence size;
- prompt/eval tokens;
- latency and queue wait;
- selected worker/GPU;
- VRAM/RAM peaks;
- cache hit/miss;
- rejected claims;
- quality/acceptance result.

An optimization is accepted only when benchmark evidence improves the intended objective without weakening safety or correctness.
