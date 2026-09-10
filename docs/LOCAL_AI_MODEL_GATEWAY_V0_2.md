# Local AI Model Gateway v0.2

Status: implementation candidate  
Depends on: `LOCAL_AI_RUNTIME_GATEWAY_V0_1.md`

## Goal

Provide one authority-bound inference facade between WorkSpace orchestration and local model backends that have already been created and resource-managed elsewhere.

The gateway does **not** contain model weights, download logic, runtime discovery, or prompt-based model selection.

```text
TaskContract
     |
     v
Trusted model binding registry
     |
     +--> TaskModelAuthority.require_tier(...)
     |
     v
LocalModelGateway
     |
     +--> pre-managed Ollama client / ResidencyManagedClient
     |
     +--> LocalEmbeddingAdapter
     |
     +--> future reviewed reranker/classifier adapters
```

## Trusted binding

A binding separates the stable WorkSpace model identity from the runtime-specific name:

```text
model_id      = security-analyst
runtime_id    = ollama-local
runtime_model = foundation-sec:8b
tier          = specialist
capabilities  = generation.text, generation.json
```

A user prompt, uploaded file, web document, or model response cannot create a binding. Unknown model ids and unbound capabilities fail closed.

## Authority

Every invocation requires an immutable `TaskContract`. The gateway derives `TaskModelAuthority` and calls `require_tier(binding.tier)` before backend invocation.

Consequences:

- `NO_LLM` contracts cannot call an embedding or generation model;
- a small-only task cannot call a specialist/strong model;
- a model cannot self-escalate;
- binding a model in the gateway does not grant the task permission to use it.

Tool/network/write authority remains separate in `TaskCapabilityAuthority`.

## Existing backend reuse

v0.2 deliberately does not implement another Ollama HTTP client. Generation backends are expected to be existing WorkSpace clients such as:

- `OllamaClient`;
- `ResidencyManagedClient`;
- metered/resource-managed wrappers already used by Orchestrator.

Embedding backends are expected to satisfy the existing `LocalEmbeddingAdapter` interface.

This preserves the existing resource budget, residency, telemetry, structured-output validation and local-only model-resolution boundaries.

## Capabilities in v0.2

Implemented gateway capabilities:

```text
generation.text
generation.json
retrieval.embedding.query
retrieval.embedding.document
```

Deferred until their runtime adapters and evaluation contracts are reviewed:

```text
retrieval.rerank
network.packet.classify
maintenance.predict
streaming generation
vLLM/OpenAI-compatible transport
```

## Structured generation

`generate_json()` requires `TaskContract.output_schema`. The caller cannot silently replace an authoritative task schema with a different model-facing schema.

The gateway forwards the contract schema to the already-existing structured generation backend, where deterministic schema validation remains authoritative.

## Output budget

Generation cannot request more than `TaskContract.generation_budget.max_output_tokens`.

Prompt/context packing remains the responsibility of the existing ContextEngine/task workflow. v0.2 intentionally does not invent a second tokenizer or approximate token authority inside the gateway.

## Audit/privacy

Invocation metadata contains model/runtime/capability/tier and the `TaskModelAuthority` fingerprint. The gateway does not persist raw prompts or model weights.

A binding fingerprint can be recorded for review and deployment evidence without including prompt content.

## Next phase

v0.3 should add a trusted runtime factory/composition layer that constructs these bindings from reviewed local configuration and wires them into Orchestrator. Only after that layer passes regression/security gates should an HTTP/SSE API expose model status and task streaming to the WorkSpace UI.
