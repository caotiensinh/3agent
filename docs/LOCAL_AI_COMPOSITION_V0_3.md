# Local AI Composition v0.3

## Goal

`local_ai_composition.py` is the trusted composition layer between `AppConfig.raw` and the authority-bound `LocalModelGateway`.

It converts reviewed WorkSpace configuration into an immutable binding registry and attaches only already-created local generation or embedding backends. It does not create runtime clients, discover or download models, grant task/model authority, or invoke a backend during composition.

## Trust boundary

The data flow is:

```text
reviewed AppConfig.raw
  -> local_ai_composition_spec()
  -> immutable LocalAIModelBinding tuple
  -> LocalAIModelBindingRegistry
  -> build_local_model_gateway()
  -> already-created local backends
  -> invocation-time TaskContract authority checks
```

Request text and request-time model names never create or modify a trusted binding.

`TaskModelAuthority` remains an invocation-time property derived by `LocalModelGateway` from the validated immutable `TaskContract`. The composition layer does not instantiate, cache, widen, or bypass model authority.

## Configuration

Local AI is disabled unless `local_ai.enabled` is the JSON boolean `true`.

Example only; model names below are placeholders and are not approved or provisioned by this configuration:

```json
{
  "local_ai": {
    "enabled": true,
    "bindings": [
      {
        "model_id": "trusted-small",
        "runtime_id": "ollama-local",
        "runtime_model": "runtime-small:latest",
        "tier": "small",
        "capabilities": [
          "generation.text",
          "generation.json"
        ]
      },
      {
        "model_id": "trusted-embedding",
        "runtime_id": "huggingface-local",
        "runtime_model": "runtime-embedding",
        "tier": "small",
        "capabilities": [
          "retrieval.embedding.query",
          "retrieval.embedding.document"
        ]
      }
    ]
  }
}
```

Each binding accepts exactly these fields:

- `model_id`: stable WorkSpace-facing trusted identifier.
- `runtime_id`: trusted local runtime identifier.
- `runtime_model`: exact runtime-specific model identity expected by the backend.
- `tier`: `small`, `specialist`, or `strong`.
- `capabilities`: only capabilities already supported by `LocalModelGateway`.

The binding object rejects unsupported tiers/capabilities and normalizes the trusted model/runtime identifiers. Duplicate normalized model IDs are rejected.

## Fail-closed behavior

When local AI is enabled, composition fails if:

- `bindings` is missing, empty, or not a JSON array;
- a binding is not an object;
- a required binding field is missing;
- a binding contains an unknown field such as a download flag;
- a field has the wrong type or an empty value;
- capabilities are duplicated or unsupported;
- normalized `model_id` values collide;
- a configured generation binding has no injected generation backend;
- a configured embedding binding has no injected embedding backend.

When local AI is absent or explicitly disabled, composition returns `None` and does not inspect or invoke model backends.

## Backend injection

The factory takes backend mappings that have already been created and managed elsewhere:

```python
gateway = build_local_model_gateway(
    config,
    generation_backends={"trusted-small": managed_ollama_client},
    embedding_backends={"trusted-embedding": managed_embedding_adapter},
)
```

Only backend entries whose IDs are required by trusted bindings are copied into the resulting gateway. Extra injected entries do not become trusted models because the registry remains deny-by-default.

The existing `LocalModelGateway` continues to enforce the exact runtime-model identity at invocation time and derives model authority from each `TaskContract`.

## Explicit non-goals

v0.3 does not:

- add model weights;
- modify `config/models.approved.json`;
- call Ollama `/api/pull` or any model download API;
- install Ollama, Transformers, vLLM, or another runtime;
- create a second HTTP client;
- expose LAN/public model endpoints;
- choose models from prompts;
- let user input register a model;
- grant `TaskModelAuthority` or `TaskCapabilityAuthority`;
- wire the gateway into Orchestrator or UI yet;
- add inference streaming.

## Verification gates

`tests/test_local_ai_composition.py` covers disabled mode, malformed configuration, unknown keys, duplicate IDs/capabilities, unsupported policy values, missing injected backends, immutable trusted composition, no backend calls during composition, and deny-by-default handling of an extra untrusted backend.

The next stage after exact-head CI is v0.4: inject this composition into the application/Orchestrator construction boundary without hard-coding any model identity into workflow logic.
