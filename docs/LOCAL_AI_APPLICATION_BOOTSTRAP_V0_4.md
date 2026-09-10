# Local AI Application Bootstrap v0.4

## Goal

Wire the trusted Local AI Composition v0.3 into the real WorkSpace application construction boundary without adding model-specific logic to Orchestrator or workflow code.

The bootstrap exposes an immutable `ApplicationRuntime` containing the existing `Orchestrator` and an optional `LocalModelGateway`.

```text
AppConfig
  -> build_application_runtime()
     -> build_local_model_gateway()
        -> trusted local_ai.bindings
        -> already-created backend injections
     -> Orchestrator(config)
     -> ApplicationRuntime(orchestrator, local_model_gateway)
```

## Security and authority boundary

The bootstrap does not:

- create Ollama, Transformers, vLLM, or embedding clients;
- download, pull, install, approve, or discover models;
- infer model identity from request or prompt text;
- grant `TaskModelAuthority` or `TaskCapabilityAuthority`;
- invoke generation or embedding backends during startup;
- expose a LAN/public model endpoint;
- modify Orchestrator workflow policy;
- add a second model registry.

`LocalModelGateway` continues to derive `TaskModelAuthority` from the immutable `TaskContract` at invocation time. The bootstrap only composes trusted dependencies.

## Disabled behavior

When `local_ai` is absent or `local_ai.enabled` is `false`, bootstrap creates the normal existing Orchestrator and returns `local_model_gateway=None`. Backend mappings are not trusted or admitted merely because they were supplied.

This preserves the existing startup path as an exact functional no-op for deployments that have not enabled Local AI.

## Enabled behavior

When Local AI is enabled, v0.3 trusted composition executes before Orchestrator construction.

Startup fails closed before application construction when:

- trusted local AI configuration is malformed;
- bindings are absent/empty;
- a required configured backend was not injected;
- any binding violates the v0.2 gateway policy.

Backend objects must already exist and remain owned by their existing lifecycle/resource-management layer. Bootstrap only passes references through composition.

## CLI boundary

The existing CLI startup must construct the application through `build_orchestrator(load_config())`, a backward-compatible facade over `build_application_runtime()`.

This makes v0.4 the canonical application startup boundary while leaving existing CLI command handling and Orchestrator domain logic unchanged.

A configuration that enables Local AI without supplying the required backend injections fails closed. Automatic backend creation is intentionally deferred rather than silently bypassing trusted composition.

## Verification

`tests/test_local_ai_application_bootstrap.py` verifies:

- disabled mode is a no-op and performs zero inference calls;
- enabled mode admits only configured trusted backend IDs;
- malformed config fails before Orchestrator construction;
- missing backend injection fails before Orchestrator construction;
- later mutation of the source config does not rewrite the already-built trusted binding;
- the backward-compatible facade returns the existing Orchestrator surface.

The next stage after exact-head CI is API/CLI exposure of explicit Local AI operations using the application runtime dependency. No UI or streaming path should bypass this bootstrap or the authority-bound gateway.
