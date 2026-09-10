# Local AI Application Bootstrap v0.4

Status: **merged production architecture**  
Merged by: PR #452 — `feat(models): wire authority-bound local AI runtime bridge`  
Merge commit: `7c7290f8e595edafe024083c6fced7c64be3357b`  
Current-state reference: `docs/PROJECT_CURRENT_STATE.md`

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

The primary CLI startup constructs the application through `build_orchestrator(load_config())`, a backward-compatible facade over `build_application_runtime()`.

This makes v0.4 the canonical composition boundary for the primary CLI while leaving existing CLI command handling and Orchestrator domain logic unchanged.

A configuration that enables Local AI without supplying the required backend injections fails closed. Automatic backend creation is intentionally deferred rather than silently bypassing trusted composition.

## Packaged chat boundary on the v0.4 merge baseline

v0.4 did **not** finish chat/API convergence.

On `main@7c7290f8e595edafe024083c6fced7c64be3357b`:

- `workspace-chat` and `three-agent-chat` still resolve to `three_agent.chat_gateway:main`;
- `chat_gateway.main()` loads configuration and constructs `Orchestrator(config)` directly;
- ordinary direct chat still uses the existing orchestrator model path;
- `LocalModelGateway` is therefore not yet the sole direct-chat inference boundary.

This is an integration gap, not a reason to bypass the trusted gateway. Frontend/API/chat code must not create a direct Ollama/runtime authority path as a shortcut.

At the 2026-09-10 audit checkpoint, PR #505 (`feat(models): route packaged chat through application runtime`) is open and proposes v0.5a assembly convergence. Its stated scope deliberately leaves ordinary direct-chat `LocalModelGateway` convergence for a later v0.5b. An open PR is WIP and must not be described as production until merged and reverified on `main`.

## Verification

`tests/test_local_ai_application_bootstrap.py` verifies:

- disabled mode is a no-op and performs zero inference calls;
- enabled mode admits only configured trusted backend IDs;
- malformed config fails before Orchestrator construction;
- missing backend injection fails before Orchestrator construction;
- later mutation of the source config does not rewrite the already-built trusted binding;
- the backward-compatible facade returns the existing Orchestrator surface;
- the production CLI cannot bypass enabled Local AI fail-closed composition.

PR #452 passed exact-head CI before merge and the merge commit subsequently passed the repository's post-merge acceptance lanes observed during the audit.

## Next convergence boundary

The next Local AI integration stages must preserve this invariant:

```text
server-side task/request classification
  -> immutable TaskContract
  -> TaskModelAuthority
  -> LocalModelGateway
  -> trusted pre-created backend
```

No request-supplied model name, prompt instruction, frontend field, raw runtime discovery result or open PR may widen authority.

The remaining work is deliberately split:

- **v0.5a** — packaged chat/application assembly through `ApplicationRuntime` without changing ordinary direct-chat model authority;
- **v0.5b** — safe server-side TaskContract compilation and convergence of ordinary direct chat onto the authority-bound `LocalModelGateway`;
- later UI/streaming exposure only after the same authority and cancellation/output-budget contracts are preserved.
