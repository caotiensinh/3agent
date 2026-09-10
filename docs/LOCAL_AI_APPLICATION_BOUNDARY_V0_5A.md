# Local AI Application Boundary v0.5a

## Purpose

Route the packaged WorkSpace chat entrypoints through the canonical `ApplicationRuntime` composition root introduced in Local AI v0.4.

This phase is intentionally narrow. It does not add a second HTTP framework, a new generation endpoint, model discovery, model installation, model download, or any new network authority.

## Production boundary

The packaged commands:

- `workspace-chat`
- `three-agent-chat`

resolve to `three_agent.chat_application:main`.

`chat_application.main()` loads trusted configuration and calls `build_application_runtime(config)` before orchestrator initialization, authentication bootstrap, service construction, Telegram startup, or `ThreadingHTTPServer` construction.

The existing `chat_gateway` service, authentication, HTTP handler, Telegram bridge, UI capability metadata, and LAN binding behavior are reused. No parallel web stack is introduced.

## Fail-closed ordering

The required startup order is:

1. load trusted configuration;
2. build `ApplicationRuntime`;
3. Local AI composition validates reviewed bindings and required injected dependencies;
4. obtain the composed `Orchestrator`;
5. initialize the orchestrator;
6. initialize authentication and identity stores;
7. construct/start chat services;
8. optionally start the Telegram bridge;
9. bind the HTTP server.

If Local AI is enabled but composition rejects the configuration or dependencies, startup terminates before step 4 and therefore before any HTTP socket is bound.

## Security invariants

v0.5a preserves the v0.4 invariants:

- Local AI composition happens before `Orchestrator` construction inside the canonical composition root.
- The HTTP client cannot provide model bindings, runtime identity, task sensitivity, source trust, risk, tools, capabilities, or authority tiers.
- No raw Ollama or model-runtime endpoint is exposed by this change.
- No model pull/install/download path is introduced.
- Existing chat, authentication, security-monitoring, Telegram, and egress policy surfaces remain authoritative.

## Explicitly deferred to v0.5b

The ordinary direct-chat path still uses the existing orchestrator model path. Converging that path onto `LocalModelGateway` requires a separate dependency-extraction change so the same trusted backend can be composed before `Orchestrator` construction without creating a duplicate runtime client or mutable deferred authority proxy.

v0.5b must preserve server-side `TaskContract` compilation and must not allow a request to manufacture its own model authority.

## Regression requirements

Tests must prove that:

- the packaged chat entrypoints point to the canonical application entrypoint;
- `build_application_runtime()` runs before orchestrator initialization and server construction;
- composition failure prevents HTTP server construction;
- successful startup preserves the existing chat-server lifecycle.
