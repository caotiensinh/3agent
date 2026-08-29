# WorkSpace Capability Broker v1

Status: **D0-03 baseline security boundary**

## Purpose

WorkSpace must never treat the existence of a gateway, shell wrapper, skill, model response, or untrusted document as permission to use a capability. Runtime authority comes from deterministic policy and the immutable `TaskContract`.

Capability Broker v1 projects the capability subset of the bridge-bound task authority into one typed decision:

```text
TaskContract
  -> TaskModelAuthority (bridge-bound immutable envelope)
  -> TaskCapabilityAuthority
  -> CapabilityDecision(task, capability, resource, effect)
  -> gateway side effect only when allowed
```

`TaskCapabilityAuthority.from_model_authority()` is a deterministic projection of fields that were already derived from the immutable contract. Prompt text, model output, tool output and web/file content are not authority inputs.

## Typed decision

A decision has these logical fields:

- task ID;
- logical capability (`run_tests`, `apply_patch`, `web_gateway`, ...);
- resource kind;
- bounded resource reference;
- effect (`read`, `compute`, `execute`, `write`, `network_read`);
- allow/deny;
- reason code;
- immutable authority fingerprint.

The audit-safe metadata representation never stores a raw URL, command argv or resource path. `resource_ref` is represented by SHA-256 only.

## Default deny

The broker rejects a request when any of the following is true:

- the capability is unknown;
- the capability is not in `TaskContract.allowed_tools`;
- the requested effect does not match the capability's fixed effect;
- network authority exceeds the contract;
- write authority exceeds `write_scope`;
- the task identity does not match the authoritative inference scope;
- a scoped execution call does not declare its logical capability.

Denial occurs before the inner Internet/execution gateway is called and before successful tool-call telemetry is emitted.

## Network authority

`web_gateway` maps only to `network_read` and is authorized only when both are true:

- sensitivity is `public`;
- network scope is `allowlisted_egress`.

Capability Broker v1 intentionally has **no `network_write` capability**. A scoped `post_json` attempt therefore fails before the inner gateway receives the payload. This reinforces the existing WorkSpace rule that arbitrary POST/upload/webhook/telemetry is not autonomous runtime authority.

## Execution authority

A production-scoped `MeteredExecutionGateway.run()` must name a logical capability. Generic shell availability is not authorization.

Examples:

- `run_tests` -> `execute`;
- `run_linter` -> `execute`;
- `apply_patch` -> `write`;
- `write_staging` -> `write`.

Write calls must also provide a bounded relative `resource_ref`. `..`, absolute paths, resources outside `write_scope`, and a default `write_scope=none` fail closed. A tool being present in `allowed_tools` is therefore necessary but not sufficient to mutate state.

## Scope and expiry

Production Research and Presentation already execute inside `inference_scope()` with bridge-bound task authority. Capability authority is available only inside that trusted task context and disappears when the context exits. Task/stage scope therefore provides the v1 authority-expiry boundary.

A future operator-driven **mid-task emergency revocation** mechanism may be added as separate hardening. It must only narrow existing authority; it may never grant a capability that the immutable TaskContract did not contain.

## Legacy compatibility boundary

Unscoped utility/tests retain historical gateway behavior for compatibility. This is **not** production authorization. Production workflow authority is the TaskContract-bound inference scope; scoped execution/network paths are fail-closed through the broker.

## Security invariants

1. Lower authority layers cannot mint higher-layer capability.
2. Stronger model routing cannot expand capability authority.
3. Internet read authority cannot become upload/POST authority.
4. Shell availability cannot become generic execution authority.
5. Write-capable tools cannot bypass `write_scope`.
6. A denied attempt creates no inner side effect.
7. Broker metadata contains no prompt, response, evidence body, URL, argv, credential or raw resource path.
