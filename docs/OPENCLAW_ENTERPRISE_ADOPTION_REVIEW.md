# OpenClaw Enterprise Adoption Review

Status: architecture decision record / implementation input  
WorkSpace source snapshot: `a28edde02555255c5fda78546f6936fbf645b55a`  
OpenClaw research snapshot: `7839c0b966a179711e0dc661946fc8365822791b`  
Review date: 2026-09-09

## 1. Purpose

This document records which OpenClaw runtime patterns WorkSpace should learn from,
which must be adapted to WorkSpace's stronger confidentiality model, which should
be deferred, and which are explicitly prohibited in Confidential Core.

This is not a source-code port and OpenClaw is not an upstream architecture for
WorkSpace. The review extracts engineering invariants and re-expresses them using
WorkSpace-native capability, authority, evidence, checkpoint, and OS-boundary
contracts.

## 2. Non-negotiable WorkSpace invariants

Any adopted pattern MUST preserve all of the following:

1. Confidential Core has no LAN/Internet egress and no public egress-broker membership.
2. Public Research is a separate UID/data/trust zone and cannot read confidential stores.
3. Capability authority is deny-by-default and deterministic; model output never grants authority.
4. Capability discovery must not execute unreviewed code.
5. Active diagnostics use curated symbolic operations, bounded targets, explicit authority, evidence, and approval where required.
6. Runtime state changes must be auditable and restart-safe.
7. A later hook, plugin, model, file, page, or message cannot weaken an earlier deny/block decision.
8. Files, web content, model output, and tool output are untrusted data, never policy authority.

## 3. Research lanes

The review was decomposed into 20 independent architecture lanes, matching the
repository execution-governance target where the subject admits useful parallelism.
The lanes are analytical decomposition, not fabricated worker activity.

| # | Lane | OpenClaw pattern studied | WorkSpace decision |
|---|---|---|---|
| 1 | Control plane | Long-lived Gateway owns sessions/tools/events | ADAPT |
| 2 | Protocol | Typed request/response/event contracts | ADOPT |
| 3 | Idempotency | Idempotency keys for side effects | ADOPT |
| 4 | Run lifecycle | Explicit run start/finish/end/error | ADOPT |
| 5 | Writer ownership | Per-session active writer + transactional expected writer | ADOPT P0 |
| 6 | Queueing | Session lane + global/resource lanes | ADOPT |
| 7 | Cancellation | Owner-aware cancellation and settlement | ADAPT |
| 8 | Timeouts | Queue/execution/model/provider timeout separation | ADOPT |
| 9 | Recovery | Generation/owner-aware stale-run recovery | ADOPT |
| 10 | Capability revision | Session pins an immutable skill/capability revision | ADOPT |
| 11 | Discovery | Manifest-first cold discovery | ADAPT STRICTER |
| 12 | Authorization | Exact prepared operation + approval binding | ADOPT / already partly present |
| 13 | Hooks | Deterministic lifecycle hooks | ADAPT |
| 14 | Monotonic policy | A block cannot be cleared by a later hook | ADOPT |
| 15 | Audit | Metadata-only security/runtime audit | ADOPT |
| 16 | Secure files | Descriptor/canonical-path revalidation before mutation | ADOPT |
| 17 | Identity/secrets | Explicit identity and secret ownership | ADAPT |
| 18 | Plugin supply chain | Plugin install/update policy | REJECT in Core; curated capability promotion only |
| 19 | Doctor/audit | Deterministic security posture audit | ADOPT |
| 20 | Multi-trust deployment | One Gateway is one trust boundary | KEEP WorkSpace's stronger zone split |

## 4. Adopt now (P0/P1)

### 4.1 Durable writer-generation fencing — P0

Problem: a superseded worker may still be alive after cancellation, timeout, restart,
or replacement. Without a transactional writer generation check, it can commit
stale transcript, checkpoint, observation, artifact, or state after the new run has
become authoritative.

Required invariant:

```text
claim writer(run A) -> generation 1
claim writer(run B) -> generation 2
run A write(expected generation 1) -> DENY
run B write(expected generation 2) -> ALLOW
```

The check MUST occur inside the same database transaction as the protected write.
A pre-check on another connection is insufficient because it creates a TOCTOU race.

Wave 1 introduces `RuntimeWriterLeaseRepository` as the canonical primitive. It is
not counted as complete enforcement until dispatch, observation, transcript,
artifact, and other authoritative state writers call
`require_current_in_transaction()` from their write transaction.

### 4.2 Typed control-plane protocol — P1

WorkSpace should converge UI, CLI, and local API onto one local control-plane
contract with:

- schema-versioned request and receipt envelopes;
- stable request/run/session/trace identifiers;
- strict unknown-field rejection on authority-sensitive messages;
- normalized reason codes;
- side-effecting operations requiring idempotency keys;
- no direct public listener in Confidential Core by default.

This does not require copying OpenClaw's WebSocket transport. WorkSpace should keep
transport replaceable and make the schema/authority contract canonical.

### 4.3 Lane-aware scheduling — P1

WorkSpace already has deterministic execution/resource scheduling. Extend rather
than replace it with these layers:

```text
admission/global cap
        |
context/session lane (serial authoritative state)
        |
resource lane (GPU/CPU/IO/background)
        |
worker selection
```

A single session/context lane must serialize authoritative writes even when tool or
model computation runs concurrently elsewhere.

### 4.4 Immutable capability revision end-to-end — P1

WorkSpace already has immutable `CapabilityDescriptor`, content-addressed
`CapabilityRegistrySnapshot`, deny-by-default `TaskCapabilityAuthority`, and a
dispatch ticket that revalidates authority. Keep those as canonical.

Domain registries must become compilers/adapters into the canonical descriptor
snapshot rather than alternate authorization authorities. A task/run binds the
snapshot fingerprint it started with; registry changes affect the next run unless a
reviewed migration explicitly says otherwise.

### 4.5 Prepared-operation/approval binding — P1

The existing security operation-plan contract correctly states that a plan is
advisory and cannot authorize execution. The symbolic operation binding also avoids
`eval`, arbitrary import, and model-selected Python targets. Preserve this.

For every active operation, the eventual execution receipt should bind:

- operation/capability identifier and revision;
- exact target/resource scope;
- normalized parameters digest;
- authority/policy fingerprint;
- approval identity and scope when required;
- writer generation/run identity;
- resulting evidence references.

Revalidate immediately before the side effect.

### 4.6 Monotonic deterministic hooks — P1

Hooks may enrich context, add restrictions, request cancellation, or add audit
metadata. They must not expand authority or undo a prior block.

```text
allow + block => block
block + allow => block
cancel + continue => cancel
```

Hook output is data. Canonical authority remains code/policy.

### 4.7 Timeout taxonomy — P1

Do not overload one timeout into several failure meanings. Record at least:

- queue/admission timeout;
- execution wall timeout;
- model idle/stream timeout;
- provider/connect timeout;
- tool timeout;
- delivery/settlement timeout.

Recovery logic must distinguish "caller stopped waiting" from "execution stopped".

### 4.8 Metadata-only audit ledger and deterministic security audit — P1

Audit records should prefer identifiers, hashes, decisions, reason codes, durations,
resource classes, approval state, and evidence references. Prompts, credentials,
raw tool results, and confidential file contents must not be duplicated into the
audit ledger.

Add an offline `workspace security-audit` / doctor surface that deterministically
checks the enterprise posture: UID separation, data-root permissions, nftables,
systemd hardening, broker membership, model endpoint scope, capability snapshot,
plugin/skill provenance, and runtime fencing state.

### 4.9 Secure file mutation — P1

For authoritative artifact/file writes, protect against path and symlink races:

1. resolve the allowed root;
2. open/prepare the target using safe flags/semantics;
3. validate identity/containment on the opened object;
4. revalidate immediately before destructive mutation/move;
5. fail closed on path/identity drift.

A lexical path-prefix check alone is not an enterprise security boundary.

## 5. Adapt, do not copy

### 5.1 Gateway

OpenClaw's Gateway is valuable as a control-plane pattern, but WorkSpace must not
turn it into a mixed-trust network hub. The WorkSpace equivalent is a local control
plane inside each trust zone.

Confidential Core and Public Research keep separate processes, UIDs, databases, and
capability surfaces. Cross-zone transfer remains an explicit reviewed bridge, not a
session convenience API.

### 5.2 Plugins -> reviewed capabilities

OpenClaw plugins are trusted in-process code. That is too broad for Confidential
Core. WorkSpace should use:

```text
metadata-only discovery
    -> canonical descriptor
    -> review/promotion
    -> immutable registry snapshot
    -> authority decision
    -> symbolic binding
    -> execution adapter
```

No discovery-time import and no Internet package install in Core.

### 5.3 Memory/context

Keep context as bounded working memory and storage as evidence/provenance-backed
state. Do not allow tool/page/file instructions to autonomously create privileged or
persistent memory.

## 6. Explicitly rejected in Confidential Core

The following are prohibited unless a future architecture review changes the Core
security invariant:

- arbitrary third-party in-process plugins;
- Internet-driven plugin/skill install or update;
- unsandboxed generic host shell as an agent default;
- elevated escape-hatch that bypasses capability authority;
- direct browser/web egress from the confidential runtime;
- cloud workspace transfer;
- one Gateway spanning mutually untrusted users/data zones;
- runtime discovery that imports candidate code merely to inspect it;
- hooks capable of weakening a prior deny/cancel/block;
- model-selected module/class/function imports;
- hidden telemetry containing confidential content.

## 7. Existing WorkSpace components that remain canonical

Do not replace these with parallel OpenClaw-shaped frameworks:

- `capability_descriptor.py` — immutable descriptor + fingerprint;
- `capability_registry_snapshot.py` — deterministic content-addressed snapshot;
- `capability_authority.py` — deny-by-default authority;
- `capability_invocation_adapter.py` — dispatch ticket + immediate revalidation;
- `runtime_checkpoint.py` — canonical restart/recovery validation;
- `execution_checkpoint.py` — immutable receipts + tamper-evident event chain;
- `security_monitoring/operation_plan.py` — advisory planning only;
- `security_monitoring/operation_binding.py` — closed symbolic binding;
- diagnostics/security registries — domain metadata sources to be converged through adapters.

## 8. Source material reviewed

Pinned OpenClaw source/docs at `7839c0b966a179711e0dc661946fc8365822791b`:

- `docs/concepts/architecture.md`
- `docs/concepts/agent-loop.md`
- `docs/concepts/queue.md`
- `docs/gateway/security/index.md`
- `docs/gateway/security/tool-permissions.md`
- `docs/gateway/security/secure-file-operations.md`
- `docs/gateway/security/running-the-audit.md`
- `docs/plugins/architecture-internals.md`
- `docs/plugins/architecture-internals/load-pipeline.md`
- `docs/plugins/architecture-internals/new-capability.md`

Relevant WorkSpace source was reviewed at
`a28edde02555255c5fda78546f6936fbf645b55a`.

## 9. Adoption quality gate

A pattern is not "adopted" because a document mentions it. It reaches DONE only
when all applicable gates pass:

1. threat model and invariant written;
2. canonical schema/interface exists;
3. negative/fail-closed tests exist;
4. integration uses the canonical path (no bypass path remains);
5. restart/concurrency/tamper behavior is tested where relevant;
6. regression suite is green;
7. CI is green on the exact PR head;
8. evidence/receipt proves the intended behavior;
9. documentation and operator recovery path exist.

Planning, source reading, and a dormant primitive do not count as production
completion.
