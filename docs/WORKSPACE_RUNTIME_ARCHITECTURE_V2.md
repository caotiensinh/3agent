# WorkSpace Runtime Architecture V2

Status: target architecture / incremental migration contract  
Base snapshot: `a28edde02555255c5fda78546f6936fbf645b55a`  
Date: 2026-09-09

## 1. Goal

Converge the existing WorkSpace runtime into one enterprise-grade execution model
without creating another parallel framework and without weakening the Confidential
Core security boundary.

The V2 architecture is a migration of existing components, not a rewrite.

## 2. Target topology

```text
                         UI / CLI / LOCAL API
                                 |
                       LOCAL CONTROL PLANE
             auth / schema / idempotency / receipts
                                 |
                         RUN-SESSION KERNEL
        run_id / session_id / trace_id / writer_generation
                                 |
                 +---------------+---------------+
                 |                               |
          CAPABILITY PLANE                EXECUTION PLANE
                 |                               |
  descriptor -> snapshot -> authority     admission/global cap
                 |                               |
         dispatch ticket                  session/context lane
                 |                               |
       immediate revalidation              resource lane
                 |                          GPU/CPU/IO/bg
                 +---------------+---------------+
                                 |
                    OPERATION / TOOL ADAPTER
                                 |
                  deterministic bounded action
                                 |
              EVIDENCE / ARTIFACT / REPORT STORES
                                 |
                         METADATA AUDIT LEDGER
```

The OS trust-zone boundary remains outside and stronger than this logical runtime:

```text
CONFIDENTIAL CORE UID           PUBLIC RESEARCH UID           EGRESS BROKER UID
read confidential data         no confidential read          no WorkSpace data read
local model only               local model + broker IPC      DNS + public HTTPS only
NO broker membership           NO direct network             allowlisted broker behavior
NO LAN/Internet                separate DB/root              NO runtime authority
```

## 3. Canonical ownership of responsibilities

### 3.1 Capability descriptor and registry

Canonical:

- `CapabilityDescriptor`
- `CapabilityRegistrySnapshot`

Domain-specific registries may describe or compile capabilities but must not become
independent authorization authorities.

Migration rule:

```text
domain metadata / curated taxonomy
              |
              v
     canonical descriptor compiler
              |
              v
     immutable registry snapshot
```

### 3.2 Authorization

Canonical:

- `TaskCapabilityAuthority`
- relevant deterministic monitoring authority for monitoring-domain operations

No model, gateway, UI, route planner, diagnostic classifier, or plugin may grant
capability authority.

### 3.3 Invocation

Canonical ingress:

- `CapabilityInvocationAdapter`

Every side-effecting or externally observable execution path should converge on a
receipt that binds the immutable capability revision/snapshot, authority decision,
request digest, target scope, and eventually run writer generation.

### 3.4 Scheduling

Existing scheduler modules are retained but their responsibilities must become
explicit instead of overlapping:

- admission/global budget: total concurrent work allowed;
- context/session lane: exactly one authoritative writer per context;
- resource scheduler: GPU/CPU/IO/background allocation;
- worker pool: execution placement only.

A scheduler decides *when/where* work may run. It does not decide capability
authority and it does not own persistence truth.

### 3.5 Persistence and recovery

Canonical persistence layers:

- `RuntimeCheckpoint` for validated workflow/runtime recovery state;
- `ExecutionCheckpointRepository` for immutable dispatch/observation receipts and
  tamper-evident execution event chain;
- `RuntimeWriterLeaseRepository` for current writer generation.

Future protected writes must perform writer-lease validation in the same transaction
as the mutation.

## 4. Run/session state contract

Every authoritative execution obtains stable identifiers:

```text
session_id  = user/work context identity
run_id      = one execution attempt within the context
task_id     = canonical work item
trace_id    = observability correlation id
writer_generation = monotonically increasing ownership generation
```

Minimum lifecycle:

```text
ACCEPTED
  -> ADMITTED
  -> RUNNING
  -> SETTLING
  -> SUCCEEDED | FAILED | CANCELLED | MANUAL_RECONCILIATION
```

A terminal state is immutable. A replacement run receives a newer writer generation;
it does not mutate the old run into a new identity.

## 5. Writer-generation invariant

### 5.1 Threat

Cancellation is not proof that old computation has stopped. Network stalls, model
streams, subprocesses, worker restarts, or late callbacks can continue after a new
run has started.

### 5.2 Rule

The database is the authority for current writer ownership.

```text
(task_id, plan_fingerprint) -> current run_id + generation + status
```

Every protected write checks the exact immutable lease in the write transaction.

### 5.3 Required protected surfaces

Rollout order:

1. execution dispatch receipt;
2. execution observation receipt;
3. cancellation/terminal runtime state;
4. conversation transcript writes;
5. workflow state mutations;
6. artifact/report finalization;
7. any durable mutable state produced asynchronously.

Read-only evidence collection does not automatically become authoritative merely
because it completed; its commit/finalization still obeys the current writer.

## 6. Idempotency contract

All local control-plane methods that may create or mutate state require an
idempotency key scoped to actor + operation + target trust zone.

A successful replay with the same canonical request digest returns the original
receipt. Reuse with a different request digest fails closed.

Idempotency is not authorization. Every replay still validates caller identity and
current authority/ownership as required.

## 7. Hook contract

Hooks are deterministic, ordered, schema-versioned policy/data transforms.

Allowed effects:

- add metadata;
- add restrictions;
- request cancellation;
- annotate evidence;
- reject/block.

Forbidden effects:

- add authority not already granted;
- remove a block;
- replace an approved target with a broader target;
- install code;
- create network egress;
- persist privileged memory from untrusted content.

Aggregation is monotonic:

```text
blocked = any(hook.blocked)
cancelled = any(hook.cancelled)
allowed_scope = intersection(all scopes)
```

## 8. Timeout and recovery model

Record timeout type instead of one generic timeout:

| Timeout | Meaning | Recovery default |
|---|---|---|
| admission | work never acquired capacity | safe retry with same idempotency key |
| execution | bounded operation exceeded wall budget | reconcile side-effect state before retry |
| model idle | model stream stopped making progress | abort generation; no automatic side-effect replay |
| provider/connect | dependency unavailable | retry only if operation is safe/idempotent |
| tool | tool-specific deadline | use tool receipt/evidence to determine ambiguity |
| settlement | execution may have finished but final persistence/delivery did not | generation-aware reconciliation |

Recovery is never authority expansion. Ambiguous side effects go to manual
reconciliation unless a deterministic receipt proves the outcome.

## 9. Security audit surface

Target command family:

```text
workspace doctor
workspace security-audit
workspace security-audit --deep
```

The audit should be offline-capable in Confidential Core and return deterministic
finding IDs, severity, evidence metadata, and remediation guidance.

Initial check families:

- process UID/group separation;
- confidential/public data-root permissions;
- broker group membership;
- nftables owner rules;
- systemd hardening;
- model endpoint binding;
- unexpected listening sockets;
- direct egress regression;
- capability snapshot integrity;
- unreviewed capability/plugin/skill presence;
- writer lease/event-chain integrity;
- stale active writer detection;
- audit-log permissions;
- installer/deployment SHA pinning.

The audit must not copy confidential payloads into findings.

## 10. Domain registry convergence

The current diagnostics runtime registry and security capability registry contain
valuable curated domain information and remain useful. Their long-term role is:

```text
domain taxonomy + metadata + symbolic binding
                  |
                  v
     canonical capability descriptor/snapshot
                  |
                  v
       canonical authority/invocation path
```

Do not delete domain-specific taxonomies. Remove only duplicated runtime authority
or incompatible registry semantics after adapters and regression tests exist.

## 11. Gateway decomposition strategy

Large gateway/frontend modules are migration risks. Do not rewrite them all at once.
Extract contracts in this order:

1. request/receipt schema;
2. identity/auth context;
3. idempotency store;
4. run/session lifecycle service;
5. writer lease enforcement;
6. capability invocation boundary;
7. read models/events;
8. transport handlers.

At every step, existing UI/CLI behavior remains behind regression tests.

## 12. Capability onboarding contract

A new capability is production-eligible only when it has:

1. stable identifier and schema version;
2. immutable descriptor revision/fingerprint;
3. declared trust scope/resource class/effects;
4. explicit authority mapping;
5. symbolic execution binding, never arbitrary model-selected import;
6. negative permission tests;
7. deterministic input/output schema tests;
8. timeout/cancellation behavior;
9. evidence/receipt binding;
10. audit metadata contract;
11. promotion/revocation path;
12. operator documentation.

Discovery is metadata-only. Activation is a separate reviewed step.

## 13. Migration waves

### Wave 1 — Runtime fencing foundation

- durable writer lease primitive;
- generation monotonicity;
- tamper-evident lease event chain;
- same-transaction enforcement API;
- focused negative tests;
- adoption review and V2 architecture docs.

Wave 1 is foundation, not full enforcement.

### Wave 2 — Execution persistence enforcement

- bind writer lease to dispatch/observation/cancellation writes;
- refuse stale/missing lease once a plan enters fenced mode;
- bind run/generation into execution audit receipts;
- restart and stale-worker tests.

### Wave 3 — Session/control-plane convergence

- canonical run lifecycle;
- idempotency keys;
- session/context serial lane;
- typed local control-plane contracts;
- migrate chat/workflow writes behind writer fence.

### Wave 4 — Capability convergence

- compile domain registries into canonical snapshots;
- remove alternate runtime authority paths;
- immutable snapshot binding across workers/recovery;
- capability contract conformance suite.

### Wave 5 — Enterprise audit and secure mutation

- security-audit/doctor catalog;
- secure file mutation helpers;
- OS boundary verification;
- stale writer and audit-integrity checks;
- deployment evidence package.

### Wave 6 — Optional channels/integrations

Only after the core invariants are complete. External channels belong outside the
Confidential Core trust boundary or behind a separately reviewed broker/adapter.

## 14. Definition of done

For any wave, DONE means:

- source change exists on exact reviewed head;
- targeted tests green;
- relevant regression tests green;
- CI green on exact head;
- negative/fail-closed behavior tested;
- security invariant unchanged or strengthened;
- migration/bypass audit completed;
- evidence/receipts retained;
- documentation updated.

Source reading, planning, dormant code, or waiting for CI does not increase the
production-complete percentage by itself.
