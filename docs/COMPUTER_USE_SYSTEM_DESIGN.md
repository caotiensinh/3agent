# WorkSpace Governed Computer Use — System Design

Status: Architecture baseline  
Document owner: WorkSpace  
Canonical document: `docs/COMPUTER_USE_SYSTEM_DESIGN.md`  
Last updated: 2026-09-10

## 1. Purpose

This document defines the canonical architecture for adding computer-use capability to WorkSpace without creating a second execution authority or weakening the local-first confidential runtime.

The design is provider-neutral. OpenAI, Anthropic, local multimodal models, or future providers may propose actions, but no model is an authority. Every action must pass deterministic WorkSpace contracts, capability policy, scoped resource validation, execution budgets, single-writer ownership, and evidence binding before it can change state.

The capability is designed as an extension of existing WorkSpace primitives:

- `TaskContract` remains the task-level authority boundary.
- `TaskCapabilityAuthority` remains the capability/resource/effect decision authority.
- `RuntimeWriterLease` remains the single-writer ownership primitive.
- `InvocationDecisionReceipt` remains audit metadata and never grants authority.
- `ExecutionObservation` remains the bounded normalized observation/evidence contract.
- existing confidential/public/auth trust-zone separation remains unchanged.

## 2. Historical and technical baseline

Computer use did not originate from OpenClaw.

- Anthropic announced Claude computer use in public beta on 2024-10-22. Claude can inspect the screen and request cursor, click, keyboard, and related client-side actions.
- OpenAI announced Operator and its Computer-Using Agent (CUA) on 2025-01-23. CUA observes screenshots, emits GUI actions, observes the resulting state, and can self-correct.
- OpenClaw later exposed a local Gateway/browser-control architecture with isolated Chromium profiles, Playwright-backed interaction, local/remote browser routing, and policy-controlled tool exposure.

These systems are best understood as convergent implementations of a general control loop rather than one product copying a single originating project.

Canonical external references:

- OpenAI CUA: https://openai.com/index/computer-using-agent/
- OpenAI Operator: https://openai.com/index/introducing-operator/
- OpenAI Operator System Card: https://openai.com/index/operator-system-card/
- Anthropic computer use launch: https://www.anthropic.com/news/3-5-models-and-computer-use
- Anthropic tool-use architecture: https://docs.anthropic.com/en/docs/agents-and-tools/tool-use/overview
- OpenClaw browser architecture: https://docs.openclaw.ai/tools/browser
- OpenClaw browser security: https://docs.openclaw.ai/gateway/security

## 3. Core model: perception → decision → action → verification

The generic loop is:

```text
User intent
   |
   v
TaskContract / ExecutionPlan
   |
   v
Model or deterministic planner proposes next action
   |
   v
Normalize provider action into WorkSpace ComputerActionRequest
   |
   v
Deterministic policy + capability + resource + risk evaluation
   |
   +---- DENY -----------------------------> evidence + stop/replan
   |
   +---- REQUIRE_APPROVAL ---> approval ----+
   |                                       |
   v                                       v
Acquire/validate single-writer lease when state may change
   |
   v
Executor performs exactly one bounded action
   |
   v
Collect structured observation + screenshot only when needed
   |
   v
Verify expected postcondition and state freshness
   |
   v
Bind evidence to ExecutionObservation
   |
   v
Return normalized result to planner/provider
   |
   +---- more work -> repeat
   |
   +---- complete -> deterministic acceptance gate
```

The model never directly controls an OS input device. It produces an action proposal. A WorkSpace executor performs the action only after deterministic admission.

## 4. Design principles

### 4.1 Existing authority first

Computer use must not introduce an independent permission database or a second policy engine. New capabilities are added to the existing tool/effect/resource vocabulary and enforced by existing WorkSpace authority primitives.

### 4.2 Structured control before pixels

Preferred execution order:

```text
1. native API / application protocol
2. bounded CLI / PowerShell / SSH operation
3. browser DOM / accessibility snapshot
4. OS accessibility tree
5. screenshot + coordinate/pointer fallback
```

The lowest sufficient layer is selected deterministically. GUI vision is a compatibility fallback, not the default execution mechanism.

### 4.3 Read before write

Observation and diagnosis are separated from mutation. The default MVP is read-only observation. State-changing actions become available only after authorization, approval, writer ownership, and evidence paths are complete.

### 4.4 Least privilege and bounded resources

Authority is scoped to a concrete resource, application/session, host, browser profile, path, network interface, or endpoint. Wildcard state-changing grants are prohibited by default.

### 4.5 Untrusted content never becomes authority

Web pages, emails, documents, images, tool output, terminal output, accessibility text, and screenshots may contain prompt injection. They are observations only. They cannot add tools, expand scopes, approve actions, or modify policy.

### 4.6 User takeover for secrets

Passwords, MFA, CAPTCHAs, payment confirmation, recovery secrets, and similarly sensitive interactive steps use a user-takeover state. The agent must not request or persist plaintext secrets merely to continue the workflow.

### 4.7 One canonical writer

Only one actor may own mutating control of one computer-use session at a time. `RuntimeWriterLease` or a narrow adapter built on it must fence stale/replayed writers.

## 5. Trust boundaries

Computer use must preserve the WorkSpace trust-zone invariant.

### 5.1 Confidential Core

- may reason over confidential work using local inference;
- has no direct public Internet route;
- cannot gain Internet reachability because a browser executor exists elsewhere;
- may control only resources already authorized by its TaskContract and deployment policy.

### 5.2 Public Research

- may use an isolated browser profile only after public-lane policy admits the task;
- must not mount/read confidential WorkSpace storage;
- public page text remains untrusted input;
- egress remains allowlisted and DLP-gated.

### 5.3 Local Device Agent

- runs as an unprivileged OS identity by default;
- exposes a narrow authenticated control surface;
- does not contain model authority;
- receives pre-authorized normalized actions rather than arbitrary scripts wherever possible.

### 5.4 Optional Privileged Broker

Some enterprise operations genuinely require elevation. They must use a separate privileged broker process with a very small fixed RPC vocabulary. The unprivileged agent cannot ask the broker to execute arbitrary shell text.

## 6. Canonical components

### 6.1 ComputerUseCoordinator

Responsibilities:

- owns a computer-use session state machine;
- binds user intent to TaskContract and ExecutionPlan;
- requests observations and actions one step at a time;
- never authorizes itself;
- enforces maximum steps/tool calls/wall time through existing budgets.

Non-responsibilities:

- no policy decisions;
- no direct mouse/keyboard implementation;
- no secret storage.

### 6.2 ProviderBridge

Normalizes provider-specific action formats into a provider-neutral request.

Examples:

- OpenAI `computer_call` → `ComputerActionRequest`;
- Anthropic `tool_use` for computer tool → `ComputerActionRequest`;
- local model JSON action → `ComputerActionRequest` after strict schema validation.

Provider output is treated as untrusted action proposal data.

### 6.3 ComputerActionRequest

Proposed canonical fields:

```text
schema_version
session_id
action_id
task_id
plan_fingerprint
node_id
provider_ref
operation
effect
resource_kind
resource_ref
arguments
state_precondition_sha256
expected_postcondition
risk_class
requires_writer
idempotency_key
```

Raw credentials, raw URLs containing credentials, and unrestricted command strings are not allowed in generic action metadata.

### 6.4 ActionRouter

Selects the safest sufficient execution path.

Priority:

```text
API > CLI > DOM > ACCESSIBILITY > VISION_POINTER
```

Routing is deterministic and policy constrained. A model may suggest a route but cannot force a less-safe route when a safer authorized adapter exists.

### 6.5 CapabilityAuthority integration

Each normalized action maps to:

```text
capability/tool_id
effect
resource_kind
resource_ref
```

`TaskCapabilityAuthority` decides whether that exact action falls within immutable task authority.

Proposed initial computer-use capabilities:

```text
computer.screen.observe
computer.window.observe
computer.accessibility.observe
browser.dom.observe
browser.navigate
browser.interact
computer.pointer.interact
computer.keyboard.interact
computer.clipboard.read
computer.clipboard.write
```

State-changing browser/desktop actions must not be introduced as generic `execute-anything` capability.

### 6.6 RiskClassifier

The classifier is deterministic. It derives risk from operation/effect/resource, not model opinion.

Initial classes:

- `R0_OBSERVE`: screenshot, accessibility tree, tab/window metadata, read-only DOM.
- `R1_REVERSIBLE_INTERACTION`: focus, scroll, open local UI, navigate within an approved origin where no durable side effect is expected.
- `R2_STATE_CHANGE`: form submit, settings change, file write, message send, account preference change.
- `R3_PRIVILEGED_OR_SENSITIVE`: elevation, security setting, identity/credential operation, destructive action, payment/financial commitment, account recovery.

Default handling:

- R0: automatic only when TaskContract explicitly allows the tool/resource.
- R1: automatic or approval according to deployment policy and expected side effect.
- R2: explicit user approval unless a narrowly scoped operator-approved workflow contract explicitly permits automatic execution.
- R3: deny by default or require high-assurance user takeover/two-step approval according to a separately reviewed policy.

### 6.7 ApprovalBroker

Approval is not a chat sentence interpreted by the model. It is a signed/bound runtime event associated with:

```text
user/session identity
action fingerprint
resource scope
risk class
expiry
action-count limit
one-shot or session scope
```

A grant can only narrow existing TaskContract authority. It cannot authorize a tool absent from the TaskContract.

### 6.8 WriterFence

Before a mutating action:

1. validate the current execution plan;
2. require the current `RuntimeWriterLease` inside the write boundary;
3. bind the action id/idempotency key to the current generation;
4. reject stale/replayed actions;
5. release or rotate ownership on takeover/recovery as defined by session state.

### 6.9 Executors

Executors are small adapters, not autonomous agents.

#### Browser executor

Preferred implementation: Playwright or CDP in an isolated profile.

Capabilities:

- tab lifecycle;
- URL/origin observation;
- bounded DOM/accessibility snapshot;
- click/type/select/scroll only on validated targets;
- screenshot on demand;
- download quarantine.

#### Windows executor

Preferred order:

- Windows UI Automation for structured UI;
- bounded PowerShell/cmdlets for deterministic system inspection/change;
- SendInput/pointer injection only as fallback.

Do not run the normal device agent as Administrator. Privileged actions go through the privileged broker.

#### Linux executor

Preferred order:

- native CLI/system APIs;
- AT-SPI accessibility where applicable;
- compositor-supported remote-desktop/input portal on Wayland;
- X11 input fallback only in explicitly trusted deployments.

#### macOS executor

- Accessibility API for UI control;
- Screen Recording permission for screen observation;
- separate privileged helper only for operations that genuinely require elevation.

### 6.10 ObservationCollector

Produces bounded, normalized observation data suitable for `ExecutionObservation`.

Observation types:

- active application/window identity;
- browser URL/origin and tab id;
- DOM/accessibility subtree;
- screenshot reference + hash, not unbounded image history;
- command result with bounded stdout/stderr;
- expected postcondition result;
- state hash/freshness token.

### 6.11 EvidenceRecorder

Every admitted action records enough metadata to reconstruct:

- what was proposed;
- what policy decided;
- whether approval was required and received;
- which writer generation executed it;
- pre-state hash;
- executor result;
- post-state hash;
- verifier result;
- bounded evidence references.

`InvocationDecisionReceipt` remains advisory audit metadata and must never be reinterpreted as an authority token.

## 7. Session state machine

Canonical proposed states:

```text
CREATED
  -> OBSERVING
  -> ACTION_PROPOSED
  -> POLICY_CHECKED
      -> DENIED
      -> WAITING_APPROVAL
      -> READY_TO_EXECUTE
  -> EXECUTING
  -> VERIFYING
      -> OBSERVING        (next step)
      -> COMPLETED
      -> FAILED_RETRYABLE
      -> WAITING_USER_TAKEOVER
      -> FAILED_TERMINAL
```

Important invariants:

- `WAITING_APPROVAL` cannot transition to `READY_TO_EXECUTE` from model output.
- `WAITING_USER_TAKEOVER` suspends agent input injection.
- a stale observation invalidates coordinate-based actions;
- failed verification never triggers a blind repeated click/type.

## 8. Stale-state and replay defense

GUI automation fails dangerously when the visible state changes between observation and action.

Each action should carry a precondition derived from one or more of:

- tab/window id;
- URL/origin;
- DOM/accessibility target reference;
- screenshot/state hash;
- focused process/window identity;
- current writer generation.

If the precondition is stale, the action is rejected and the coordinator must observe again.

Every mutating action receives an idempotency key. A retry first checks whether the postcondition already holds. WorkSpace must never blindly repeat an uncertain side-effect action.

## 9. Prompt-injection defense

Threat model: an attacker controls text or pixels observed by the agent and attempts to cause data exfiltration, tool expansion, policy bypass, or unintended state changes.

Controls:

1. trust hierarchy from `AGENTS.md` remains authoritative;
2. browser/page/document text enters only as untrusted observation data;
3. tool lists and scopes are compiled before untrusted content is observed;
4. no content can create an approval event;
5. navigation/egress targets are independently validated;
6. confidential data is unavailable to the public browser identity;
7. screenshots/tool results are bounded and optionally redacted before retention;
8. suspicious instruction-like content may force re-observation or user confirmation but never grant authority;
9. red-team fixtures must include indirect prompt injection in pages, PDFs, emails, images, tooltips, accessibility labels, terminal output, and downloaded files.

## 10. Credential and user-takeover design

The agent should not need password-manager access.

For a sensitive authentication step:

```text
agent navigates to authentication boundary
-> WorkSpace declares WAITING_USER_TAKEOVER
-> input injection and screenshots for sensitive region/session are suspended according to policy
-> user enters secret/MFA directly
-> user explicitly returns control
-> WorkSpace records only bounded success/failure metadata
-> new observation is collected
-> agent continues under the same or narrowed TaskContract
```

The transition back to agent control must invalidate stale action references created before takeover.

## 11. Browser isolation model

Three deployment profiles are supported conceptually:

### Isolated managed profile — default

- dedicated browser user-data directory;
- password manager/sync disabled;
- separate downloads quarantine;
- no personal cookies by default;
- only allowlisted origins according to task/deployment policy.

### User signed-in profile — high risk, opt-in

- attaches to a user browser only after explicit user consent;
- scope must identify the profile/session;
- treated as operator-equivalent access to that browser state;
- never the default for unattended execution.

### Remote browser/node

- authenticated device identity;
- encrypted private transport;
- node/profile allowlist;
- no public unauthenticated control port.

## 12. Network architecture

```text
                 +----------------------+
                 | Confidential Core    |
                 | local inference      |
                 | confidential store   |
                 | NO public egress     |
                 +----------+-----------+
                            |
                  bounded local contracts
                            |
             +--------------v--------------+
             | Computer Use coordination   |
             | policy / approval / evidence|
             +-------+--------------+-------+
                     |              |
          local-only |              | public-lane only
                     |              |
        +------------v---+      +---v----------------+
        | Device Agent   |      | Public Browser    |
        | unprivileged   |      | isolated identity |
        +--------+-------+      +---------+----------+
                 |                        |
           local OS/UI              egress broker
                                          |
                                   allowlisted HTTPS
```

No bridge is allowed to turn browser control into a general confidential-core Internet path.

## 13. Provider adapters

### 13.1 OpenAI

Conceptual flow:

1. provider emits a computer action request;
2. bridge validates and normalizes it;
3. WorkSpace policy decides independently;
4. executor performs one admitted action;
5. WorkSpace captures the new observation/screenshot;
6. bridge returns a provider-compatible computer output;
7. repeat until completion or WorkSpace stops the session.

### 13.2 Anthropic

Conceptual flow:

1. Claude returns `tool_use` for the computer client tool;
2. bridge normalizes the request;
3. WorkSpace policy decides independently;
4. client executor performs the admitted action;
5. normalized result becomes a `tool_result`;
6. Claude reasons from the new result.

### 13.3 Local models

A local model may emit the same normalized action schema, but it receives no special trust. Schema validation and policy admission are identical.

## 14. Reliability model

### 14.1 Action budget

Use existing execution budgets for:

- maximum steps;
- maximum tool calls;
- retries;
- wall time;
- optional model escalation.

### 14.2 No blind retry

A failed or uncertain action requires:

1. observation/log inspection;
2. postcondition check;
3. failure classification;
4. new strategy or safe idempotent retry.

### 14.3 Target references

DOM/accessibility refs must be session/state scoped. They are invalid after navigation, significant layout change, takeover, browser restart, or writer-generation change.

### 14.4 Human blockers

CAPTCHA, unavailable physical device, login consent, camera/microphone OS prompt, unsupported elevation, or external approval are explicit blockers/user-takeover states rather than triggers for guessing.

## 15. Data retention and privacy

Default:

- do not retain continuous screen video;
- retain only evidence required by task policy;
- prefer hashes and structured observations over raw screenshots;
- redact or deny raw capture for restricted/secret contexts according to existing logging policy;
- do not persist credentials;
- quarantine downloads and treat them as untrusted files;
- bind evidence to task/run/action identifiers and content hashes.

## 16. API boundary examples

### ComputerActionRequest

```json
{
  "schema_version": "workspace-computer-action-request/v1",
  "session_id": "cus_01",
  "action_id": "act_01",
  "task_id": "task_01",
  "operation": "browser.click",
  "effect": "write",
  "resource_kind": "browser_element",
  "resource_ref": "profile:isolated/tab:12/ref:button-save",
  "arguments": {"button": "left"},
  "state_precondition_sha256": "sha256:...",
  "risk_class": "R2_STATE_CHANGE",
  "requires_writer": true,
  "idempotency_key": "sha256:..."
}
```

### ComputerPolicyDecision

```json
{
  "decision": "REQUIRE_APPROVAL",
  "reason_code": "COMPUTER_STATE_CHANGE_REQUIRES_APPROVAL",
  "action_fingerprint": "sha256:...",
  "approval_scope": "ONCE",
  "expires_at": "2026-09-10T00:00:00Z"
}
```

### ComputerObservation

```json
{
  "schema_version": "workspace-computer-observation/v1",
  "session_id": "cus_01",
  "state_id": "state_02",
  "state_sha256": "sha256:...",
  "surface": "browser",
  "active_target_ref": "profile:isolated/tab:12",
  "structured_observation": {},
  "screenshot_ref": null,
  "captured_at": "2026-09-10T00:00:01Z"
}
```

## 17. Implementation boundaries in the current repository

The initial implementation should remain in canonical unversioned modules.

Proposed production modules:

```text
src/three_agent/computer_use.py
```

Only decompose further if measured complexity requires it and each module owns a clearly separate functional authority. The repository Single Canonical Module Rule forbids sibling version/copy implementations.

Initial code responsibilities for `computer_use.py`:

- provider-neutral contracts;
- risk classes;
- deterministic route selection;
- state freshness checks;
- approval requirement calculation;
- no real OS mutation in the first implementation slice.

Existing canonical modules should be extended where authority belongs there:

- `task_contract.py`: register reviewed computer-use tool IDs;
- `capability_authority.py`: map those tools to effects and exact resource policies;
- orchestration/execution modules: integrate the coordinator only after contract tests exist;
- frontend: add approval/takeover UX only after backend approval contracts are stable.

## 18. Phased delivery

### Phase A — contracts and read-only observation

- normalized action/observation contracts;
- deterministic risk and route selection;
- tool/effect/resource registration;
- isolated browser observation only;
- evidence integration tests.

### Phase B — governed browser interaction

- navigate/click/type/select/scroll;
- stale-ref prevention;
- approval for state-changing browser actions;
- download quarantine;
- prompt-injection red-team fixtures.

### Phase C — local desktop observation

- window/process identity;
- accessibility tree;
- screenshot fallback;
- no privileged mutation.

### Phase D — governed desktop interaction

- pointer/keyboard fallback;
- user takeover;
- writer fencing;
- OS-specific permission handling.

### Phase E — privileged broker

Only if concrete enterprise use cases require it and a separate security review approves the fixed RPC vocabulary.

## 19. Acceptance criteria

The capability is not considered production-ready until all mandatory criteria have executed evidence:

1. Model output cannot expand TaskContract tool/network/write authority.
2. Page/document/screenshot content cannot create or simulate approval.
3. A stale action cannot execute after state, takeover, or writer-generation change.
4. State-changing actions are fenced by single-writer ownership.
5. R2/R3 action policy is fail-closed.
6. Confidential Core does not gain public egress through computer use.
7. Provider bridges produce equivalent normalized policy decisions for semantically equivalent actions.
8. Read-only observations are bounded and respect logging/privacy policy.
9. Browser profile isolation is verified.
10. Prompt-injection red-team fixtures cannot cause unauthorized action or data transfer.
11. Existing WorkSpace governance validators and touched tests pass at exact head.

## 20. Non-goals

The first implementation does not aim to:

- create a general remote-admin/RMM product;
- give a model unrestricted shell or Administrator/root authority;
- record a user's entire desktop continuously;
- expose a public browser-control API;
- import personal browser cookies/passwords by default;
- replace existing API/CLI integrations with slower pixel automation;
- bypass application authentication or authorization.

## 21. Architectural conclusion

WorkSpace Computer Use is a governed execution surface, not a model feature.

The strategic advantage is not merely the ability to click a UI. It is the ability to combine deterministic APIs, CLI, DOM, accessibility, and visual fallback under one existing WorkSpace authority/evidence system. This makes computer use suitable for enterprise diagnostics and operations while preserving the repository's local-first, least-privilege, fail-closed security model.
