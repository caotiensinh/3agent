# WorkSpace Governed Computer Use — Implementation Task List

Status: Active delivery plan  
Canonical document: `docs/COMPUTER_USE_TASK_LIST.md`  
Last updated: 2026-09-10

## 1. Delivery rules

This task list is subordinate to:

- `AGENTS.md`;
- `config/workspace.execution-governance.json`;
- the existing WorkSpace security policies and `TaskContract` authority.

Planning, code written, or unexecuted tests do not count as verified completion. Each implementation task reaches `VERIFIED_PASS` only with executed evidence. The repository Single Canonical Module Rule applies throughout.

The implementation is intentionally staged so that WorkSpace gains observation and governance before it gains actuator power.

## 2. Definition of done for the program

The Computer Use program is complete only when:

- provider-neutral action and observation contracts are canonical;
- computer-use tools are represented in `TaskContract` and `TaskCapabilityAuthority` without creating a parallel authority;
- action routing prefers API/CLI/DOM/accessibility over pixel control;
- state-changing actions require the correct approval/writer fence;
- stale/replayed actions fail closed;
- isolated browser execution works;
- native desktop observation and interaction work on supported OS targets;
- user takeover is enforced for sensitive authentication boundaries;
- prompt-injection tests prove untrusted content cannot expand authority;
- evidence/observations are bounded and policy compliant;
- confidential/public trust-zone invariants remain intact;
- exact-head unit/integration/security/governance verification passes.

## 3. Work packages

### CU-000 — Architecture and research baseline

Status: `VERIFIED_PASS` when the three canonical documents exist on the development branch and their references/constraints are reviewed against the live repository baseline.

Deliverables:

- `docs/COMPUTER_USE_SYSTEM_DESIGN.md`
- `docs/COMPUTER_USE_DEPLOYMENT_GUIDE.md`
- `docs/COMPUTER_USE_TASK_LIST.md`

Acceptance:

- history does not incorrectly claim OpenClaw predates Claude/OpenAI computer use;
- design references existing WorkSpace authority/evidence primitives;
- deployment plan preserves Core/Public/Egress/Auth separation;
- no version-suffixed canonical documentation family is created.

### CU-010 — Provider-neutral contracts

Status: `ACTIVE` after CU-000.

Write set:

- `src/three_agent/computer_use.py`
- focused tests for this module.

Implement:

- `ComputerActionRequest`;
- `ComputerObservation`;
- operation and surface vocabulary;
- deterministic canonical JSON/fingerprints;
- compact resource/reference validation;
- state-precondition hash;
- idempotency key validation;
- risk class enum/vocabulary.

Acceptance:

- malformed actions fail closed;
- raw URL/credential-like references are rejected where inappropriate;
- canonical serialization/fingerprint is deterministic;
- equivalent payloads produce stable fingerprints;
- unknown operations/surfaces fail validation.

### CU-020 — Deterministic route selector

Dependencies: CU-010.

Write set:

- canonical `computer_use.py` only unless measured complexity justifies a separately authoritative module.

Implement route preference:

```text
API > CLI > DOM > ACCESSIBILITY > VISION_POINTER
```

Acceptance:

- model/provider preference cannot override a safer available authorized route;
- unavailable routes are skipped deterministically;
- unsupported route set fails closed;
- route decision produces auditable reason codes.

### CU-030 — TaskContract tool vocabulary integration

Dependencies: CU-010.

Write set:

- `src/three_agent/task_contract.py`
- existing TaskContract tests.

Initial reviewed tool IDs:

```text
computer.screen.observe
computer.window.observe
computer.accessibility.observe
computer.accessibility.interact
browser.dom.observe
browser.navigate
browser.interact
computer.pointer.interact
computer.keyboard.interact
computer.clipboard.read
computer.clipboard.write
```

Acceptance:

- unknown tool validation remains strict;
- existing task contracts remain backward compatible;
- no computer-use tool appears implicitly in default task authority;
- secret/confidential network restrictions remain intact.

### CU-040 — CapabilityAuthority integration

Dependencies: CU-030.

Write set:

- `src/three_agent/capability_authority.py`
- focused authority tests.

Implement:

- effect mappings for computer-use tools;
- resource-kind/ref policies;
- exact/narrow browser-profile, application/window, and device resource forms;
- fail-closed network/resource rules.

Acceptance:

- action cannot exceed TaskContract tool scope;
- effect mismatch is denied;
- resource mismatch is denied;
- action cannot convert public browser authority into confidential-core egress;
- all tool/effect vocabulary consistency guards pass.

### CU-050 — Computer-use policy decision layer

Dependencies: CU-010, CU-040.

Implement deterministic decision outcomes:

```text
ALLOW_AUTOMATIC
REQUIRE_APPROVAL
DENY
```

Acceptance:

- R0 observation can be automatic only under explicit task authority;
- R2 state changes require approval by default;
- R3 privileged/sensitive operations deny by default absent separately reviewed policy;
- model confidence/text never changes the decision class;
- policy outputs are reason-coded and fingerprinted.

### CU-060 — Approval contract

Dependencies: CU-050, existing WorkSpace auth/session model.

Implement:

- action-bound approval request;
- one-shot/session scopes;
- expiry;
- action-count bound;
- user/session identity binding;
- stale-action invalidation.

Acceptance:

- approval cannot grant a tool absent from TaskContract;
- approval for action A cannot authorize action B;
- expired/closed/cancelled approval fails closed;
- page/tool/model text cannot synthesize a valid approval.

### CU-070 — Single-writer integration

Dependencies: CU-060.

Use existing `RuntimeWriterLease` rather than creating a computer-use-specific competing writer authority.

Acceptance:

- mutating action requires current writer generation;
- stale writer is rejected;
- takeover/recovery invalidates previous action refs;
- uncertain side-effect retry checks postcondition/idempotency before re-execution.

### CU-080 — Observation/evidence integration

Dependencies: CU-010.

Use existing `ExecutionObservation` and evidence binding.

Implement:

- normalized structured observation;
- bounded screenshot reference/hash;
- pre/post-state hashes;
- action result/error class;
- executor/cost metadata.

Acceptance:

- raw outputs respect existing size/logging limits;
- successful execution cannot omit declared required evidence;
- evidence cannot exceed declared execution node authority/budget.

### CU-090 — Fake executor and deterministic test harness

Dependencies: CU-010, CU-020, CU-050.

Implement a non-OS fake executor for CI.

Acceptance:

- records only admitted normalized actions;
- can simulate stale state, failure, partial result, and postcondition mismatch;
- provides deterministic fixtures for all policy/routing tests.

### CU-100 — Isolated browser observation adapter

Dependencies: CU-080, CU-090.

Implement:

- dedicated browser profile;
- tab/window metadata;
- DOM/accessibility snapshots;
- on-demand screenshot;
- target/state refs;
- no state-changing action in first slice.

Acceptance:

- browser profile is separate from personal profile;
- observation is bounded;
- control endpoint is local/private;
- confidential storage is inaccessible to public browser identity;
- stale refs are detected.

### CU-110 — Governed browser interaction

Dependencies: CU-060, CU-070, CU-100.

Implement:

- navigate;
- click;
- type;
- select;
- scroll;
- form interaction;
- download quarantine.

Acceptance:

- side-effect action requires correct approval;
- navigation/egress target is independently policy checked;
- page prompt injection cannot alter tool/approval authority;
- stale target ref rejects before interaction;
- postcondition verification occurs after action.

### CU-120 — OpenAI provider bridge

Dependencies: CU-010, CU-100/110 according to enabled action subset.

Implement translation between OpenAI computer-use action/output form and canonical WorkSpace contracts.

Acceptance:

- provider action cannot bypass WorkSpace policy;
- provider-specific fields remain outside core authority;
- screenshots/outputs are returned only after WorkSpace retention/redaction rules;
- provider errors map to bounded internal failure classes.

### CU-130 — Anthropic provider bridge

Dependencies: same as CU-120.

Implement translation between Anthropic computer `tool_use`/`tool_result` and canonical WorkSpace contracts.

Acceptance mirrors CU-120.

### CU-140 — Local-model bridge

Dependencies: CU-010.

Implement strict JSON/schema translation for local multimodal models.

Acceptance:

- local models receive no implicit additional trust;
- malformed output fails closed;
- model may propose, never authorize.

### CU-150 — Frontend approval UX

Dependencies: CU-060 backend contracts stable.

Implement:

- approval card/dialog;
- resource/action/risk explanation;
- approve once;
- approved session scope only when policy supports it;
- deny;
- timeout/stale display;
- user-takeover entry/exit state.

Acceptance:

- ambiguous dismissal means deny/no approval;
- approval fingerprint matches backend action;
- stale approval cannot execute;
- UI does not expose raw credentials in logs/state.

### CU-160 — Windows observation adapter

Dependencies: CU-080.

Implement:

- active window/process metadata;
- Windows UI Automation tree;
- bounded screenshots;
- reuse existing read-only PowerShell diagnostics where applicable.

Acceptance:

- standard-user operation;
- no Admin requirement for read-only baseline;
- structured APIs preferred over pixel vision;
- secure/password UI fields are not scraped into normal evidence.

### CU-170 — Windows interaction adapter

Status: `VERIFIED_PASS` at implementation head `f572c2a59859cde7edc77825c88043807f409553`.

Dependencies: CU-060, CU-070, CU-160.

Implement:

- UI Automation invoke/value/select first;
- pointer/keyboard injection only as fallback;
- per-app/session target validation.

Acceptance:

- input cannot occur while user takeover is active;
- stale focus/window target fails closed;
- state-changing action uses approval/writer fence;
- no arbitrary elevated shell.

Executed evidence:

- `computer-use-windows-interaction-ci` run `34489074180` passed on Python 3.11 and 3.12;
- live WPF controls verified real `ValuePattern.SetValue` and `InvokePattern.Invoke` behavior;
- exact-head `canonical-module-ci` `34489074139`, `internet-egress-security-ci` `34489074195`, `windows-deploy-ci` `34489074099`, `installer-ci` `34489074093`, and `harness-ci` `34489074371` all passed;
- pointer/keyboard remain explicit fallback and CU-210 privileged broker is not used.

### CU-180 — Linux observation/interaction adapter

Status: `ACTIVE` after CU-170 verification.

Dependencies: browser path stable, CU-060/CU-070.

Implement:

- native CLI/system APIs;
- AT-SPI where supported;
- Wayland portal/compositor-supported mechanisms where required;
- controlled X11 fallback only in approved deployments.

Acceptance:

- does not instruct deployment to disable Wayland security merely to automate;
- same authority/approval semantics as Windows.

### CU-190 — macOS observation/interaction adapter

Dependencies: same governance layers.

Implement:

- Accessibility API;
- Screen Recording permission path;
- user-takeover boundaries;
- no broad Full Disk Access requirement by default.

Acceptance mirrors other OS adapters.

### CU-200 — Privileged broker threat model

This is a design/security gate, not automatic implementation approval.

Deliverable:

- concrete privileged use cases;
- fixed RPC vocabulary;
- OS service identity;
- authentication/replay defense;
- approval binding;
- abuse cases and rollback.

Acceptance:

- demonstrate that API/standard-user alternatives are insufficient;
- security review explicitly approves implementation.

### CU-210 — Privileged broker implementation

Blocked until CU-200 `VERIFIED_PASS` and explicit policy approval.

No arbitrary command execution API is allowed.

### CU-220 — Prompt-injection red-team suite

Dependencies: provider/browser adapters.

Implement adversarial fixtures for pages, files, images, accessibility text, and downloaded content.

Acceptance:

- untrusted content cannot expand tools/network/write authority;
- model proposals remain untrusted until deterministic admission;
- suspicious content cannot simulate approval;
- stale/replayed actions remain blocked.

### CU-230 — Replay/stale/concurrency suite

Dependencies: CU-070.

Acceptance:

- same action replay blocked;
- stale state/target blocked;
- writer generation change invalidates prior action;
- takeover invalidates old action refs;
- uncertain side effect does not blindly retry.

### CU-240 — Privacy/evidence suite

Dependencies: CU-080 and platform adapters.

Acceptance:

- screenshot/tool outputs bounded;
- secure UI content not retained as normal evidence;
- secret/restricted logging policy remains deny where configured;
- evidence remains task/run/action bound.

### CU-250 — Packaging and deployment

Dependencies: supported platform adapters verified.

Implement:

- feature flags default off where actuator risk exists;
- private/local control binding;
- deployment profile documentation;
- upgrade/rollback path.

Acceptance:

- clean installation path;
- safe defaults;
- no public unauthenticated control surface.

### CU-260 — Remote node control

Status: `OPTIONAL_INACTIVE`.

Activation condition: remote node control becomes a concrete product requirement.

### CU-270 — Benchmark/evaluation

Implement measured:

- action success rate;
- stale-target rejection rate;
- approval latency;
- observation/action latency;
- token/tool overhead;
- recovery behavior.

### CU-280 — Final security/release gate

Acceptance:

- all active packages verified;
- exact-head mandatory CI green;
- threat model reviewed;
- deployment defaults fail closed;
- release evidence complete.
