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

### CU-180 — Linux observation/interaction adapter

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

Dependencies: CU-100 before browser release; expands continuously.

Fixtures:

- hostile web page text;
- hidden DOM instructions;
- accessibility-label injection;
- image/screenshot instruction injection;
- downloaded document injection;
- terminal output injection;
- fake approval text;
- exfiltration request;
- request to change tool/network scope.

Acceptance:

- none can expand authority;
- state changes still require deterministic admission/approval;
- confidential data is not moved into public lane.

### CU-230 — Replay, stale-state, and concurrency tests

Dependencies: CU-070.

Acceptance:

- replayed action id rejected;
- previous writer generation rejected;
- old DOM/accessibility ref rejected after navigation;
- coordinate action rejected after state hash change;
- two simultaneous writers cannot mutate one session.

### CU-240 — Privacy and evidence retention tests

Dependencies: CU-080.

Acceptance:

- restricted/secret raw logging policy is honored;
- credentials are absent from retained evidence;
- continuous video is not silently recorded;
- screenshot evidence is bounded and optional according to task policy.

### CU-250 — Deployment packaging

Dependencies: platform adapters selected for release.

Deliver:

- service/companion packaging;
- least-privilege OS identity setup;
- browser profile setup;
- health/readiness checks;
- disable/rollback procedure.

### CU-260 — Enterprise fleet/node identity

Optional until remote node control is a concrete product requirement.

Acceptance:

- authenticated node enrollment;
- encrypted transport;
- node/profile allowlist;
- no public unauthenticated control endpoint;
- revocation/recovery tested.

### CU-270 — Performance and reliability benchmark

Measure per verified task, not clicks/second.

Metrics:

- task success rate;
- actions per verified task;
- model calls per verified task;
- stale-ref recovery rate;
- approval rate;
- false/unsafe action admission count;
- wall time;
- screenshot/token overhead;
- structured-route percentage vs vision fallback percentage.

Target behavior:

- structured paths dominate whenever available;
- visual fallback is bounded;
- adding computer use does not materially degrade unrelated WorkSpace tasks.

### CU-280 — Final security/release gate

Required checks:

- repository governance validator;
- canonical-module guard;
- focused unit tests;
- integration tests;
- prompt-injection red-team suite;
- stale/replay/concurrency suite;
- trust-zone/egress tests;
- platform smoke tests for supported release targets;
- exact-head CI evidence.

## 4. Initial implementation slice for this branch

This branch starts with the smallest coherent governed core:

```text
CU-000  documentation
CU-010  provider-neutral contracts
CU-020  deterministic route selector
CU-090  focused deterministic tests for contracts/router
```

If the current repository tests reveal that CU-010 requires immediate vocabulary integration to remain coherent, CU-030/CU-040 may be brought into the same acceptance boundary; otherwise they remain the next slice.

The initial branch must not yet control a real user's mouse/keyboard or attach to a personal signed-in browser.

## 5. Parallel lane decomposition

For substantial sessions, apply the canonical repository lane policy. A useful 20-lane decomposition once implementation broadens is:

| Lane | Goal | Primary write set |
|---|---|---|
| L01 | core contracts | `computer_use.py` |
| L02 | TaskContract vocabulary | `task_contract.py` |
| L03 | CapabilityAuthority mapping | `capability_authority.py` |
| L04 | approval contract | canonical auth/approval module |
| L05 | writer fence integration | existing runtime writer path |
| L06 | execution observation binding | existing observation path |
| L07 | fake executor | test/support canonical location |
| L08 | browser observation | browser adapter |
| L09 | browser interaction | browser adapter, same writer ownership coordinated with L08 |
| L10 | OpenAI bridge | provider bridge authority |
| L11 | Anthropic bridge | provider bridge authority |
| L12 | local-model bridge | provider bridge authority |
| L13 | frontend approval | frontend canonical files |
| L14 | Windows observation | Windows adapter |
| L15 | Windows interaction | Windows adapter coordinated single writer |
| L16 | Linux adapter | Linux adapter |
| L17 | macOS adapter | macOS adapter |
| L18 | injection/replay security tests | security tests |
| L19 | deployment/health | deployment canonical files |
| L20 | release/evidence convergence | verification only; no competing production authority |

Do not execute overlapping write lanes simultaneously. If a canonical file is shared, it has one writer owner and other lanes produce analysis/evidence only until ownership is handed over.

## 6. Progress accounting baseline

At program creation, the complete production program is intentionally not assigned an artificial high percentage. Verified progress is based on mandatory acceptance work actually executed.

For the current branch slice:

- CU-000 counts only after all three documents are present and re-read from the branch.
- CU-010/CU-020/CU-090 count only after code exists and executed tests pass.
- planning alone gives zero implementation completion credit.

Checkpoint reports must follow the repository canonical execution-governance metrics rather than subjective estimates.
