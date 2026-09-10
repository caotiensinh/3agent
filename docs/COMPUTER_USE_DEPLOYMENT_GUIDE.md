# WorkSpace Governed Computer Use — Deployment Guide

Status: Deployment baseline  
Canonical document: `docs/COMPUTER_USE_DEPLOYMENT_GUIDE.md`  
Last updated: 2026-09-10

## 1. Scope

This guide defines how to deploy the WorkSpace computer-use capability while preserving the existing local-first security zones, least-privilege OS identities, deterministic capability authority, and evidence requirements.

Computer use must be deployed incrementally. The safe default is read-only observation. Browser interaction, desktop input, and privileged operations are separate capability tiers and must not be enabled merely because the code exists.

## 2. Deployment profiles

### Profile A — Isolated browser sandbox

Recommended first deployment and CI target.

```text
WorkSpace coordinator
      |
      | local authenticated IPC
      v
browser worker
      |
      v
dedicated Chromium profile
```

Properties:

- separate browser user-data directory;
- no personal browser cookies by default;
- sync and password manager disabled;
- downloads written to quarantine;
- browser worker runs unprivileged;
- network access follows the existing public-lane/egress policy;
- suitable for DOM/accessibility/screenshot observation and governed browser actions.

### Profile B — Local workstation companion

Used when WorkSpace must observe or interact with native applications.

```text
WorkSpace Core / coordinator
       |
       | loopback/private authenticated IPC
       v
unprivileged device agent
       |
       +--> OS accessibility APIs
       +--> screen observation
       +--> bounded native commands
       +--> pointer/keyboard fallback
```

Properties:

- agent runs as the signed-in unprivileged user;
- no automatic Administrator/root elevation;
- control listener binds to loopback by default;
- remote deployments require authenticated private transport and device identity;
- UI mutation remains disabled until approval/writer-fence support is verified.

### Profile C — Enterprise coordinator + device nodes

Used for managed fleets.

```text
                 WorkSpace coordinator
                         |
              authenticated private transport
         +---------------+----------------+
         |               |                |
   device-node-1    device-node-2    browser-node
      Windows          Linux           isolated
```

Requirements:

- per-node identity and explicit enrollment;
- node allowlist;
- per-session resource scopes;
- no unauthenticated public control endpoint;
- node compromise must not expose confidential WorkSpace storage by default;
- remote browser/device control is treated as operator-level access to the authorized surface.

## 3. Trust-zone placement

### 3.1 Confidential Core

Do not add public Internet connectivity to `workspace-core` for computer use.

Core may:

- compile the task and execution plan;
- perform local policy decisions;
- coordinate local device actions within approved resources;
- consume bounded observations.

Core must not:

- use a browser worker as an implicit egress tunnel;
- forward confidential prompt/task/file data to a public browser lane;
- share confidential data-store permissions with browser/egress identities.

### 3.2 Public browser worker

Place public web automation in the existing public/egress trust path.

The worker should have:

- its own OS identity;
- its own data root;
- no read permission on confidential WorkSpace storage;
- outbound access only through the approved egress path;
- a dedicated browser profile and downloads directory.

### 3.3 Device agent

The device agent is an actuator. It should receive small normalized action requests, not the full confidential prompt unless a separate design explicitly requires that data and policy permits it.

## 4. Recommended initial filesystem layout

Illustrative Linux layout:

```text
/var/lib/workspace/                    # confidential core; existing policy
/var/lib/workspace-public/             # public lane; existing policy
/var/lib/workspace-computer-use/
    sessions/                           # bounded non-secret runtime metadata
    browser/
        profiles/
            isolated/
        downloads-quarantine/
    evidence/                           # only policy-authorized retained evidence
/run/workspace/
    computer-use.sock                   # local authenticated IPC
```

Never place browser profiles, downloads, or raw screenshots in the confidential task store by convenience. Their admission/retention must follow explicit evidence policy.

## 5. OS identity model

### Linux

Recommended identities:

```text
workspace-core
workspace-public
workspace-egress
workspace-auth
workspace-device       # new unprivileged local actuator if required
```

Do not add `workspace-core` and `workspace-device` to broad shared groups simply to simplify access. Expose only the specific local IPC/resources required by the approved design.

### Windows

Recommended model:

- normal WorkSpace/device-agent process runs as a standard user;
- no `runas Administrator` default;
- UI Automation runs in the user session;
- bounded PowerShell commands run with that user's token;
- a future privileged broker, if approved, is a separate service with a fixed RPC allowlist.

### macOS

The user may need to grant OS-level Accessibility and Screen Recording permissions to the device-agent application. Grant only to the signed WorkSpace companion binary. Do not request Full Disk Access unless a separately reviewed requirement proves it necessary.

## 6. Browser setup

### 6.1 Dedicated profile

The default profile must be agent-only.

Recommended controls:

- dedicated `user-data-dir`;
- browser sync disabled;
- password manager disabled;
- no personal extension set;
- downloads isolated;
- developer protocol endpoint bound only to loopback/private node boundary;
- short-lived session state where practical.

### 6.2 Browser control protocol

Preferred browser driver:

1. Playwright for structured page interaction and controlled browser lifecycle;
2. CDP where lower-level browser state is needed;
3. screenshot/pointer fallback only for surfaces that cannot be addressed structurally.

Do not expose raw CDP on a public/LAN interface.

### 6.3 Signed-in user browser

This mode is optional and higher risk.

Enable only when:

- user explicitly requests use of existing login state;
- the target browser profile/session is part of the approved resource scope;
- the user is informed that the agent will have access equivalent to the visible signed-in browser surface;
- password manager and unrelated sensitive tabs are outside scope where possible.

For unattended enterprise operation, prefer service-specific API credentials in a narrow connector over attaching a personal daily browser.

## 7. Configuration baseline

The exact configuration schema should be introduced only with implementation tests. The following illustrates intended semantics, not a second normative policy source:

```yaml
computer_use:
  enabled: false
  observation:
    screen: false
    accessibility: false
    browser_dom: false
  interaction:
    browser: false
    desktop_pointer: false
    desktop_keyboard: false
  browser:
    profile: isolated
    downloads: quarantine
  approvals:
    state_change: required
    privileged: deny
  remote_control:
    bind: loopback
```

Production numerical limits remain sourced from existing canonical WorkSpace governance/configuration, not this guide.

## 8. Capability rollout

### Stage 0 — feature absent/default deny

Expected production default until code and tests land:

```text
computer_use.enabled = false
```

### Stage 1 — read-only browser observation

Enable only:

- browser metadata;
- DOM/accessibility snapshot;
- screenshot on explicit need;
- no click/type/navigation that can leave the pre-approved origin policy.

Acceptance:

- bounded observation;
- no confidential-core egress regression;
- prompt injection cannot change policy;
- observations bind into execution evidence.

### Stage 2 — governed browser interaction

Add:

- navigation to policy-approved targets;
- click/type/select/scroll;
- stale-reference checks;
- approval for side-effect actions;
- download quarantine.

### Stage 3 — native desktop observation

Add:

- active window/application identity;
- accessibility tree;
- optional screenshot;
- bounded system read commands.

No native desktop mutation yet.

### Stage 4 — native desktop interaction

Add:

- pointer/keyboard fallback;
- user takeover;
- writer fencing;
- OS permission UX;
- per-application/resource scopes.

### Stage 5 — privileged operations

Not enabled by default. Requires a separate threat model and security review.

## 9. Approval UX deployment

The frontend must distinguish three outcomes:

```text
ALLOW_AUTOMATIC
REQUIRE_APPROVAL
DENY
```

Approval screen must show, at minimum:

- proposed action in user-understandable terms;
- target resource/application/site;
- expected change;
- risk class;
- whether network/session interruption is possible;
- scope of approval: once/session;
- expiration when applicable.

Approval choices should be explicit. Closing the dialog, timeout, stale state, logout, or session ownership change means no approval.

## 10. User-takeover deployment

Takeover requires an explicit state transition.

During takeover:

- WorkSpace stops synthetic keyboard/pointer injection;
- stale action refs are invalidated;
- screenshot retention may be suspended/redacted for the sensitive surface according to policy;
- the user enters credentials/MFA directly;
- returning control requires an explicit hand-back event;
- a fresh observation is mandatory before the agent acts again.

## 11. Windows implementation guidance

### Observation

Preferred sources:

- UI Automation tree;
- process/window metadata;
- PowerShell read-only cmdlets;
- bounded screenshots.

### Interaction

Preferred order:

1. application/native API;
2. PowerShell or documented command interface for deterministic actions;
3. UI Automation invoke/value/select patterns;
4. pointer/keyboard injection as fallback.

### Elevation

If a future action needs Administrator privileges:

- do not elevate the whole WorkSpace process;
- broker only a reviewed fixed operation;
- display the exact operation/target to the user;
- bind the approval to the action fingerprint;
- record result evidence;
- fail closed if broker identity or request integrity cannot be verified.

## 12. Linux implementation guidance

### X11

Synthetic input is technically easy but should be treated as high-impact because clients sharing the display may observe/inject events. Prefer accessibility/native APIs.

### Wayland

Wayland intentionally restricts arbitrary global input/screen access. Use compositor-supported portals/remote-desktop mechanisms where required. Do not weaken the desktop security model by instructing operators to disable Wayland security features merely to make automation convenient.

### Headless browser

For CI and public research, run Chromium headless or in a sandboxed display environment with a dedicated profile and network policy.

## 13. macOS implementation guidance

- request Accessibility only when native UI control is enabled;
- request Screen Recording only when screen observation is enabled;
- identify the signed application/binary clearly to the operator;
- use the Accessibility API before coordinate clicking;
- treat user approval prompts and secure text fields as manual/takeover boundaries.

## 14. Remote-node transport

If computer use is extended to remote nodes:

Required:

- mutually authenticated device/session identity;
- encrypted transport;
- replay protection;
- request/action idempotency key;
- node/resource allowlist;
- server and node clocks monitored sufficiently for expiry checks;
- explicit disconnect/revocation behavior.

Preferred network placement:

- private overlay/VPN or tightly controlled management network;
- no public control listener;
- no implicit trust from source IP alone.

## 15. Logs and evidence

Record bounded metadata such as:

```text
session_id
action_id
task_id
plan_fingerprint
writer_generation
action_fingerprint
policy decision + reason code
approval reference if applicable
executor class
pre-state hash
post-state hash
verification outcome
evidence refs
latency/tool-call cost
```

Avoid by default:

- raw passwords/tokens;
- full browser cookie state;
- complete clipboard history;
- continuous screen recording;
- unbounded DOM/page dumps;
- unnecessary raw confidential tool output.

## 16. Security hardening checklist

Before enabling interaction in any environment:

- [ ] dedicated browser profile exists;
- [ ] browser control endpoint is not publicly reachable;
- [ ] device worker is unprivileged;
- [ ] confidential Core network invariant remains intact;
- [ ] task tools are explicit/default-deny;
- [ ] resource scope validation exists;
- [ ] prompt-injection fixtures are tested;
- [ ] stale-state rejection is tested;
- [ ] side-effect approval is tested;
- [ ] single-writer fencing is tested;
- [ ] user takeover invalidates old refs;
- [ ] downloads are quarantined;
- [ ] screenshot/observation retention follows logging policy;
- [ ] timeouts and action budgets are enforced;
- [ ] all touched repository governance/security validators pass.

## 17. CI deployment

CI should not require control of a developer's physical desktop.

Use deterministic fixtures:

- local static test web application;
- synthetic DOM/accessibility trees;
- fixed screenshots for vision fallback parsing;
- fake executor recording admitted actions;
- replay/stale-state test cases;
- injected malicious page text;
- approval and writer-lease fixtures.

End-to-end physical desktop smoke tests, when eventually introduced, should run only on isolated dedicated runners and never on general-purpose signed-in employee machines.

## 18. Rollback

Computer use must be removable/disableable without breaking normal WorkSpace operation.

Emergency rollback order:

1. disable interaction capability exposure;
2. revoke active computer-use grants/sessions;
3. stop device/browser workers;
4. close/revoke browser control endpoints;
5. preserve minimal evidence required for incident investigation;
6. return WorkSpace to non-computer-use execution paths.

A deployment must not require database downgrade or destructive migration merely to disable computer use.

## 19. Operational health signals

Recommended health categories:

- control-plane ready/not-ready;
- browser/device worker identity verified;
- executor adapter available;
- active session count;
- stale-action rejection count;
- approval pending/expired count;
- policy denial count by reason;
- executor failures by class;
- postcondition verification failures;
- action budget exhaustion;
- unexpected egress attempts;
- evidence write failures.

Health endpoints must not leak raw page content, credentials, or confidential task data.

## 20. First deployment target

The first shippable deployment should be deliberately narrow:

```text
WorkSpace
+ provider-neutral computer-use contracts
+ deterministic risk/router logic
+ isolated browser observation
+ fake executor for tests
+ existing capability/evidence integration
- no unrestricted shell
- no personal browser attach by default
- no native pointer/keyboard control
- no privileged broker
```

Only after this slice passes exact-head tests should state-changing browser interaction be enabled.
