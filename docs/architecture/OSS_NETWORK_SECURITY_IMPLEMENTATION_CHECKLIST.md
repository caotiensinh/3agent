# WorkSpace OSS Network/Security Integration Checklist

Status: implementation tracker  
Design source: `docs/architecture/OSS_NETWORK_SECURITY_DESIGN_BLUEPRINT.md`  
Implementation branch: `feature/security-monitoring-phase1`

## Delivery rules

- Preserve local-first, evidence-bounded and advisory-by-default behavior.
- Preserve `approved_inventory_only`; a rule or discovery result never grants network authority.
- Reuse existing WorkSpace contracts, policy, storage, deterministic correlation and harness primitives before adding new ones.
- Every implementation slice must have deterministic tests before it is committed.
- Commit a passing slice immediately; do not batch unrelated passing slices.
- Failed or partially tested code stays uncommitted.
- Report implementation completion and remaining percentage at the end of every working session.
- Do not merge to `main` until the implementation/test/security gates are explicitly ready.

## Weighted implementation roadmap

| Phase | Scope | Weight | Acceptance gate |
|---|---|---:|---|
| 1a | Source checkpoint contracts | 5% | strict validation, canonical serialization/fingerprint, no raw locator/secret, targeted tests pass |
| 1b | Compatibility/discontinuity evaluator | 5% | explicit START/RESUME/RESET/INVALID outcomes, rotation/truncation tests pass |
| 1c | Deterministic replay | 7% | identical bounded input + checkpoint produces byte-identical replay output/fingerprint |
| 1d | Phase-1 integration | 3% | existing log pipeline integration, public exports/docs, security-monitoring regression tests pass |
| 2 | Health state + hysteresis | 15% | deterministic state machine, no single-sample alert promotion, transition evidence retained |
| 3 | Temporal behavior engine | 20% | bounded temporal windows/buckets, deterministic scenario evaluation, replay fixtures pass |
| 4 | Rule compiler + work clustering | 20% | validate/compile before execution, capability requirements externalized, duplicate work eliminated |
| 5 | Discovery candidates | 10% | passive/untrusted candidates separated from approved inventory; no authority escalation |
| 6 | Flow -> process attribution | 10% | typed identity refs, bounded adapters, deterministic correlation into existing graph |
| 7 | Optional edge agent | 5% | read-only bounded contract, authenticated evidence transport, local-first fail-closed behavior |
|  | **Total** | **100%** | |

## Phase 1 — checkpoint and replay

### 1a Source checkpoint contracts — 5%

- [ ] Define an opaque `SourceDescriptor` that stores stable identifiers/fingerprints, never credentials or raw URLs.
- [ ] Define `SourceCheckpoint` with an explicit byte cursor and observed extent.
- [ ] Reject negative/non-integer cursor values and cursor positions beyond observed extent.
- [ ] Require timezone-aware UTC checkpoint timestamps and canonicalize equivalent UTC representations.
- [ ] Reject unknown/missing serialized fields and unsupported schema versions.
- [ ] Provide deterministic canonical JSON and SHA-256 fingerprinting.
- [ ] Add targeted unit tests and run them locally.
- [ ] Commit immediately after PASS.

### 1b Compatibility/discontinuity evaluator — 5%

- [ ] No prior checkpoint -> `START`.
- [ ] Same identity + monotonic extent + valid cursor -> `RESUME`.
- [ ] Source identity changed -> explicit rotation/reset outcome.
- [ ] Source extent shrank -> explicit truncation/reset outcome.
- [ ] Cursor beyond current extent -> fail closed as invalid/discontinuous.
- [ ] Never silently resume ambiguous state.
- [ ] Add deterministic decision receipt/fingerprint.
- [ ] Targeted tests PASS -> immediate commit.

### 1c Deterministic replay — 7%

- [ ] Reuse existing deterministic retrieval/harness conventions.
- [ ] Replay only bounded, already-authorized local evidence; no live network action.
- [ ] Stable ordering is explicit, not filesystem/thread dependent.
- [ ] Same inputs produce byte-identical output and fingerprint.
- [ ] Input/checkpoint discontinuity is surfaced, not hidden.
- [ ] Targeted replay fixtures PASS -> immediate commit.

### 1d Phase-1 integration — 3%

- [ ] Integrate with the existing log pipeline rather than creating a parallel ingestion subsystem.
- [ ] Add public package exports only after contracts are stable.
- [ ] Preserve existing spool, retention, evidence receipt and freshness boundaries.
- [ ] Run targeted Phase-1 tests plus relevant existing security-monitoring regressions.
- [ ] Update architecture notes with exact behavior/evidence.
- [ ] PASS -> immediate commit.

## Phase 2 — health state + hysteresis — 15%

- [ ] Define deterministic UNKNOWN/HEALTHY/DEGRADED/UNREACHABLE/MAINTENANCE/DATA_GAP semantics.
- [ ] Separate observations from interpreted health state.
- [ ] Add bounded failure/recovery hysteresis.
- [ ] Keep thresholds in policy/config, never model output.
- [ ] Preserve evidence IDs for every transition.
- [ ] Add replay/state-transition fixtures.

## Phase 3 — temporal behavior engine — 20%

- [ ] Reuse current behavior store/windows where possible.
- [ ] Add bounded temporal buckets/scenarios.
- [ ] Separate parsing, scenario evaluation, finding generation and response.
- [ ] Require deterministic time/window semantics.
- [ ] Prevent temporal rules from granting capture/scan/remediation authority.
- [ ] Add positive, negative, out-of-window and replay fixtures.

## Phase 4 — rule compiler + work clustering — 20%

- [ ] Rule source -> parse -> validate -> compile -> capability requirements.
- [ ] Authorization remains in existing policy/inventory engine.
- [ ] Matchers/extractors are deterministic and side-effect free.
- [ ] Cluster equivalent authorized collection work before increasing concurrency.
- [ ] Version/fingerprint every compiled rule plan.
- [ ] Reject malformed/unknown capabilities fail-closed.

## Phase 5 — discovery candidates — 10%

- [ ] Candidate != inventory asset.
- [ ] Store candidate provenance/confidence/last-seen without auto-enrollment.
- [ ] Require explicit approval path before any active capability becomes available.
- [ ] Deduplicate candidates deterministically.
- [ ] Test that discovery can never bypass `approved_inventory_only`.

## Phase 6 — flow to process attribution — 10%

- [ ] Reuse typed entity-reference model.
- [ ] Keep packet/flow collection metadata-only unless separate PCAP approval exists.
- [ ] Bound OS-specific adapters and normalize outputs.
- [ ] Feed existing DNS -> FLOW -> AUTH -> PROCESS/IDS graph rather than creating a competing graph.
- [ ] Hash sensitive identity material as typed references.

## Phase 7 — optional edge agent — 5%

- [ ] Edge agent is optional; core monitoring remains functional without it.
- [ ] Read-only bounded collector contract.
- [ ] Authenticated/tamper-evident evidence envelope.
- [ ] No cloud dependency for normal confidential operation.
- [ ] Offline/backpressure behavior is explicit and bounded.
- [ ] Agent cannot self-authorize new targets or remediation.

## Session measurement

Implementation percentage is calculated only from the weighted implementation roadmap above. Research/architecture is tracked separately and is already complete.

At the end of each session report:

1. architecture/research completion;
2. implementation completion and remaining percentage;
3. current phase completion;
4. exact commits created in the session;
5. tests executed and their result;
6. any failed/uncommitted work and its blocker.
