# WorkSpace / 3agent — Development Handoff — 2026-09-02

## Repository

- Repository: `caotiensinh/3agent`
- Branch: `main`
- Verified implementation head before this handoff document: `6ce2def620613e416ad2c87f2aeb3a507767fe59`
- Product name: **WorkSpace**
- Positioning: local-first enterprise AI workspace for internal company work, with strict policy boundaries for any Internet or privileged capability.

## Non-negotiable development policy

1. Work directly from current GitHub state; never trust stale SHAs without re-checking.
2. Implement in small checkpoints and commit every completed unit.
3. A feature is not PASS until its relevant tests and exact-head CI are green.
4. Keep these acceptance levels separate:
   - code/static/unit test pass;
   - GitHub exact-head CI pass;
   - physical AI-server acceptance pass;
   - full end-to-end workflow acceptance pass.
5. Security-monitoring features remain **read-only / advisory by default**. No autonomous shell, firewall modification, active scan, remediation, credential use, or unrestricted packet capture.
6. Sensitive identities and evidence references must remain bounded, auditable, and policy-controlled.
7. Fail closed on malformed, ambiguous, unauthorized, oversized, replaced, or mutated evidence.
8. Preserve enterprise engineering standards: least privilege, deterministic validation, bounded resources, audit evidence, cross-platform tests, rollback where applicable.

## Existing WorkSpace architecture baseline

WorkSpace currently contains three main local logical agents:

1. Research Agent — `調査・情報収集AI`
2. Presentation Agent — `資料作成・発表AI`
3. Daily Report Agent — `日報作成AI`

Important architecture already implemented before the current security-monitoring work:

- local Ollama inference;
- model-on-demand routing with one loaded model at a time;
- research evidence integrity gates;
- Agent 2 handoff validation;
- daily-report reconstruction from task/activity records;
- LAN chat gateway and optional Telegram gateway;
- capability/policy controls and auditable artifacts;
- workflow fail-closed behavior;
- installer and deployment CI for Linux and Windows.

## Security / Network Monitoring development completed in the latest sequence

### v0.6 — audited analyst workflow

Completed and committed:

- hash-chained workflow audit journal;
- audited analyst workflow coordinator;
- tests covering the audited analyst workflow.

Relevant commits:

- `c65996a712c4cc11c7221cb78e58eacbd24f498a` — `feat(security): add hash-chained workflow audit journal v0.6`
- `565c3a80f7272a1664d6723938deacf9ba3c32df` — `feat(security): add audited analyst workflow coordinator v0.6`
- `5ecb893d2938df88aa86cebce9b0613ab578025e` — `test(security): cover audited analyst workflow v0.6`

### v0.7 — bounded trusted PCAP evidence

Completed and committed:

- bounded trusted PCAP evidence reader;
- task-authorized PCAP invocation profile;
- explicit tests for task-authorized PCAP evidence reads;
- corrected PCAP binding coverage import;
- SNMP read-only pilot dependency installation;
- cross-platform PCAP CI on Ubuntu/Windows and Python 3.11/3.12.

Relevant commits:

- `07bbb8a4ff70c552e3e46660f512e047007b3bbc` — `feat(security): add bounded trusted PCAP evidence reader v0.7`
- `d92ab1de92e5991c87476dbf1a0c79ce3fb1d34e` — `feat(security): add task-authorized PCAP invocation profile v0.7`
- `1378fb82b5ba86eff9047fe887c6aaff5963f028` — `fix(security): correct PCAP binding coverage import`
- `360914023a5e02d45a540f419fbfa1f005f4c47e` — `test(security): cover task-authorized PCAP evidence read v0.7`
- `a1f810617963b4e4a927a8af4391d16eca8bd972` — `test(security): fix bounded PCAP fixture`
- `50ece5f104122b6889c0acda2eb328e401d1ded3` — `fix(security): install SNMP extra for readonly pilot`

### v0.7.1 — PCAP hardening

Latest implementation commit:

- `6ce2def620613e416ad2c87f2aeb3a507767fe59` — `fix(security): harden bounded PCAP snapshot reads v0.7.1`

Hardening added:

- opened file descriptor must still resolve to a regular file;
- stable identity/size check detects replacement before read;
- post-read file snapshot detects same-file mutation during bounded read;
- `O_NOFOLLOW` where supported;
- `O_BINARY` on Windows where supported;
- bounded chunked reads without quadratic byte concatenation;
- memoryview-based parsing;
- explicit upper bound on original PCAP packet length;
- metadata mode and capture mode remain bounded;
- new hardening tests;
- new `security-pcap-cross-platform` workflow.

## Verified CI evidence at implementation head `6ce2def...`

All observed workflow runs for the exact implementation head completed successfully:

- `installer-ci` — run `33596350877` — **SUCCESS**
- `harness-ci` — run `33596350887` — **SUCCESS**
- `security-pcap-cross-platform` — run `33596350858` — **SUCCESS**
- `portable-deploy-ci` — run `33596350993` — **SUCCESS**
- `windows-deploy-ci` — run `33596350936` — **SUCCESS**

Therefore the implementation through PCAP v0.7.1 is **code/CI PASS** at `6ce2def...`.

Do **not** claim physical deployment PASS from these CI results alone.

## Current security boundary

The security/network analyst capability must continue to be developed as a controlled enterprise analysis plane, not as an offensive toolkit.

Allowed direction:

- read-only SNMP collection;
- approved log ingestion;
- bounded task-authorized PCAP evidence reads;
- DNS / flow / authentication / process correlation;
- asset, IP, user, service correlation using typed references;
- inventory validation;
- bounded time windows, event counts, entity counts, graph edges, file sizes, packet counts;
- anomaly scoring and explanation;
- advisory maintenance / upgrade recommendations;
- auditable evidence lineage;
- internal AI analysis through a future controlled gateway.

Still forbidden by default:

- active exploitation;
- arbitrary shell execution;
- autonomous firewall changes;
- credential harvesting;
- unrestricted packet capture;
- unrestricted scanning;
- autonomous remediation;
- data exfiltration to cloud services.

## Immediate next development target

Continue from current `main` and build the next security-monitoring layer without weakening the v0.7.1 boundary.

Recommended next milestone: **v0.8 — normalized read-only evidence pipeline + analyst finding contract**.

Target scope:

1. Define one normalized evidence envelope for SNMP, logs, PCAP summaries, DNS/flow/auth/process correlation outputs.
2. Enforce common fields:
   - evidence ID;
   - source type;
   - asset reference;
   - collection timestamp/window;
   - integrity/hash metadata;
   - authorization/task reference;
   - sensitivity classification;
   - confidence/quality fields;
   - bounded raw-reference pointer rather than uncontrolled raw payload embedding.
3. Add deterministic validation and size/count limits.
4. Add an `AnalystFinding` contract separating:
   - observed facts;
   - derived indicators;
   - hypotheses;
   - confidence;
   - supporting evidence IDs;
   - conflicting evidence IDs;
   - recommended human action;
   - prohibited automatic action.
5. Add fail-closed workflow behavior when evidence lineage is missing or invalid.
6. Add unit tests and cross-platform regression tests.
7. Commit each coherent slice.
8. Verify exact-head CI before declaring v0.8 PASS.

## Development workflow for the next chat

For every development step:

1. Read current `main` SHA and latest commits.
2. Inspect relevant source/tests/docs before editing.
3. Implement only one coherent checkpoint.
4. Add or update tests in the same checkpoint.
5. Run/verify relevant CI.
6. If CI fails, fetch exact job logs and fix the real error; do not guess.
7. Commit the fix.
8. Re-check exact-head CI.
9. Report:
   - exact SHA;
   - what changed;
   - tests/CI evidence;
   - PASS/NOT PASS;
   - next milestone;
   - completion % only when evidence supports an increase.

## Handoff acceptance statement

At the time this handoff was written:

- latest verified implementation head: `6ce2def620613e416ad2c87f2aeb3a507767fe59`;
- PCAP security hardening v0.7.1: **CODE/CI PASS**;
- all five observed exact-head workflows listed above: **SUCCESS**;
- physical server acceptance for this security-monitoring slice: **NOT CLAIMED**;
- next planned development milestone: **v0.8 normalized read-only evidence pipeline + analyst finding contract**.
