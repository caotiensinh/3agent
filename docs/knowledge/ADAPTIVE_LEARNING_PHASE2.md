# Adaptive Learning Phase 2 — Offline Domain Evaluation

Status: IMPLEMENTED OFFLINE/SYNTHETIC VALIDATION / NO BACKGROUND LEARNER

Phase 2 adds a fixed deterministic evaluation lane for adaptive-learning candidates before any LLM reflection worker exists.

## Components

- `src/three_agent/adaptive_learning_evaluation.py`
  - strict learning-evaluation corpus parser;
  - deterministic replay engine;
  - Network/Security/Analyst domain safety checks;
  - metadata-only replay output.
- `evaluation/adaptive_learning_offline_v1.json`
  - fixed synthetic fixtures for safe and unsafe learning proposals.
- `tests/test_adaptive_learning_evaluation.py`
  - corpus strictness, complete replay, metadata-only output and fail-closed regression tests.

## v1 fixture coverage

### Network

- passive/read-only link-flap analysis — allowed;
- active scan (`nmap`/equivalent pattern) — rejected;
- load testing (`iperf`/speedtest pattern) — rejected;
- switch/router configuration mutation — rejected;
- confidential source -> public candidate downgrade — rejected.

### Security

- evidence-correlation triage pattern — allowed;
- firewall/block mutation — rejected;
- account mutation — rejected;
- global alert suppression — rejected.

### Analyst

- observation + hypothesis + uncertainty boundary — allowed;
- missing hypothesis separation — rejected;
- missing uncertainty/missing-evidence boundary — rejected.

### Cross-cutting

- unresolved experience -> procedural skill — rejected;
- prompt/policy-injection persistence attempt — rejected.

## Important boundary

The content-pattern validators are defense-in-depth evaluation guards, not capability security. A candidate that passes them still gains **zero** network/shell/remediation authority. WorkSpace deterministic capability policy remains the enforcement boundary.

The replay result contains only:

```text
case_id
passed
accepted
reason_codes
```

It does not echo candidate content or raw evidence into replay artifacts.

## Next phase

Phase 3 should implement a local append-only candidate/validation ledger plus rollback-safe knowledge-store staging. It should still use deterministic/synthetic producers first. LLM background reflection should come only after storage, authenticated reviewer identity, and rollback are proven.
