# WorkSpace Execution Governance — Living Guide

**Status:** mandatory operating guide, non-normative explanation  
**Canonical machine policy:** `config/workspace.execution-governance.json`  
**Scope:** every human, AI agent, sub-agent, automation and CI worker that changes, verifies or reports on WorkSpace

> This file is intentionally edited in place. Do not create `...V0_0_2.md`, `...FINAL.md`, or sibling policy copies. Git history records revisions. When this guide conflicts with the JSON policy, the JSON policy wins.

## 1. Core law

```text
understand
  -> decompose
  -> run independent lanes
  -> execute real work
  -> verify
  -> diagnose failure
  -> change strategy / decompose again
  -> verify again
  -> measure verified progress
  -> commit passed boundary
  -> exact-head report
```

An agent does not own the meaning of `DONE`. The acceptance gate owns it.

## 2. What counts as complete

The only successful terminal state is **`VERIFIED_PASS`**. A substantial session may claim it only when all conditions defined in the canonical policy are true, including:

- every required lane is `VERIFIED_PASS`;
- every mandatory acceptance criterion actually ran its verifier and passed;
- evidence exists for the criterion and verification check;
- goal, verified-completion and evidence coverage meet the canonical thresholds;
- no retryable/actionable failure remains;
- no canonical-policy drift/duplicate exists;
- repository mutations required by the session are committed;
- completion/remaining percentages are consistent with verified work.

Writing code, producing a plan, performing QA commentary, saying “looks good”, or reporting model confidence is **not** completion evidence.

## 3. What counts as failure

`FAILED_RETRYABLE` is not terminal. It means the solver must continue:

```text
FAILED_RETRYABLE -> DIAGNOSING -> REPLANNED -> ACTIVE -> VERIFYING
```

A session may stop unsuccessfully only as one of the canonical unsuccessful terminal states:

- **`BLOCKED_EXTERNAL`** — a genuinely external dependency is preventing progress; blocker, owner, next action and evidence are mandatory.
- **`HARD_FAILED`** — safe in-authority approaches are exhausted; the minimum strategy diversity and failure evidence from the canonical policy are mandatory.
- **`ABORTED_BY_OPERATOR`** — the operator explicitly stops the work; the abort evidence is mandatory.

None of these states may be reported as completion. Difficulty, elapsed time, context size, or “the task is too complex” are not sufficient stop reasons.

## 4. Parallel lane model

For substantial work, **use the lane window and limits from the canonical JSON**. This guide intentionally does not duplicate the current numerical minimum, target, or maximum. Do not create useless lanes merely to satisfy a number.

Every lane carries the same contract shape:

```text
lane_id
 goal
 required
 dependencies
 write_set
 functional_authority
 acceptance_criteria
 verification_checks
 evidence
 attempts
 status
```

Parallel safety rules:

- independent write sets may run concurrently;
- one shared/canonical write set has one writer owner at a time;
- other lanes may inspect/test the same target but must not race to mutate it;
- a blocked lane must not idle unrelated lanes;
- if fewer safe independent units exist than the canonical target, record the dependency limit with evidence.

Illustrative responsibility families for a cybersecurity/network/monitoring session include exact-head evidence, contract/schema acceptance, network implementation, security integration, telemetry, unit tests, regression/compatibility, negative-security paths, documentation/evidence, and release/convergence. Decompose or combine these only as allowed by the canonical policy and the actual dependency graph.

## 5. Acceptance contract

A required criterion should be machine-checkable whenever possible:

```yaml
id: AC-01
statement: observable condition that must be true
required: true
status: PASS
verifier: exact command/test/check that was executed
evidence:
  - exact artifact/log/status/commit reference
```

A lane cannot be `VERIFIED_PASS` when a required criterion has no verifier, no evidence, or a non-PASS status.

## 6. Adaptive solver: no idle failure

After repeated materially equivalent failure, repeating the same strategy is forbidden. Move to a different safe strategy family: decomposition, dependency isolation, deterministic verification, alternate implementation, rollback/rebuild of an atomic unit, new instrumentation/evidence, or another method allowed by the canonical policy.

The solver loop is mandatory while the failure is actionable. Failed verification must read the failed logs before an edit or rerun:

```text
execute -> verify -> read_failed_logs -> diagnose -> decompose/replan -> execute
```

## 7. Session effectiveness

Every substantial session reports the metrics required by the canonical policy. The important distinction is:

- **activity**: messages, code written, analysis, attempted commands;
- **effectiveness**: verified acceptance work that now passes with evidence.

Only effectiveness advances completion. A successful session must meet all hard thresholds from the canonical JSON. First-pass yield and rework ratio are diagnostic efficiency metrics; they do not compensate for failed acceptance.

## 8. Machine enforcement

Run the canonical policy check:

```bash
python scripts/validate_execution_governance.py
```

Validate a session receipt:

```bash
python scripts/validate_execution_governance.py --session path/to/session-receipt.json
```

The validator fails closed on:

- multiple execution-governance JSON policy copies;
- invalid lane limits or terminal states;
- false PASS without executed verifier/evidence;
- retryable failure at session stop;
- success with blockers or incomplete effectiveness thresholds;
- repository mutation success without commit evidence;
- under-sized substantial lane plan without dependency-limit evidence;
- `BLOCKED_EXTERNAL`, `HARD_FAILED`, or operator abort without their required proof.

CI executes the policy validator before the normal test suite. Future runtime/executor layers that want to enforce this contract must call the same validator/contract instead of reimplementing policy values.

## 9. Canonical edit rule

For any governance upgrade:

1. edit `config/workspace.execution-governance.json` in place;
2. update this existing guide and `AGENTS.md` only as references/explanations;
3. update the validator/tests when executable enforcement changes;
4. run verification;
5. commit the coherent passed boundary;
6. verify the exact committed head before `READY`.

Never create a second canonical policy to preserve an old version. The repository history already preserves it.
