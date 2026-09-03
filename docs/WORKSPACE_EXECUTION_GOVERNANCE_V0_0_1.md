# WorkSpace Execution Governance v0.0.1

**Status:** Mandatory project-wide operating policy  
**Scope:** every human, AI agent, sub-agent, automation, CI worker, or future execution role that changes, evaluates, or reports on WorkSpace  
**Authority:** subordinate to WorkSpace security policy and `TaskContract`; this document never grants runtime capability

## 1. Purpose

This policy turns the Harness philosophy into the default way WorkSpace is developed and operated.

The required behavior is:

```text
understand -> decompose -> run independent lanes -> verify -> adapt on failure -> measure -> commit passed units -> report exact evidence
```

A difficult problem is not a reason to stop. It is a signal to reduce the problem into smaller acceptance-bounded units, change strategy when a method stagnates, and continue until the requested acceptance boundary passes or an irreducible external/security blocker is proven.

## 2. Project-wide mandatory rules

The keywords **MUST**, **MUST NOT**, **SHALL**, and **SHALL NOT** are normative.

1. All non-trivial development sessions MUST use a parallel work plan.
2. The default operating window is **5–10 active lanes**, with a target of **10** when ten independent or dependency-isolated tasks can safely progress.
3. If fewer than five independent tasks exist, the actor MUST attempt to decompose large tasks into smaller acceptance-bounded units. It MUST NOT invent useless work merely to reach a lane count.
4. Every lane MUST have a goal, acceptance criteria, dependencies, evidence target, and explicit state.
5. Existing implementation MUST be inspected and reused before new architecture is added.
6. No task is `SUCCESS` because code was written or a model said it worked. Mandatory acceptance criteria MUST pass with evidence.
7. If a result is wrong or incomplete, the actor MUST revise it and rerun verification in the same session where practical.
8. Repeating the same failed strategy against the same state without new evidence is forbidden.
9. After two materially equivalent failures, the actor MUST change strategy: decompose, reframe, isolate a dependency, reduce scope, replace the implementation approach, roll back to an atomic boundary, or collect new evidence.
10. A hard problem MUST be split until each leaf unit is small enough to be completed and verified in one session where technically possible.
11. Progress MUST be measured and reported every development session.
12. Any task or module that reaches its acceptance boundary with PASS evidence MUST be committed in the same session at a coherent acceptance boundary.
13. Claims such as `PASS`, `READY`, `DONE`, `SUCCESS`, capacity, or completion percentage MUST be tied to exact-head evidence.
14. Security, authority, confidentiality, and fail-closed invariants override throughput. Parallelism never grants authority.

## 3. Ten-lane execution model

A normal high-throughput session SHOULD start with this template and adapt lane names to the work:

| Lane | Default responsibility | Required output |
|---|---|---|
| L1 | Current-state / exact-head reconnaissance | verified baseline |
| L2 | Contract / spec | acceptance-bounded contract |
| L3 | Core implementation | code or deterministic change |
| L4 | Integration | connection to existing architecture |
| L5 | Unit tests | focused deterministic tests |
| L6 | Regression / compatibility | regression evidence |
| L7 | Security / authority | invariant evidence |
| L8 | Failure / edge cases | negative-path evidence |
| L9 | Documentation / operator contract | synchronized docs |
| L10 | Release / exact-head evidence | commit + CI evidence + progress report |

These are execution lanes, not permanent teams. A lane may finish early and immediately take the next independent atomic task.

### 3.1 Lane state machine

```text
PLANNED -> ACTIVE -> VERIFYING -> PASS -> COMMITTED
                    |          
                    +-> FAIL -> ADAPT -> ACTIVE
                    +-> BLOCKED
```

`BLOCKED` is legal only when the blocker is explicit, evidence-backed, and cannot be removed within current authority. A blocked lane does not justify idling other independent lanes.

## 4. Atomic decomposition rule

When a unit is too large, uncertain, or repeatedly failing, recursively split it using one or more of these axes:

- contract vs implementation;
- data model vs behavior;
- read path vs write path;
- happy path vs failure path;
- authority decision vs side effect;
- platform-specific behavior;
- parser/compiler vs evaluator;
- deterministic verifier vs model-assisted inference;
- migration vs compatibility;
- documentation vs executable enforcement.

Stop decomposing when the leaf unit has:

- one primary purpose;
- explicit inputs/outputs;
- bounded side effects;
- a deterministic acceptance test where possible;
- no hidden dependency that prevents independent progress;
- a realistic path to PASS in one working session.

## 5. Adaptive failure policy

Harness principle: **failure changes strategy**.

The actor MUST retain the failure evidence and compare the next attempt against it. Valid adaptations include:

1. reduce the failing surface;
2. isolate the dependency;
3. replace inference with deterministic code;
4. replace the library/algorithm/implementation pattern;
5. create a reproducer or fixture;
6. roll back to the last proven boundary;
7. add instrumentation and collect new evidence;
8. change ordering or dependency graph;
9. split one lane into multiple leaf lanes;
10. mark an irreducible blocker only after viable in-authority alternatives were attempted or ruled out with evidence.

An identical retry with identical inputs, state, and method is not a new attempt.

## 6. Acceptance and no-false-completion rule

Every non-trivial lane SHOULD define an acceptance contract before implementation.

A mandatory criterion has this minimum shape:

```yaml
id: AC-01
statement: observable condition that must be true
verifier: deterministic verifier when available
evidence: exact artifact/test/commit/status source
required: true
```

`SUCCESS` is allowed only when all mandatory criteria pass. Optional scores, model confidence, code coverage percentage, or subjective quality cannot compensate for a failed hard gate.

Valid terminal states are:

- `SUCCESS`
- `PARTIAL`
- `BLOCKED`
- `IMPOSSIBLE`
- `FAILED_SAFE`
- `ABORTED`

## 7. Progress measurement

Progress is based on **verified work**, not code volume, elapsed time, messages, or model effort.

For a fixed scope:

```text
completion_percent = passed_acceptance_weight / total_planned_acceptance_weight * 100
remaining_percent  = 100 - completion_percent
```

A work unit contributes to the numerator only after its mandatory acceptance criteria PASS with evidence.

If new required scope is discovered, rebaseline explicitly:

```text
old_scope_weight -> new_scope_weight
old_completion    -> rebased_completion
reason            -> evidence-backed scope discovery
```

Never silently preserve an inflated percentage after adding required work.

### 7.1 Mandatory session report

Every substantial development session MUST report:

- base SHA;
- exact current/head SHA;
- lane states;
- acceptance PASS/FAIL state;
- tests/CI/evidence;
- completion %;
- remaining %;
- blockers and their evidence;
- commits created or merged.

## 8. Commit discipline

A commit is a verified checkpoint, not a progress claim.

- Commit a completed task/module in the same session once its coherent acceptance boundary passes.
- Do not label a known failing or unverified state as complete.
- Keep code, tests, and security/documentation changes together when they define one acceptance boundary.
- Multiple passed lanes may share one commit only when they are one tightly coupled module; otherwise prefer separate checkpoint commits.
- Commit messages, code, tests, schemas, and technical identifiers remain English.
- Before a `READY` or release claim, verify the exact commit head and its required CI/status evidence.

## 9. Harness principles applied to project work

All actors SHALL apply these defaults:

```text
avoid > reuse > precompute > compact > parallelize > accelerate > scale hardware
```

And:

- preserve user intent without promoting prompt text to authority;
- inspect and reuse existing implementation before rebuilding;
- correctness and security before optimization;
- deterministic work stays deterministic;
- evidence and provenance are first-class;
- no false completion;
- failure changes strategy;
- use the smallest high-signal context needed for the current leaf task;
- fail closed on security or authority uncertainty.

## 10. Precedence and exceptions

This governance is mandatory by default for every actor working on WorkSpace. It cannot override a higher-priority security, legal, repository, CI, or `TaskContract` restriction.

If the full 5–10 lane model is temporarily impossible because the task has fewer safe independent units, the actor MUST record the dependency limit and continue all available lanes. This is a dependency exception, not permission to abandon decomposition or progress measurement.

An exception to a MUST rule requires explicit operator approval or an evidence-backed higher-authority constraint and must be recorded in the session evidence.
