# Failure Evidence and Regression Policy v0.1

## Purpose

WorkSpace must not treat difficult failures as disposable debugging events. A difficult incident that produces a verified root cause must be converted into durable engineering evidence and, where technically possible, a machine-enforced regression guard.

The objective is not to promise that software can never fail again. The objective is to ensure that a known failure mechanism is not silently reintroduced and that future diagnosis starts from prior verified evidence instead of repeating the same investigation from zero.

## When an incident record is mandatory

Create a durable incident record when one or more of the following is true:

- root cause required multi-step diagnosis, log correlation, reproduction, or elimination of competing hypotheses;
- the failure crossed a privilege, ownership, security, network, process, filesystem, runtime, packaging, or deployment boundary;
- the symptom appeared only in CI, field deployment, a specific OS/runtime, or another environment that is difficult to reproduce;
- a workaround could hide the failure without correcting the root cause;
- the same or a materially similar failure has appeared before;
- the failure could affect installation, upgrade, recovery, availability, confidentiality, integrity, or release readiness;
- concurrent repository changes, timing, race conditions, hidden state, or external infrastructure materially complicated diagnosis;
- the final fix establishes a reusable engineering invariant.

## Required evidence fields

Every difficult-incident record must contain, at minimum:

1. **Incident ID and status** — stable identifier and current disposition.
2. **Date and component** — when the incident was verified and the affected boundary.
3. **Observed signature** — exact or normalized symptom that future engineers can search for.
4. **Impact** — what operation was blocked or made unsafe.
5. **Evidence chain** — logs, code paths, commits, pull requests, CI runs, or reproducible observations that support the conclusion.
6. **Root cause** — the specific mechanism that explains the evidence; do not substitute a symptom description.
7. **Rejected hypotheses/workarounds** — especially broad exceptions that would weaken security or hide the defect.
8. **Corrective change** — the minimal production change that resolves the root cause.
9. **Prevention invariant** — a concise rule that must remain true after the fix.
10. **Regression enforcement** — test, static contract, CI gate, assertion, monitor, or an explicit reason why machine enforcement is not feasible.
11. **Verification evidence** — exact head SHA and terminal verifier results when available.
12. **Recurrence procedure** — what to inspect first if the same signature appears again.

## No fix-only closure

A difficult incident is not considered engineering-complete merely because the immediate symptom disappears.

Where machine enforcement is feasible, the root-cause invariant MUST be encoded in a regression test or CI/static contract in the same development stream as the fix. The regression must fail when the known-bad pattern is reintroduced.

If machine enforcement is not feasible, the incident record MUST state why and define the narrowest reliable manual verification or monitoring procedure.

## Same-signature recurrence rule

If a future failure matches an existing incident signature:

1. Treat it as a potential regression first, not as an unrelated new problem.
2. Load the existing incident record and verify its prevention invariant.
3. Check whether the existing regression guard executed and whether it was bypassed, weakened, removed, or scoped incorrectly.
4. Compare the current code/runtime boundary with the previously verified corrective state.
5. Only open a new root-cause branch after evidence shows that the prior mechanism does not explain the new failure.

A recurring signature must never be "fixed" by deleting, weakening, skipping, or broadly bypassing the regression guard without a new evidence-backed root-cause analysis.

## Security and safety rule

Do not replace a precise boundary fix with a broad exception merely to make a failing workflow pass.

Examples of prohibited closure patterns include:

- globally trusting an unsafe path when only one command has the wrong effective identity;
- broadening filesystem ownership or permissions without a demonstrated requirement;
- disabling a security check because it exposes an ownership, provenance, or trust mismatch;
- suppressing an error without preserving equivalent detection elsewhere.

If the platform protection is correct and WorkSpace is violating its contract, fix WorkSpace.

## Evidence integrity

Use immutable or stable references whenever possible:

- exact commit SHA rather than only branch name;
- pull request number plus exact head SHA;
- workflow run ID and terminal conclusion;
- exact file path and invariant under test.

Do not claim a failure is resolved from queued, pending, or in-progress CI alone.

## Required incident template

```text
# <INCIDENT_ID> — <short title>

Status:
Date:
Component:
Related PR:
Verified head:

## Observed signature
## Impact
## Evidence chain
## Root cause
## Rejected hypotheses / unsafe workarounds
## Corrective change
## Prevention invariant
## Regression enforcement
## Verification evidence
## Recurrence procedure
## Lessons retained
```

## Governance rule

For future difficult failures, the default engineering sequence is:

**observe -> collect evidence -> reproduce/narrow -> establish root cause -> fix minimally -> encode invariant -> add regression -> verify exact head -> record incident evidence**.

Planning, speculation, queued CI, and documentation alone do not prove a fix. The durable record is evidence of what was learned; the regression guard is the mechanism that prevents the same known defect from silently returning.
