# INC-2026-09-10-SECURE-INSTALLER-GIT-OWNERSHIP

**Status:** RESOLVED_IN_PR / READY_TO_MERGE  
**Date:** 2026-09-10  
**Component:** `scripts/setup_workspace_secure.sh`  
**Related PR:** #513 — `fix(installer): prevent secure checkout ownership failure`  
**Verified head:** `6ad8f3344ae50b453cfb64a23931e74ebdd1312b`  
**Verified base:** `main@fd4084c2927dfc3490e0498bd20d756cfe25ee5a`

## Observed signature

Secure installation could abort while reading the Git checkout with a Git `dubious ownership` / safe-directory failure for the root-owned WorkSpace installation directory.

The important normalized signature is:

```text
root-owned WORKSPACE_INSTALL_DIR
+ Git operation executed as normal operator user
+ Git safe-directory ownership rejection
```

## Impact

The installer could successfully create or update the checkout and then fail before secure boundary installation, virtual-environment completion, and the final confidential-mode smoke test.

This is an installer correctness failure, not a reason to weaken Git ownership protection.

## Evidence chain

The secure installer intentionally performs installation-directory Git operations through the `as_root` privilege boundary. Before the fix, the checkout/update operations were privileged, but the exact-head lookup was not:

```bash
EXACT_HEAD="$(git -C "$INSTALL_DIR" rev-parse HEAD)"
```

That command accessed the same root-owned repository as the normal operator user.

The corrected form is:

```bash
EXACT_HEAD="$(as_root git -C "$INSTALL_DIR" rev-parse HEAD)"
```

PR #513 contains only two changed files:

- `scripts/setup_workspace_secure.sh`
- `scripts/test_workspace_security_contract.sh`

The production delta is one privilege-boundary correction. The remaining change is regression enforcement.

## Root cause

The root cause was an **effective-identity mismatch inside one Git command**.

The installer created or updated `WORKSPACE_INSTALL_DIR` under `as_root`, so Git correctly saw the checkout as owned by another identity when the later `rev-parse` executed as the normal user. The read-only nature of `rev-parse` did not exempt it from Git's repository ownership trust check.

The defect therefore was not Git's `safe.directory` behavior. Git's protection exposed an inconsistent privilege boundary in WorkSpace.

## Why this was easy to misdiagnose

Several facts made the failure look more complicated than the final one-line production fix:

1. Clone, fetch, checkout, and merge already used `as_root`, so the installer appeared privilege-consistent at first inspection.
2. The failing operation was read-only (`rev-parse`), which can be incorrectly assumed to be ownership-neutral.
3. The repository was changing concurrently. `main` moved from `1c30bccbd7c54cbb54fd934ae589c0f8b466b605` to `fd4084c2927dfc3490e0498bd20d756cfe25ee5a` while PR #513 was being prepared.
4. During CI, requesting logs for a still-running job returned `BlobNotFound`. That was an unavailable in-progress log artifact, not a test failure.

These complications must not obscure the evidence-backed root cause.

## Rejected hypotheses / unsafe workarounds

The following were deliberately not used as the corrective action:

### Global or broad `safe.directory`

Do not hide this defect with a broad trust exception such as globally trusting `/opt/workspace`. That would suppress Git's ownership protection instead of restoring the intended privilege boundary.

### Ownership broadening

Do not `chown` the secure installation tree to the operator merely to make one Git read succeed. The installation layout is intentionally managed through the privileged boundary.

### Disabling or ignoring the error

Do not suppress the Git error or make exact-head provenance optional. The installer uses `EXACT_HEAD` as deployment evidence.

## Corrective change

The exact-head lookup now executes through the same `as_root` wrapper as every other Git operation scoped to `WORKSPACE_INSTALL_DIR`:

```bash
EXACT_HEAD="$(as_root git -C "$INSTALL_DIR" rev-parse HEAD)"
```

No driver, kernel, bootloader, filesystem ownership, or global Git trust policy was changed.

## Prevention invariant

> Every Git operation that accesses `WORKSPACE_INSTALL_DIR` in `setup_workspace_secure.sh` MUST execute through the same `as_root` privilege boundary used to create and maintain that checkout.

Read-only Git commands are included in this invariant.

## Regression enforcement

`scripts/test_workspace_security_contract.sh` statically scans the secure installer for any occurrence of:

```text
git -C "$INSTALL_DIR"
```

that is not protected by:

```text
as_root git -C "$INSTALL_DIR"
```

The contract also explicitly asserts the privileged exact-head form.

Therefore, reintroducing the known-bad unprivileged pattern fails the installer security contract in CI.

## Verification evidence

PR #513 exact head:

`6ad8f3344ae50b453cfb64a23931e74ebdd1312b`

Terminal pull-request workflows:

- `canonical-module-ci` — SUCCESS
- `installer-ci` — SUCCESS
  - shell-contract — SUCCESS
  - ShellCheck — SUCCESS
  - existing harness regression — SUCCESS
  - harness smoke — SUCCESS
- `harness-ci` — SUCCESS
  - Python 3.11 — Unit tests SUCCESS, Runtime P0 SUCCESS, EV-01 through EV-10 SUCCESS
  - Python 3.12 — Unit tests SUCCESS, Runtime P0 SUCCESS, EV-01 through EV-10 SUCCESS

Relevant workflow run IDs:

- harness-ci: `34478728677`
- installer-ci: `34478728680`
- canonical-module-ci: `34478728682`

PR #514 governance/evidence head before this terminal-state refresh was `1a00de0bd81351951a7d5096a8844755bf186c99`; all three of its pull-request workflows were also terminal SUCCESS before this documentation-only status refresh. Because this file update changes the exact PR head, the new head must be re-verified before PR #514 is called release-ready.

## Recurrence procedure

If Git again reports `dubious ownership` for the secure WorkSpace checkout:

1. Do not add a broad `safe.directory` exception.
2. Read this incident first.
3. Run or inspect `scripts/test_workspace_security_contract.sh`.
4. Enumerate every Git operation scoped to `WORKSPACE_INSTALL_DIR` and verify it crosses the `as_root` boundary.
5. Verify filesystem ownership and the effective identity of the failing Git command.
6. If the invariant still holds, collect fresh evidence and investigate a new root cause; do not force this historical explanation onto contradictory facts.

## Lessons retained

- Privilege consistency applies to read-only operations as well as mutations.
- Security mechanisms such as Git safe-directory checks should not be weakened to compensate for application boundary mistakes.
- A one-line production fix can require substantial RCA; retain the reasoning and the machine guard, not just the line change.
- Concurrent `main` movement requires explicit convergence and exact-head re-verification.
- Missing logs for an in-progress CI job are not equivalent to a failing job.
- A difficult incident is not durable until its root-cause invariant has a regression mechanism and an evidence record.