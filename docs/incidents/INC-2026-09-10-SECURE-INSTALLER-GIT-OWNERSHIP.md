# INC-2026-09-10-SECURE-INSTALLER-GIT-OWNERSHIP

**Status:** RESOLVED_IN_PR / PENDING_MERGE  
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

`scripts/test_workspace_security_contract.sh` now statically scans the secure installer for any occurrence of:

```text
git -C "$INSTALL_DIR"
```

that is not protected by:

```text
as_root git -C "$INSTALL_DIR"
```

The contract also explicitly asserts the privileged exact-head form.

Therefore, reintroducing the known-bad unprivileged pattern should fail the installer security contract in CI.

## Exact-head verification

For exact head `6ad8f3344ae50b453cfb64a23931e74ebdd1312b`, the pull-request workflows reached terminal SUCCESS:

- `canonical-module-ci` — run `34478728682` — SUCCESS
- `installer-ci` — run `34478728680` — SUCCESS
  - Bash syntax and installer contracts — SUCCESS
  - ShellCheck — SUCCESS
  - existing harness regression — SUCCESS
  - harness smoke — SUCCESS
- `harness-ci` — run `34478728677` — SUCCESS
  - Python 3.11 — SUCCESS through Unit tests, Runtime P0, and EV-01 through EV-10
  - Python 3.12 — SUCCESS through Unit tests, Runtime P0, and EV-01 through EV-10

At verification time PR #513 was open, non-draft, and mergeable. This record must not claim the fix is present on `main` until the PR is actually merged and `main` is re-read after merge.

## Concurrent-main convergence evidence

While the fix branch was being prepared, `main` advanced from:

```text
1c30bccbd7c54cbb54fd934ae589c0f8b466b605
```

to:

```text
fd4084c2927dfc3490e0498bd20d756cfe25ee5a
```

The intervening change was checked for overlap with the two-file incident write-set. No overlap was found. The branch was then converged using a non-force two-parent merge commit:

```text
6ad8f3344ae50b453cfb64a23931e74ebdd1312b
```

This preserved concurrent work and retained the exact incident fix without force-pushing.

## CI evidence interpretation lesson

A log request against the still-running Python 3.12 job returned an Azure-backed `BlobNotFound` response. The authoritative job state still reported `in_progress` with no failing conclusion.

Rule retained from this incident:

> Missing/unpublished logs for an in-progress GitHub Actions job are not evidence of test failure. Use job/run status and terminal conclusion as the primary state. Diagnose logs as a failure source only after GitHub reports an actual failed/cancelled terminal state or other direct failure evidence exists.

## Recurrence procedure

If the same or similar Git ownership signature appears again:

1. Open this incident record before changing code.
2. Confirm the effective user and owner of `WORKSPACE_INSTALL_DIR`.
3. Enumerate every `git -C "$INSTALL_DIR"` call in the secure installer.
4. Verify every such call is wrapped by `as_root`.
5. Run `scripts/test_workspace_security_contract.sh` and confirm the regression guard is active.
6. Check whether the guard was removed, skipped, bypassed, or made too narrow.
7. Do **not** add a global `safe.directory` exception or ownership broadening as the first response.
8. If the invariant still holds, collect new evidence and treat the event as a distinct root-cause investigation rather than assuming this incident explains it.

## Lessons retained

- A read-only operation still participates in the security/ownership boundary of the resource it accesses.
- Fix the inconsistent caller identity; do not weaken a correct platform protection.
- Preserve provenance (`EXACT_HEAD`) rather than bypassing it.
- When `main` moves concurrently, verify write-set overlap before convergence and avoid force-push when a safe merge preserves both histories.
- Do not classify missing in-progress CI logs as a failed test.
- Difficult RCA work is not complete until its invariant is encoded into a regression guard and its evidence is retained.
