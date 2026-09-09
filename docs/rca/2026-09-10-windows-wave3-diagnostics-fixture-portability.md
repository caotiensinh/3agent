# RCA: Windows Wave-3 diagnostics fixture portability

**Date:** 2026-09-10 JST  
**Repository:** `caotiensinh/3agent`  
**Area:** diagnostics / Windows deployment / cross-platform test fixtures  
**Related work:** PR #483, corrective PR #489  
**Corrective PR head:** `cc7810862cda6a5a00d7706b37767795e515a8eb`  
**Corrective merge SHA:** `603577566a7ee4cafa32773fcd7dfb9c26305077`

## 1. Context

Wave-3 diagnostics added dock/display/driver collectors and associated tests. Linux-oriented diagnostics tests passed in the normal development path, but a Windows clean-install path later exposed a portability failure in a synthetic Linux driver-inventory fixture.

This was a difficult case because the production collector was not the failing component. The failure lived in test-fixture construction and only became visible under the Windows filesystem rules exercised by deployment CI.

## 2. Symptom

The reproducible failing test was:

`test_linux_driver_inventory_is_bounded_and_excludes_usb_serial`

The direct Windows traceback proved failure during fixture setup at:

`pci_device.mkdir()`

The fixture attempted to create a directory component containing a Linux PCI BDF identifier:

`0000:00:01.0`

Windows rejected the `:` characters in that directory component and raised:

`OSError: [WinError 123]`

The failure reproduced on both Python 3.11 and Python 3.12 in the dedicated Windows portability path.

## 3. Evidence that mattered

The decisive evidence was not an inferred platform difference; it was the direct Windows traceback showing the failing filesystem operation and the exact invalid path component.

A dedicated Windows portability gate was used to run the complete Wave-3 diagnostics test file on:

- Windows + Python 3.11
- Windows + Python 3.12

This removed ambiguity caused by broader bootstrap/deployment execution and made the failing unit test directly observable.

## 4. False leads and rejected hypotheses

### 4.1 Real symlink creation was only part of the problem

An earlier version of the fixture created a real directory symlink for the synthetic driver binding. That was OS-sensitive and removing it was necessary, but it was not sufficient.

After removing the symlink dependency, Windows still failed because the fixture retained the Linux PCI BDF text as a physical directory name.

**Lesson:** fixing the first portability smell does not prove the entire fixture is portable. Rerun the exact failing platform after every candidate fix.

### 4.2 Production collector logic was not proven defective

The failing operation occurred before the collector behavior under test could complete. The evidence pointed to the synthetic test filesystem, not production driver enumeration.

**Lesson:** distinguish fixture-construction failures from production behavior failures before changing production code.

### 4.3 A green Linux path was not sufficient release evidence

The Linux-compatible fixture could pass while containing assumptions that are illegal on Windows.

**Lesson:** cross-platform code needs cross-platform fixture validation, not only cross-platform production abstractions.

## 5. Root cause

The synthetic Linux driver-inventory fixture encoded Linux-specific representation details directly into the host operating system's temporary filesystem:

1. it previously depended on a real symlink;
2. it used `0000:00:01.0` as a literal temporary directory name;
3. `:` is invalid in a normal Windows path component.

Therefore the test fixture itself was not host-OS neutral.

## 6. Fix

The corrective change kept the semantics of the test but removed host-filesystem assumptions:

- replace the synthetic PCI directory name `0000:00:01.0` with the OS-neutral `device-0`;
- stop creating a real filesystem symlink for the driver binding;
- mock the source-reviewed `_driver_name` seam by exact fixture `Path` identity;
- preserve real temporary PCI/USB inventory files used by the rest of the test;
- preserve the expected `fixture_driver` binding evidence;
- preserve device-count bounds;
- preserve USB serial exclusion.

No production collector behavior, authority policy, network policy, or security boundary was relaxed.

## 7. Regression protection added

A dedicated workflow was added:

`.github/workflows/windows-wave3-portability-ci.yml`

It runs the full `test_dock_display_driver_wave3.py` suite on Windows for both Python 3.11 and 3.12.

Purpose:

- catch Linux-only fixture assumptions before merge;
- expose Wave-3 failures directly instead of allowing a larger deployment bootstrap to hide the immediate traceback;
- prevent future symlink/path portability regressions.

## 8. Verification

Corrective PR #489 was merged with merge commit:

`603577566a7ee4cafa32773fcd7dfb9c26305077`

Post-merge verification on that exact SHA completed successfully:

- `windows-wave3-portability-ci` — Python 3.11: PASS
- `windows-wave3-portability-ci` — Python 3.12: PASS
- `windows-deploy-ci` full clean-install — Python 3.11: PASS
- `windows-deploy-ci` full clean-install — Python 3.12: PASS
- installed command + exact GitHub lineage verification: PASS
- Python 3.12 trusted updater re-deploy + configuration preservation: PASS
- harness-ci — Python 3.11: PASS
- harness-ci — Python 3.12: PASS
- regression groups A-D, E-H, I-M, N-R, S-Z: PASS
- full unit tests: PASS
- runtime P0 benchmark: PASS
- enterprise verification EV-01 through EV-10: PASS
- installer-ci: PASS
- canonical-module-ci: PASS

The Windows failed-unit diagnostic step was skipped after the fix because bootstrap/unit execution no longer failed, which was the expected success-path behavior.

## 9. Reusable engineering lessons

1. **A fixture is software.** Treat fixture portability and privilege assumptions with the same rigor as production code.
2. **Do not emulate one OS by writing its illegal path syntax onto another OS.** Model the semantic identity separately from the host filesystem representation.
3. **Use seams instead of privileged filesystem tricks when the seam is what production code already consumes.** In this case `_driver_name` was the appropriate seam.
4. **When a broad workflow hides the root error, add a narrow diagnostic gate.** The narrow gate should reproduce the same behavior without weakening assertions.
5. **A partial fix must be re-proven on the failing platform.** Removing the symlink was not enough; the invalid BDF directory remained.
6. **Do not modify production logic until evidence identifies production logic as the cause.** This incident was a test-fixture defect.
7. **Do not call a post-merge incident closed at PR-green.** Re-run the downstream lifecycle where the incident originally appeared.
8. **Exact SHA matters.** Installation, updater, and post-merge tests must prove they executed the intended commit rather than an ambiguous branch tip.

## 10. Closure criteria used for 100%

The case was considered complete only after all of the following were true:

- root cause proven by Windows traceback;
- minimal fixture fix implemented;
- no correctness/security assertion weakened;
- dedicated cross-platform regression gate added;
- corrective PR merged;
- merge SHA proven on `main` at the verification checkpoint;
- Windows full clean-install passed on Python 3.11 and 3.12;
- exact installed SHA/lineage verification passed;
- trusted updater/config-preservation verification passed where applicable;
- harness, installer, canonical, regression, unit, benchmark, and enterprise verification gates passed.

## 11. Pattern to recognize in future incidents

When CI behaves like this:

- Linux passes;
- Windows fails before meaningful assertion execution;
- traceback points into `TemporaryDirectory`, `mkdir`, `symlink`, path parsing, permissions, shell quoting, or executable lookup;

first audit the test harness/fixture for host-OS assumptions before changing production behavior.
