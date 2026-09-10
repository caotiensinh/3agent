# CU-160 Incident RCA — Windows PowerShell Parameter Binding Failure

Incident ID: `CU160-PS-ARG-BINDING-20260910`  
Date: 2026-09-10  
Status: `RESOLVED / REGRESSION-GUARDED`  
Affected component: `src/three_agent/computer_use_windows_observation.py`  
Detection gate: `computer-use-windows-observation-ci`  
Security posture: read-only, standard-user; no privileged broker involved

## 1. Executive summary

The CU-160 Windows observation backend contained a real invocation defect that unit tests and the existing Windows deployment smoke gate did not detect.

The backend used `powershell.exe -Command` with the fixed observation script as one process argument, then appended `-IncludeScreenshot`, `-MaxNodes`, and `-MaxDepth` as additional process arguments. PowerShell did not bind those trailing arguments to the script's `param(...)` block. Instead, the script executed first with default/unbound parameter values and PowerShell then interpreted `-IncludeScreenshot` as a new command.

The live Windows acceptance test exposed the defect on a real `windows-latest` runner. The production fix changed the invocation to one fixed PowerShell scriptblock containing both the fixed observation script and the already-validated boolean/integer argument binding. `subprocess.run(..., shell=False)` remains mandatory.

This incident establishes a permanent repository invariant: **when WorkSpace uses `powershell.exe -Command`, no script parameter tokens may be appended after the single command payload argument.** The complete invocation must be one PowerShell command payload, or the implementation must use a reviewed `-File`/other explicit mechanism whose parameter-binding semantics are covered by executable tests.

## 2. User-visible / system-visible symptom

The live CU-160 acceptance failed with:

```text
WindowsObservationError: WINDOWS_OBSERVATION_BACKEND_FAILED
```

The first implementation hid the underlying PowerShell stderr behind the bounded production error class, so the initial error was insufficient for root-cause analysis.

A controlled CI diagnostic, limited to the synthetic acceptance window created by the test itself, revealed the actual PowerShell error:

```text
-IncludeScreenshot : The term '-IncludeScreenshot' is not recognized as the name of a cmdlet, function, script file, or operable program.
```

The same diagnostic showed that the script had already emitted malformed/incomplete observation state before failing:

```text
uia_node_count=0
accessibility=null
```

This proved that the failure was not a UI Automation availability problem and not a Python-version problem. It was process-invocation semantics.

## 3. Defective invocation pattern

The defective Python command construction was semantically equivalent to:

```text
powershell.exe \
  -NoLogo \
  -NoProfile \
  -NonInteractive \
  -Command \
  <SCRIPT_WITH_param_BLOCK> \
  -IncludeScreenshot \
  $false \
  -MaxNodes \
  32 \
  -MaxDepth \
  4
```

The incorrect assumption was that arguments following the `-Command` script string would automatically bind to:

```powershell
param([bool]$IncludeScreenshot, [int]$MaxNodes, [int]$MaxDepth)
```

That assumption is forbidden from now on.

## 4. Root cause

### Primary root cause

The Python-to-PowerShell process boundary was tested syntactically but not behaviorally. The code verified that:

- `shell=False` was used;
- `-NoProfile` and `-NonInteractive` were present;
- the fixed script contained UI Automation code;
- dangerous primitives such as `Invoke-Expression`, `Start-Process`, and registry mutation were absent.

Those checks were valuable security checks, but they did **not** verify PowerShell's actual parameter-binding behavior for the complete command line.

### Contributing cause 1 — mocked subprocess result

The original unit test mocked `subprocess.run` and returned a valid JSON payload. Therefore the test proved the Python parser and command-shape properties that it asserted, but it never executed the command through a real PowerShell parser.

### Contributing cause 2 — Windows CI gate was too shallow

The existing `windows-deploy-ci` path compiled source/tests and ran `three-agent smoke`, but did not execute CU-160's real UI Automation backend against a real Windows window. A compile/smoke pass therefore created no evidence that the PowerShell boundary worked end-to-end.

### Contributing cause 3 — bounded error classification hid RCA detail

The production backend correctly avoided returning arbitrary stderr as a public error surface, but `WINDOWS_OBSERVATION_BACKEND_FAILED` alone was insufficient for engineering RCA. The correct response is not to expose raw stderr generally; it is to maintain a controlled synthetic acceptance/diagnostic path in CI.

## 5. Correct implementation invariant

The corrected implementation constructs one PowerShell invocation string:

```text
& {
  <FIXED SCRIPT WITH param(...)>
} -IncludeScreenshot:$false -MaxNodes 32 -MaxDepth 4
```

and passes exactly that one string after `-Command`:

```text
powershell.exe -NoLogo -NoProfile -NonInteractive -Command <ONE_INVOCATION_STRING>
```

The following are mandatory:

1. `subprocess.run(..., shell=False)`.
2. The PowerShell program remains fixed code owned by the repository; no model/user/page text is concatenated into executable PowerShell.
3. Dynamic values are restricted to values already validated by Python policy/types. For CU-160 these are a boolean and bounded integers.
4. `-Command` has exactly one command-payload argument after it in the process argument vector.
5. No parameter token such as `-IncludeScreenshot`, `-MaxNodes`, or `-MaxDepth` may appear as a separate process argument after the `-Command` payload.
6. A live Windows acceptance must execute the real backend, not only a mocked subprocess.
7. Secure/password UI evidence remains redacted and screenshots remain denied by default.

## 6. Forbidden patterns

Do not reintroduce any of these patterns without a new reviewed design and executable proof:

```python
["powershell.exe", "-Command", SCRIPT, "-Param", "value"]
```

```python
subprocess.run(command, shell=True)
```

```powershell
Invoke-Expression $dynamicText
```

Do not fix parameter binding by moving user/model-controlled text into the command string. That would replace a correctness bug with a command-injection risk.

## 7. Required regression protection

The repository must retain both layers below.

### Layer A — command-shape unit invariant

A focused test must fail if:

- `-Command` is no longer the penultimate process argument;
- more than one process argument follows `-Command`;
- validated CU-160 parameters are moved back outside the single scriptblock payload;
- `shell=False` is removed;
- forbidden dynamic-execution primitives are introduced.

### Layer B — live Windows acceptance

`computer-use-windows-observation-ci` must run the real backend on `windows-latest` for supported Python versions and prove that:

- an actual foreground test window can be observed;
- UI Automation returns structured data;
- the target process/window identity matches the synthetic test target;
- no screenshot is retained when not requested;
- bounded/privacy tests still pass.

A mocked subprocess test alone is never sufficient evidence for this boundary again.

## 8. Review checklist for all future PowerShell-backed adapters

Before merging any PowerShell-backed observation or interaction code, reviewers must answer YES to all of the following:

- Is the exact process argument vector tested?
- Is parameter binding executed through real PowerShell in at least one Windows acceptance test?
- Is `shell=False` enforced?
- Is executable PowerShell fixed/trusted rather than assembled from untrusted text?
- Are all dynamic arguments typed, bounded, and validated before crossing the process boundary?
- Does failure remain fail-closed?
- Is controlled diagnostic evidence available without leaking credentials or arbitrary user UI content?
- Does CI run this acceptance when either the adapter, its regression tests, or its workflow changes?

Any NO blocks `VERIFIED_PASS`.

## 9. Evidence and chronology

Initial live acceptance head:

```text
cd815a01e8e10585721e00a5632f7704e773b103
```

The live test failed on both Python 3.11 and 3.12 at the real UI Automation step.

Controlled diagnostic head:

```text
08bb777da9d2e76ad4981056c83e3ba3db146d8f
```

The diagnostic exposed the `-IncludeScreenshot` command-not-found error and incomplete UIA output.

Production fix head:

```text
444cfd44caf34bfae7e48ff2d207d11f92c17b64
```

Focused acceptance:

```text
computer-use-windows-observation-ci run 34479843304: SUCCESS
Python 3.11 live Windows UI Automation: PASS
Python 3.12 live Windows UI Automation: PASS
```

Mandatory exact-head workflows at the production fix head:

```text
canonical-module-ci run 34479843336: SUCCESS
internet-egress-security-ci run 34479843325: SUCCESS
windows-deploy-ci run 34479843352: SUCCESS
installer-ci run 34479843294: SUCCESS
harness-ci run 34479843311: SUCCESS
```

The final CU-160 ledger commit then recorded the verified package at:

```text
39c55d98d9ee365236061ce0e5c29415c84f158c
```

## 10. Rule carried forward into CU-170 and later adapters

CU-170 Windows interaction and every later native adapter inherit this incident rule. Any new PowerShell bridge must prove its command boundary with both command-shape regression tests and a real platform acceptance appropriate to the capability.

For CU-170 specifically, this incident does **not** justify adding a generic shell execution interface. Interaction must remain a narrow, typed action vocabulary (UI Automation first; pointer/keyboard only reviewed fallback) behind existing WorkSpace approval, writer-fence, stale-target, and user-takeover controls.
