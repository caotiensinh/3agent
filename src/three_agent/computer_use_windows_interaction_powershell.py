from __future__ import annotations

import base64
import json
import os
import subprocess
from typing import Any, Mapping

from .computer_use_windows_interaction import (
    WindowsInteractionBackendResult,
    WindowsInteractionCommand,
    WindowsInteractionError,
    WindowsTargetInspection,
)
from .computer_use_windows_observation import (
    WindowsObservationConfig,
    WindowsPowerShellObservationBackend,
    WindowsReadOnlyBackend,
    capture_windows_observation,
)


class WindowsPowerShellInteractionBackend:
    """Standard-user, fixed-script Windows UIA/input backend.

    Caller-controlled text is passed only as base64-encoded JSON in a child
    process environment variable. It is never concatenated into PowerShell
    source. `-Command` receives exactly one fixed script payload and subprocess
    always uses `shell=False`.
    """

    _PAYLOAD_ENV = "WORKSPACE_CU170_PAYLOAD_B64"

    _SCRIPT = r'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class WorkspaceCu170Input {
  [DllImport("user32.dll", SetLastError=true)]
  public static extern bool SetCursorPos(int X, int Y);

  [DllImport("user32.dll")]
  public static extern void mouse_event(uint flags, uint dx, uint dy, uint data, UIntPtr extra);

  [StructLayout(LayoutKind.Sequential)]
  struct INPUT {
    public uint type;
    public InputUnion U;
  }

  [StructLayout(LayoutKind.Explicit)]
  struct InputUnion {
    [FieldOffset(0)] public MOUSEINPUT mi;
    [FieldOffset(0)] public KEYBDINPUT ki;
    [FieldOffset(0)] public HARDWAREINPUT hi;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct MOUSEINPUT {
    public int dx;
    public int dy;
    public uint mouseData;
    public uint dwFlags;
    public uint time;
    public UIntPtr dwExtraInfo;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct KEYBDINPUT {
    public ushort wVk;
    public ushort wScan;
    public uint dwFlags;
    public uint time;
    public UIntPtr dwExtraInfo;
  }

  [StructLayout(LayoutKind.Sequential)]
  struct HARDWAREINPUT {
    public uint uMsg;
    public ushort wParamL;
    public ushort wParamH;
  }

  [DllImport("user32.dll", SetLastError=true)]
  static extern uint SendInput(uint nInputs, INPUT[] pInputs, int cbSize);

  public static void Click(int x, int y) {
    if (!SetCursorPos(x, y)) throw new InvalidOperationException("SET_CURSOR_POS_FAILED");
    const uint DOWN = 0x0002;
    const uint UP = 0x0004;
    mouse_event(DOWN, 0, 0, 0, UIntPtr.Zero);
    mouse_event(UP, 0, 0, 0, UIntPtr.Zero);
  }

  public static void SendUnicode(string text) {
    const uint INPUT_KEYBOARD = 1;
    const uint KEYEVENTF_KEYUP = 0x0002;
    const uint KEYEVENTF_UNICODE = 0x0004;
    foreach (char ch in text) {
      var down = new INPUT {
        type = INPUT_KEYBOARD,
        U = new InputUnion {
          ki = new KEYBDINPUT {
            wVk = 0,
            wScan = ch,
            dwFlags = KEYEVENTF_UNICODE,
            time = 0,
            dwExtraInfo = UIntPtr.Zero
          }
        }
      };
      var up = down;
      up.U.ki.dwFlags = KEYEVENTF_UNICODE | KEYEVENTF_KEYUP;
      var inputs = new INPUT[] { down, up };
      if (SendInput(2, inputs, Marshal.SizeOf(typeof(INPUT))) != 2) {
        throw new InvalidOperationException("SEND_INPUT_FAILED");
      }
    }
  }
}
"@
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class WorkspaceCu170Window {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
}
"@

$encoded = [Environment]::GetEnvironmentVariable('WORKSPACE_CU170_PAYLOAD_B64', 'Process')
if ([string]::IsNullOrWhiteSpace($encoded)) { throw 'WINDOWS_INTERACTION_PAYLOAD_MISSING' }
try {
  $json = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($encoded))
  $payload = $json | ConvertFrom-Json
} catch {
  throw 'WINDOWS_INTERACTION_PAYLOAD_INVALID'
}

$hwnd = [WorkspaceCu170Window]::GetForegroundWindow()
if ($hwnd -eq [IntPtr]::Zero) { throw 'WINDOWS_FOREGROUND_WINDOW_NOT_FOUND' }
[uint32]$pidValue = 0
[void][WorkspaceCu170Window]::GetWindowThreadProcessId($hwnd, [ref]$pidValue)
if ($pidValue -le 0) { throw 'WINDOWS_FOREGROUND_PROCESS_NOT_FOUND' }
$process = Get-Process -Id $pidValue -ErrorAction Stop
$windowId = ('0x{0:X}' -f $hwnd.ToInt64())

if ([string]$payload.window_id -ne $windowId) { throw 'WINDOWS_INTERACTION_WINDOW_STALE' }
if ([int]$payload.process_id -ne [int]$pidValue) { throw 'WINDOWS_INTERACTION_PROCESS_STALE' }
if ([string]$payload.process_name -ine [string]$process.ProcessName) { throw 'WINDOWS_INTERACTION_PROCESS_NAME_STALE' }

$root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
if ($null -eq $root) { throw 'WINDOWS_UIA_ROOT_NOT_FOUND' }

function Find-ExactTarget($selector) {
  $condition = $null
  if (-not [string]::IsNullOrEmpty([string]$selector.automation_id)) {
    $condition = [System.Windows.Automation.PropertyCondition]::new(
      [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
      [string]$selector.automation_id
    )
  } elseif (-not [string]::IsNullOrEmpty([string]$selector.name)) {
    $condition = [System.Windows.Automation.PropertyCondition]::new(
      [System.Windows.Automation.AutomationElement]::NameProperty,
      [string]$selector.name
    )
  } else {
    throw 'WINDOWS_UIA_SELECTOR_MISSING'
  }
  $matches = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
  if ($matches.Count -eq 0) { throw 'WINDOWS_UIA_TARGET_NOT_FOUND' }
  if ($matches.Count -ne 1) { throw 'WINDOWS_UIA_TARGET_AMBIGUOUS' }
  $element = $matches.Item(0)
  if (-not [string]::IsNullOrEmpty([string]$selector.control_type)) {
    if ([string]$element.Current.ControlType.ProgrammaticName -ne [string]$selector.control_type) {
      throw 'WINDOWS_UIA_TARGET_CONTROL_TYPE_STALE'
    }
  }
  return $element
}

$element = $null
$focused = $false
$secure = $false
if ([string]$payload.operation -eq 'computer.accessibility.interact') {
  $element = Find-ExactTarget $payload.arguments
  $secure = [bool]$element.Current.IsPassword
} elseif ([string]$payload.operation -eq 'computer.keyboard.interact') {
  $element = [System.Windows.Automation.AutomationElement]::FocusedElement
  if ($null -eq $element) { throw 'WINDOWS_KEYBOARD_FOCUS_NOT_FOUND' }
  if ([int]$element.Current.ProcessId -ne [int]$pidValue) { throw 'WINDOWS_KEYBOARD_FOCUS_PROCESS_STALE' }
  if ([string]$element.Current.AutomationId -ne [string]$payload.arguments.focus_automation_id) {
    throw 'WINDOWS_KEYBOARD_FOCUS_STALE'
  }
  $focused = $true
  $secure = [bool]$element.Current.IsPassword
}

if ([string]$payload.phase -eq 'inspect') {
  [ordered]@{
    window_id = $windowId
    process_id = [int]$pidValue
    process_name = [string]$process.ProcessName
    automation_id = if ($null -ne $element) { [string]$element.Current.AutomationId } else { $null }
    name = if ($null -ne $element) { [string]$element.Current.Name } else { $null }
    control_type = if ($null -ne $element) { [string]$element.Current.ControlType.ProgrammaticName } else { $null }
    secure_input = [bool]$secure
    focused = [bool]$focused
  } | ConvertTo-Json -Compress
  exit 0
}

if ([string]$payload.phase -ne 'dispatch') { throw 'WINDOWS_INTERACTION_PHASE_INVALID' }
if ($secure -and ([string]$payload.interaction_kind -eq 'value' -or [string]$payload.interaction_kind -eq 'text')) {
  throw 'WINDOWS_SECURE_INPUT_USER_TAKEOVER_REQUIRED'
}

$postcondition = $null
switch ([string]$payload.operation) {
  'computer.accessibility.interact' {
    switch ([string]$payload.interaction_kind) {
      'invoke' {
        $pattern = $null
        if (-not $element.TryGetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern, [ref]$pattern)) {
          throw 'WINDOWS_UIA_INVOKE_PATTERN_UNAVAILABLE'
        }
        ([System.Windows.Automation.InvokePattern]$pattern).Invoke()
        $postcondition = 'WINDOWS_UIA_INVOKED'
      }
      'value' {
        $pattern = $null
        if (-not $element.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) {
          throw 'WINDOWS_UIA_VALUE_PATTERN_UNAVAILABLE'
        }
        $valuePattern = [System.Windows.Automation.ValuePattern]$pattern
        if ($valuePattern.Current.IsReadOnly) { throw 'WINDOWS_UIA_VALUE_READ_ONLY' }
        $valuePattern.SetValue([string]$payload.arguments.value)
        if ([string]$valuePattern.Current.Value -ne [string]$payload.arguments.value) {
          throw 'WINDOWS_UIA_VALUE_POSTCONDITION_FAILED'
        }
        $postcondition = 'WINDOWS_UIA_VALUE_SET'
      }
      'select' {
        $pattern = $null
        if (-not $element.TryGetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern, [ref]$pattern)) {
          throw 'WINDOWS_UIA_SELECTION_PATTERN_UNAVAILABLE'
        }
        $selectionPattern = [System.Windows.Automation.SelectionItemPattern]$pattern
        $selectionPattern.Select()
        if (-not $selectionPattern.Current.IsSelected) {
          throw 'WINDOWS_UIA_SELECTION_POSTCONDITION_FAILED'
        }
        $postcondition = 'WINDOWS_UIA_ITEM_SELECTED'
      }
      default { throw 'UNSUPPORTED_WINDOWS_UIA_INTERACTION' }
    }
  }
  'computer.pointer.interact' {
    if ([string]$payload.interaction_kind -ne 'click') { throw 'UNSUPPORTED_WINDOWS_POINTER_INTERACTION' }
    [WorkspaceCu170Input]::Click([int]$payload.arguments.x, [int]$payload.arguments.y)
    $postcondition = 'WINDOWS_POINTER_CLICK_SENT'
  }
  'computer.keyboard.interact' {
    if ([string]$payload.interaction_kind -ne 'text') { throw 'UNSUPPORTED_WINDOWS_KEYBOARD_INTERACTION' }
    [WorkspaceCu170Input]::SendUnicode([string]$payload.arguments.text)
    $postcondition = 'WINDOWS_KEYBOARD_TEXT_SENT'
  }
  default { throw 'UNSUPPORTED_GOVERNED_WINDOWS_OPERATION' }
}

[ordered]@{
  postcondition = $postcondition
  window_id = $windowId
  process_id = [int]$pidValue
  process_name = [string]$process.ProcessName
} | ConvertTo-Json -Compress
'''

    _KNOWN_BACKEND_ERRORS = frozenset({
        "WINDOWS_INTERACTION_PAYLOAD_MISSING",
        "WINDOWS_INTERACTION_PAYLOAD_INVALID",
        "WINDOWS_FOREGROUND_WINDOW_NOT_FOUND",
        "WINDOWS_FOREGROUND_PROCESS_NOT_FOUND",
        "WINDOWS_INTERACTION_WINDOW_STALE",
        "WINDOWS_INTERACTION_PROCESS_STALE",
        "WINDOWS_INTERACTION_PROCESS_NAME_STALE",
        "WINDOWS_UIA_ROOT_NOT_FOUND",
        "WINDOWS_UIA_SELECTOR_MISSING",
        "WINDOWS_UIA_TARGET_NOT_FOUND",
        "WINDOWS_UIA_TARGET_AMBIGUOUS",
        "WINDOWS_UIA_TARGET_CONTROL_TYPE_STALE",
        "WINDOWS_KEYBOARD_FOCUS_NOT_FOUND",
        "WINDOWS_KEYBOARD_FOCUS_PROCESS_STALE",
        "WINDOWS_KEYBOARD_FOCUS_STALE",
        "WINDOWS_INTERACTION_PHASE_INVALID",
        "WINDOWS_SECURE_INPUT_USER_TAKEOVER_REQUIRED",
        "WINDOWS_UIA_INVOKE_PATTERN_UNAVAILABLE",
        "WINDOWS_UIA_VALUE_PATTERN_UNAVAILABLE",
        "WINDOWS_UIA_VALUE_READ_ONLY",
        "WINDOWS_UIA_VALUE_POSTCONDITION_FAILED",
        "WINDOWS_UIA_SELECTION_PATTERN_UNAVAILABLE",
        "WINDOWS_UIA_SELECTION_POSTCONDITION_FAILED",
        "UNSUPPORTED_WINDOWS_UIA_INTERACTION",
        "UNSUPPORTED_WINDOWS_POINTER_INTERACTION",
        "UNSUPPORTED_WINDOWS_KEYBOARD_INTERACTION",
        "UNSUPPORTED_GOVERNED_WINDOWS_OPERATION",
        "SET_CURSOR_POS_FAILED",
        "SEND_INPUT_FAILED",
    })

    @classmethod
    def _bounded_backend_error(cls, stderr: str) -> str:
        # PowerShell often wraps `throw CODE` with stack/location text. Only fixed,
        # reviewed reason codes may cross the backend boundary; arbitrary stderr is
        # never propagated because it may contain desktop/user data.
        text = stderr if isinstance(stderr, str) else ""
        for code in cls._KNOWN_BACKEND_ERRORS:
            if code in text:
                return code
        return "WINDOWS_INTERACTION_BACKEND_FAILED"

    def __init__(
        self,
        *,
        powershell_executable: str = "powershell.exe",
        timeout_seconds: int = 15,
        observation_backend: WindowsReadOnlyBackend | None = None,
        observation_config: WindowsObservationConfig | None = None,
    ) -> None:
        if not isinstance(powershell_executable, str) or not powershell_executable.strip():
            raise WindowsInteractionError("INVALID_POWERSHELL_EXECUTABLE")
        if not isinstance(timeout_seconds, int) or not (1 <= timeout_seconds <= 60):
            raise WindowsInteractionError("INVALID_WINDOWS_INTERACTION_TIMEOUT")
        self._powershell_executable = powershell_executable
        self._timeout_seconds = timeout_seconds
        self._observation_backend = observation_backend or WindowsPowerShellObservationBackend(
            powershell_executable=powershell_executable,
            timeout_seconds=timeout_seconds,
        )
        self._observation_config = observation_config or WindowsObservationConfig(
            max_uia_nodes=128,
            max_uia_depth=6,
        )

    @staticmethod
    def _require_windows_host() -> None:
        if os.name != "nt":
            raise WindowsInteractionError("WINDOWS_BACKEND_REQUIRES_WINDOWS")

    @staticmethod
    def _payload(command: WindowsInteractionCommand, *, phase: str) -> dict[str, Any]:
        if phase not in {"inspect", "dispatch"}:
            raise WindowsInteractionError("WINDOWS_INTERACTION_PHASE_INVALID")
        return {
            "phase": phase,
            "session_id": command.session_id,
            "task_id": command.task_id,
            "operation": command.operation,
            "interaction_kind": command.interaction_kind,
            "resource_ref": command.resource_ref,
            "window_id": command.window_id,
            "process_id": command.process_id,
            "process_name": command.process_name,
            "arguments": dict(command.arguments),
        }

    def _run(self, command: WindowsInteractionCommand, *, phase: str) -> Mapping[str, Any]:
        self._require_windows_host()
        payload = json.dumps(
            self._payload(command, phase=phase),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        encoded = base64.b64encode(payload).decode("ascii")
        env = os.environ.copy()
        env[self._PAYLOAD_ENV] = encoded
        process_command = [
            self._powershell_executable,
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-STA",
            "-Command",
            self._SCRIPT,
        ]
        try:
            completed = subprocess.run(
                process_command,
                capture_output=True,
                text=True,
                timeout=self._timeout_seconds,
                check=False,
                shell=False,
                env=env,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise WindowsInteractionError("WINDOWS_INTERACTION_BACKEND_FAILED") from exc
        if completed.returncode != 0:
            raise WindowsInteractionError(self._bounded_backend_error(completed.stderr))
        if len(completed.stdout.encode("utf-8")) > 16 * 1024:
            raise WindowsInteractionError("WINDOWS_INTERACTION_BACKEND_OUTPUT_BOUND_EXCEEDED")
        try:
            result = json.loads(completed.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise WindowsInteractionError("WINDOWS_INTERACTION_BACKEND_OUTPUT_INVALID_JSON") from exc
        if not isinstance(result, Mapping):
            raise WindowsInteractionError("WINDOWS_INTERACTION_BACKEND_OUTPUT_MUST_BE_OBJECT")
        return result

    def inspect_target(self, command: WindowsInteractionCommand) -> WindowsTargetInspection:
        result = self._run(command, phase="inspect")
        process_id = result.get("process_id")
        if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
            raise WindowsInteractionError("INVALID_WINDOWS_TARGET_INSPECTION")
        return WindowsTargetInspection(
            window_id=str(result.get("window_id") or ""),
            process_id=process_id,
            process_name=str(result.get("process_name") or ""),
            automation_id=result.get("automation_id"),
            name=result.get("name"),
            control_type=result.get("control_type"),
            secure_input=result.get("secure_input") is True,
            focused=result.get("focused") is True,
        )

    def dispatch(self, command: WindowsInteractionCommand) -> WindowsInteractionBackendResult:
        result = self._run(command, phase="dispatch")
        if result.get("window_id") != command.window_id or result.get("process_id") != command.process_id:
            raise WindowsInteractionError("WINDOWS_DISPATCH_TARGET_STALE")
        if str(result.get("process_name") or "").lower() != command.process_name.lower():
            raise WindowsInteractionError("WINDOWS_DISPATCH_TARGET_STALE")
        postcondition = result.get("postcondition")
        if postcondition != command.expected_postcondition:
            raise WindowsInteractionError("WINDOWS_BACKEND_POSTCONDITION_MISMATCH")
        post_observation = capture_windows_observation(
            config=self._observation_config,
            backend=self._observation_backend,
            session_id=command.session_id,
            task_id=command.task_id,
        )
        return WindowsInteractionBackendResult(
            post_observation=post_observation,
            observed_postconditions=(postcondition,),
            result={
                "operation": command.operation,
                "interaction_kind": command.interaction_kind,
                "window_id": command.window_id,
                "process_id": command.process_id,
            },
        )
