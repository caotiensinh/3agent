from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from .computer_use import ComputerActionRequest, ComputerObservation, ComputerPolicyDecision, decide_computer_action
from .computer_use_approval import ComputerApprovalGrant, consume_computer_approval, require_valid_computer_approval
from .computer_use_replay import ComputerActionReplayLedger, require_target_fresh
from .computer_use_windows_observation import (
    WindowsObservationConfig,
    WindowsPowerShellObservationBackend,
    capture_windows_observation,
)
from .computer_use_writer import ComputerWriterBinding, require_current_writer_binding
from .runtime_writer_lease import RuntimeWriterLease, RuntimeWriterLeaseRepository

MAX_AUTOMATION_ID_CHARS = 128
MAX_TYPED_TEXT_CHARS = 4096
MAX_EXPECTED_VISIBLE_TEXT_CHARS = 512
_WINDOW_REF_RE = re.compile(r"^local:desktop:window:(0x[0-9A-Fa-f]{1,16})$")
_AUTOMATION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class WindowsInteractionError(RuntimeError):
    """Governed Windows interaction failed admission, dispatch, or verification."""


class WindowsInteractionDispatchError(WindowsInteractionError):
    def __init__(self, reason_code: str, *, consumed_approval: ComputerApprovalGrant | None) -> None:
        self.reason_code = reason_code
        self.consumed_approval = consumed_approval
        super().__init__(reason_code)


@dataclass(frozen=True)
class WindowsInteractionCommand:
    operation: str
    interaction_kind: str
    resource_ref: str
    window_id: str
    automation_id: str
    text: str | None = None
    expected_visible_text: str | None = None


@dataclass(frozen=True)
class WindowsTargetInspection:
    state_sha256: str
    window_id: str
    process_id: int
    secure_input: bool
    is_enabled: bool
    control_type: str


@dataclass(frozen=True)
class WindowsInteractionBackendResult:
    post_observation: ComputerObservation
    observed_postconditions: tuple[str, ...]
    result: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class GovernedWindowsInteractionResult:
    backend_result: WindowsInteractionBackendResult
    consumed_approval: ComputerApprovalGrant


class WindowsInteractionBackend(Protocol):
    def inspect_target(
        self,
        command: WindowsInteractionCommand,
        *,
        session_id: str,
        task_id: str,
    ) -> WindowsTargetInspection:
        ...

    def dispatch(
        self,
        command: WindowsInteractionCommand,
        *,
        session_id: str,
        task_id: str,
    ) -> WindowsInteractionBackendResult:
        ...


def _bounded_text(value: Any, *, field: str, limit: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str) or value != value.strip() or (not value and not allow_empty):
        raise WindowsInteractionError(f"INVALID_WINDOWS_{field.upper()}")
    if len(value) > limit or "\x00" in value or "\r" in value or "\n" in value:
        raise WindowsInteractionError(f"INVALID_WINDOWS_{field.upper()}")
    return value


def _automation_id(value: Any) -> str:
    if not isinstance(value, str) or value != value.strip() or not _AUTOMATION_ID_RE.fullmatch(value):
        raise WindowsInteractionError("INVALID_WINDOWS_AUTOMATION_ID")
    return value


def _window_id_from_ref(resource_ref: str) -> str:
    match = _WINDOW_REF_RE.fullmatch(resource_ref)
    if match is None:
        raise WindowsInteractionError("INVALID_WINDOWS_INTERACTION_RESOURCE_REF")
    return "0x" + match.group(1)[2:].upper()


def _strict_arguments(arguments: Mapping[str, Any], allowed: frozenset[str]) -> dict[str, Any]:
    if not isinstance(arguments, Mapping) or set(arguments) - allowed:
        raise WindowsInteractionError("WINDOWS_INTERACTION_ARGUMENT_NOT_ALLOWED")
    return dict(arguments)


def _command_from_action(action: ComputerActionRequest) -> WindowsInteractionCommand:
    window_id = _window_id_from_ref(action.resource_ref)
    arguments = dict(action.arguments)
    kind = arguments.get("interaction")

    if action.operation == "computer.keyboard.interact":
        if kind != "set_value":
            raise WindowsInteractionError("UNSUPPORTED_WINDOWS_KEYBOARD_INTERACTION")
        values = _strict_arguments(arguments, frozenset({"interaction", "automation_id", "text"}))
        automation_id = _automation_id(values.get("automation_id"))
        text = _bounded_text(
            values.get("text"),
            field="typed_text",
            limit=MAX_TYPED_TEXT_CHARS,
            allow_empty=True,
        )
        if action.expected_postcondition != "uia_value_set":
            raise WindowsInteractionError("WINDOWS_EXPECTED_POSTCONDITION_MISMATCH")
        return WindowsInteractionCommand(
            operation=action.operation,
            interaction_kind=kind,
            resource_ref=action.resource_ref,
            window_id=window_id,
            automation_id=automation_id,
            text=text,
        )

    if action.operation == "computer.pointer.interact":
        if kind == "invoke":
            values = _strict_arguments(
                arguments,
                frozenset({"interaction", "automation_id", "expected_visible_text"}),
            )
            automation_id = _automation_id(values.get("automation_id"))
            expected_visible_text = _bounded_text(
                values.get("expected_visible_text"),
                field="expected_visible_text",
                limit=MAX_EXPECTED_VISIBLE_TEXT_CHARS,
            )
            if action.expected_postcondition != "uia_text_visible":
                raise WindowsInteractionError("WINDOWS_EXPECTED_POSTCONDITION_MISMATCH")
            return WindowsInteractionCommand(
                operation=action.operation,
                interaction_kind=kind,
                resource_ref=action.resource_ref,
                window_id=window_id,
                automation_id=automation_id,
                expected_visible_text=expected_visible_text,
            )
        if kind == "select":
            values = _strict_arguments(arguments, frozenset({"interaction", "automation_id"}))
            automation_id = _automation_id(values.get("automation_id"))
            if action.expected_postcondition != "uia_item_selected":
                raise WindowsInteractionError("WINDOWS_EXPECTED_POSTCONDITION_MISMATCH")
            return WindowsInteractionCommand(
                operation=action.operation,
                interaction_kind=kind,
                resource_ref=action.resource_ref,
                window_id=window_id,
                automation_id=automation_id,
            )
        raise WindowsInteractionError("UNSUPPORTED_WINDOWS_POINTER_INTERACTION")

    raise WindowsInteractionError("UNSUPPORTED_GOVERNED_WINDOWS_OPERATION")


def _require_windows_pre_target(*, action: ComputerActionRequest, observation: ComputerObservation, command: WindowsInteractionCommand) -> int:
    structured = observation.structured_observation
    if observation.surface != "desktop" or structured.get("platform") != "windows":
        raise WindowsInteractionError("WINDOWS_INTERACTION_REQUIRES_WINDOWS_OBSERVATION")
    observed_window = structured.get("window_id")
    process_id = structured.get("process_id")
    if not isinstance(observed_window, str) or observed_window.upper() != command.window_id.upper():
        raise WindowsInteractionError("WINDOWS_INTERACTION_WINDOW_STALE")
    if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
        raise WindowsInteractionError("WINDOWS_INTERACTION_PROCESS_INVALID")
    expected_target = f"windows:window:{observed_window}/process:{process_id}"
    if observation.active_target_ref != expected_target:
        raise WindowsInteractionError("WINDOWS_INTERACTION_TARGET_IDENTITY_MISMATCH")
    if action.state_precondition_sha256 != observation.state_sha256:
        raise WindowsInteractionError("WINDOWS_INTERACTION_STATE_STALE")
    return process_id


def execute_governed_windows_action(
    *,
    action: ComputerActionRequest,
    pre_observation: ComputerObservation,
    capability_decision: Any,
    policy_decision: ComputerPolicyDecision,
    backend: WindowsInteractionBackend,
    replay_ledger: ComputerActionReplayLedger,
    approver_session_ref: str,
    now: str,
    approval: ComputerApprovalGrant,
    lease_repository: RuntimeWriterLeaseRepository,
    lease: RuntimeWriterLease,
    writer_binding: ComputerWriterBinding,
    user_takeover_active: bool = False,
) -> GovernedWindowsInteractionResult:
    """Execute one approved standard-user Windows UI Automation action.

    The model/provider may propose an action, but TaskContract capability authority,
    policy, approval, writer generation, target freshness, and postcondition remain
    authoritative. Sensitive inputs and user-takeover sessions fail closed.
    """

    action.validate()
    pre_observation.validate()
    policy_decision.validate()
    if not isinstance(user_takeover_active, bool):
        raise WindowsInteractionError("INVALID_WINDOWS_USER_TAKEOVER_STATE")
    if user_takeover_active:
        raise WindowsInteractionError("WINDOWS_USER_TAKEOVER_ACTIVE")
    if action.operation not in {"computer.pointer.interact", "computer.keyboard.interact"}:
        raise WindowsInteractionError("UNSUPPORTED_GOVERNED_WINDOWS_OPERATION")
    if action.expected_postcondition is None:
        raise WindowsInteractionError("WINDOWS_EXPECTED_POSTCONDITION_REQUIRED")

    require_target_fresh(action=action, observation=pre_observation)
    command = _command_from_action(action)
    expected_process_id = _require_windows_pre_target(
        action=action,
        observation=pre_observation,
        command=command,
    )

    derived_policy = decide_computer_action(action, capability_decision)
    if derived_policy.fingerprint != policy_decision.fingerprint:
        raise WindowsInteractionError("WINDOWS_POLICY_DECISION_MISMATCH")
    if policy_decision.outcome != "REQUIRE_APPROVAL":
        raise WindowsInteractionError("WINDOWS_ACTION_REQUIRES_APPROVAL_POLICY")

    inspection = backend.inspect_target(command, session_id=action.session_id, task_id=action.task_id)
    if not isinstance(inspection, WindowsTargetInspection):
        raise WindowsInteractionError("INVALID_WINDOWS_TARGET_INSPECTION")
    if inspection.state_sha256 != action.state_precondition_sha256:
        raise WindowsInteractionError("WINDOWS_TARGET_INSPECTION_STALE")
    if inspection.window_id.upper() != command.window_id.upper() or inspection.process_id != expected_process_id:
        raise WindowsInteractionError("WINDOWS_TARGET_FOCUS_STALE")
    if not inspection.is_enabled:
        raise WindowsInteractionError("WINDOWS_TARGET_DISABLED")
    if command.interaction_kind == "set_value" and inspection.secure_input:
        raise WindowsInteractionError("WINDOWS_SECURE_INPUT_USER_TAKEOVER_REQUIRED")

    require_valid_computer_approval(
        grant=approval,
        action=action,
        policy_decision=policy_decision,
        approver_session_ref=approver_session_ref,
        now=now,
    )
    require_current_writer_binding(
        action=action,
        binding=writer_binding,
        lease_repository=lease_repository,
        lease=lease,
    )
    replay_ledger.admit_once(action=action, observation=pre_observation)

    consumed_approval = consume_computer_approval(
        grant=approval,
        action=action,
        policy_decision=policy_decision,
        approver_session_ref=approver_session_ref,
        now=now,
    )
    require_current_writer_binding(
        action=action,
        binding=writer_binding,
        lease_repository=lease_repository,
        lease=lease,
    )

    try:
        backend_result = backend.dispatch(command, session_id=action.session_id, task_id=action.task_id)
    except Exception as exc:
        raise WindowsInteractionDispatchError(
            "WINDOWS_BACKEND_DISPATCH_FAILED",
            consumed_approval=consumed_approval,
        ) from exc
    if not isinstance(backend_result, WindowsInteractionBackendResult):
        raise WindowsInteractionDispatchError(
            "INVALID_WINDOWS_BACKEND_RESULT",
            consumed_approval=consumed_approval,
        )

    post = backend_result.post_observation
    post.validate()
    if post.task_id != action.task_id or post.session_id != action.session_id:
        raise WindowsInteractionDispatchError(
            "WINDOWS_POST_OBSERVATION_IDENTITY_MISMATCH",
            consumed_approval=consumed_approval,
        )
    post_window = post.structured_observation.get("window_id")
    post_process = post.structured_observation.get("process_id")
    if not isinstance(post_window, str) or post_window.upper() != command.window_id.upper() or post_process != expected_process_id:
        raise WindowsInteractionDispatchError(
            "WINDOWS_POST_TARGET_CHANGED",
            consumed_approval=consumed_approval,
        )
    if action.expected_postcondition not in backend_result.observed_postconditions:
        raise WindowsInteractionDispatchError(
            "WINDOWS_POSTCONDITION_NOT_SATISFIED",
            consumed_approval=consumed_approval,
        )
    return GovernedWindowsInteractionResult(
        backend_result=backend_result,
        consumed_approval=consumed_approval,
    )


class WindowsPowerShellInteractionBackend:
    """Fixed-script standard-user UI Automation backend.

    Dynamic values cross the Python/PowerShell boundary only through environment
    variables and are treated as data, never as PowerShell source. The backend has
    no process-start, shell passthrough, elevation, credential, registry, filesystem,
    or arbitrary command surface.
    """

    _SCRIPT = r'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class WorkSpaceCU170Foreground {
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint processId);
}
"@

$mode = [string]$env:WORKSPACE_CU170_MODE
$windowId = [string]$env:WORKSPACE_CU170_WINDOW_ID
$automationId = [string]$env:WORKSPACE_CU170_AUTOMATION_ID
if ($windowId -notmatch '^0x[0-9A-Fa-f]{1,16}$') { throw 'WINDOWS_INTERACTION_WINDOW_ID_INVALID' }
if ($automationId -notmatch '^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$') { throw 'WINDOWS_INTERACTION_AUTOMATION_ID_INVALID' }
$expected = [Int64]::Parse($windowId.Substring(2), [System.Globalization.NumberStyles]::HexNumber)
$hwnd = [WorkSpaceCU170Foreground]::GetForegroundWindow()
if ($hwnd -eq [IntPtr]::Zero -or $hwnd.ToInt64() -ne $expected) { throw 'WINDOWS_TARGET_FOCUS_STALE' }
[uint32]$pidValue = 0
[void][WorkSpaceCU170Foreground]::GetWindowThreadProcessId($hwnd, [ref]$pidValue)
if ($pidValue -le 0) { throw 'WINDOWS_FOREGROUND_PROCESS_NOT_FOUND' }
$root = [System.Windows.Automation.AutomationElement]::FromHandle($hwnd)
if ($null -eq $root) { throw 'WINDOWS_UIA_ROOT_NOT_FOUND' }
$condition = New-Object System.Windows.Automation.PropertyCondition(
  [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
  $automationId
)
$element = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $condition)
if ($null -eq $element) { throw 'WINDOWS_UIA_TARGET_NOT_FOUND' }
$current = $element.Current
$result = [ordered]@{
  process_id = [int]$pidValue
  secure_input = [bool]$current.IsPassword
  is_enabled = [bool]$current.IsEnabled
  control_type = [string]$current.ControlType.ProgrammaticName
  value_set = $false
  invoked = $false
  item_selected = $false
  expected_text_visible = $false
}

if ($mode -eq 'inspect') {
  $result | ConvertTo-Json -Compress
  exit 0
}
if (-not $current.IsEnabled) { throw 'WINDOWS_UIA_TARGET_DISABLED' }

if ($mode -eq 'set_value') {
  if ($current.IsPassword) { throw 'WINDOWS_SECURE_INPUT_USER_TAKEOVER_REQUIRED' }
  $pattern = $element.GetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern)
  $textBytes = [Convert]::FromBase64String([string]$env:WORKSPACE_CU170_TEXT_B64)
  $textValue = [Text.Encoding]::UTF8.GetString($textBytes)
  $pattern.SetValue($textValue)
  $result.value_set = ([string]$pattern.Current.Value -ceq $textValue)
} elseif ($mode -eq 'invoke') {
  $pattern = $element.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern)
  $pattern.Invoke()
  $result.invoked = $true
  Start-Sleep -Milliseconds 150
  $expectedBytes = [Convert]::FromBase64String([string]$env:WORKSPACE_CU170_EXPECTED_TEXT_B64)
  $expectedText = [Text.Encoding]::UTF8.GetString($expectedBytes)
  $nameCondition = New-Object System.Windows.Automation.PropertyCondition(
    [System.Windows.Automation.AutomationElement]::NameProperty,
    $expectedText
  )
  $visible = $root.FindFirst([System.Windows.Automation.TreeScope]::Descendants, $nameCondition)
  $result.expected_text_visible = ($null -ne $visible)
} elseif ($mode -eq 'select') {
  $pattern = $element.GetCurrentPattern([System.Windows.Automation.SelectionItemPattern]::Pattern)
  $pattern.Select()
  $result.item_selected = [bool]$pattern.Current.IsSelected
} else {
  throw 'WINDOWS_INTERACTION_MODE_NOT_ALLOWED'
}
$result | ConvertTo-Json -Compress
'''

    def __init__(
        self,
        *,
        observation_backend: WindowsPowerShellObservationBackend | None = None,
        observation_config: WindowsObservationConfig | None = None,
        powershell_executable: str = "powershell.exe",
        timeout_seconds: int = 15,
    ) -> None:
        if not isinstance(powershell_executable, str) or not powershell_executable.strip():
            raise WindowsInteractionError("INVALID_WINDOWS_INTERACTION_POWERSHELL")
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 60:
            raise WindowsInteractionError("INVALID_WINDOWS_INTERACTION_TIMEOUT")
        self._observation_backend = observation_backend or WindowsPowerShellObservationBackend(timeout_seconds=timeout_seconds)
        self._observation_config = observation_config or WindowsObservationConfig(max_uia_nodes=64, max_uia_depth=5)
        self._powershell_executable = powershell_executable
        self._timeout_seconds = timeout_seconds

    def _capture(self, *, session_id: str, task_id: str) -> ComputerObservation:
        return capture_windows_observation(
            config=self._observation_config,
            backend=self._observation_backend,
            session_id=session_id,
            task_id=task_id,
        )

    def _run_script(self, command: WindowsInteractionCommand, *, mode: str) -> Mapping[str, Any]:
        if os.name != "nt":
            raise WindowsInteractionError("WINDOWS_INTERACTION_BACKEND_REQUIRES_WINDOWS")
        env = os.environ.copy()
        env["WORKSPACE_CU170_MODE"] = mode
        env["WORKSPACE_CU170_WINDOW_ID"] = command.window_id
        env["WORKSPACE_CU170_AUTOMATION_ID"] = command.automation_id
        env["WORKSPACE_CU170_TEXT_B64"] = base64.b64encode((command.text or "").encode("utf-8")).decode("ascii")
        env["WORKSPACE_CU170_EXPECTED_TEXT_B64"] = base64.b64encode(
            (command.expected_visible_text or "").encode("utf-8")
        ).decode("ascii")
        try:
            completed = subprocess.run(
                [
                    self._powershell_executable,
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    self._SCRIPT,
                ],
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
            raise WindowsInteractionError("WINDOWS_INTERACTION_BACKEND_FAILED")
        if len(completed.stdout.encode("utf-8")) > 16 * 1024:
            raise WindowsInteractionError("WINDOWS_INTERACTION_BACKEND_OUTPUT_BOUND_EXCEEDED")
        try:
            payload = json.loads(completed.stdout)
        except (TypeError, json.JSONDecodeError) as exc:
            raise WindowsInteractionError("WINDOWS_INTERACTION_BACKEND_INVALID_JSON") from exc
        if not isinstance(payload, Mapping):
            raise WindowsInteractionError("WINDOWS_INTERACTION_BACKEND_OUTPUT_MUST_BE_OBJECT")
        return payload

    def inspect_target(
        self,
        command: WindowsInteractionCommand,
        *,
        session_id: str,
        task_id: str,
    ) -> WindowsTargetInspection:
        before = self._capture(session_id=session_id, task_id=task_id)
        payload = self._run_script(command, mode="inspect")
        after = self._capture(session_id=session_id, task_id=task_id)
        if before.state_sha256 != after.state_sha256:
            raise WindowsInteractionError("WINDOWS_TARGET_CHANGED_DURING_INSPECTION")
        window_id = after.structured_observation.get("window_id")
        process_id = payload.get("process_id")
        if not isinstance(window_id, str):
            raise WindowsInteractionError("WINDOWS_INTERACTION_WINDOW_ID_MISSING")
        if isinstance(process_id, bool) or not isinstance(process_id, int) or process_id <= 0:
            raise WindowsInteractionError("WINDOWS_INTERACTION_PROCESS_ID_INVALID")
        secure_input = payload.get("secure_input")
        is_enabled = payload.get("is_enabled")
        control_type = payload.get("control_type")
        if not isinstance(secure_input, bool) or not isinstance(is_enabled, bool) or not isinstance(control_type, str):
            raise WindowsInteractionError("WINDOWS_INTERACTION_INSPECTION_INVALID")
        return WindowsTargetInspection(
            state_sha256=after.state_sha256,
            window_id=window_id,
            process_id=process_id,
            secure_input=secure_input,
            is_enabled=is_enabled,
            control_type=control_type,
        )

    def dispatch(
        self,
        command: WindowsInteractionCommand,
        *,
        session_id: str,
        task_id: str,
    ) -> WindowsInteractionBackendResult:
        payload = self._run_script(command, mode=command.interaction_kind)
        observed: list[str] = []
        if command.interaction_kind == "set_value" and payload.get("value_set") is True:
            observed.append("uia_value_set")
        if command.interaction_kind == "invoke" and payload.get("expected_text_visible") is True:
            observed.append("uia_text_visible")
        if command.interaction_kind == "select" and payload.get("item_selected") is True:
            observed.append("uia_item_selected")
        post = self._capture(session_id=session_id, task_id=task_id)
        return WindowsInteractionBackendResult(
            post_observation=post,
            observed_postconditions=tuple(observed),
            result={
                "interaction_kind": command.interaction_kind,
                "verified": bool(observed),
            },
        )
