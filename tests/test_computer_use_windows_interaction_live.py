from __future__ import annotations

import ctypes
import hashlib
import os
import subprocess
import tempfile
import time
import unittest
from ctypes import wintypes
from pathlib import Path

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.computer_use import ComputerActionRequest, decide_computer_action
from three_agent.computer_use_approval import issue_computer_approval
from three_agent.computer_use_replay import ComputerActionReplayLedger
from three_agent.computer_use_windows_interaction import execute_governed_windows_action
from three_agent.computer_use_windows_interaction_powershell import WindowsPowerShellInteractionBackend
from three_agent.computer_use_windows_observation import (
    WindowsObservationConfig,
    WindowsPowerShellObservationBackend,
    capture_windows_observation,
)
from three_agent.computer_use_writer import bind_current_writer
from three_agent.runtime_writer_lease import RuntimeWriterLeaseRepository
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


FORM_TITLE = "WorkSpace CU-170 Acceptance Window"
VALUE_AUTOMATION_ID = "ValueBox"
BUTTON_AUTOMATION_ID = "InvokeButton"
VALUE_TEXT = "workspace-cu170-live-value"
STARTUP_TIMEOUT_SECONDS = 45


def sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


@unittest.skipUnless(os.name == "nt", "live Windows interaction acceptance requires Windows")
class WindowsInteractionLiveAcceptanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = rf'''
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase

$window = New-Object System.Windows.Window
$window.Title = "{FORM_TITLE}"
$window.Width = 680
$window.Height = 280
$window.Topmost = $true

$panel = New-Object System.Windows.Controls.StackPanel
$panel.Margin = New-Object System.Windows.Thickness(24)

$text = New-Object System.Windows.Controls.TextBox
$text.Text = "before"
$text.Height = 32
$text.Margin = New-Object System.Windows.Thickness(0,0,0,18)
[System.Windows.Automation.AutomationProperties]::SetAutomationId($text, "{VALUE_AUTOMATION_ID}")
$panel.Children.Add($text) | Out-Null

$button = New-Object System.Windows.Controls.Button
$button.Content = "Invoke"
$button.Width = 160
$button.Height = 32
$button.HorizontalAlignment = "Left"
[System.Windows.Automation.AutomationProperties]::SetAutomationId($button, "{BUTTON_AUTOMATION_ID}")
$button.Add_Click({{ $window.Title = "{FORM_TITLE} INVOKED" }})
$panel.Children.Add($button) | Out-Null

$window.Content = $panel
$window.Add_ContentRendered({{ $window.Activate() }})
[void]$window.ShowDialog()
'''
        cls._process = subprocess.Popen(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-STA", "-Command", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls._hwnd = cls._wait_for_window(
            FORM_TITLE,
            timeout_seconds=STARTUP_TIMEOUT_SECONDS,
            process=cls._process,
        )
        if not cls._hwnd:
            returncode = cls._process.poll()
            if returncode is None:
                cls._terminate_process()
                raise RuntimeError(
                    f"CU170_ACCEPTANCE_WINDOW_START_TIMEOUT:{STARTUP_TIMEOUT_SECONDS}s"
                )
            stderr = ""
            if cls._process.stderr is not None:
                stderr = cls._process.stderr.read()
            raise RuntimeError(
                f"CU170_ACCEPTANCE_FIXTURE_EXITED:rc={returncode};stderr={stderr[:1000]}"
            )
        cls._focus_window(cls._hwnd)

    @classmethod
    def tearDownClass(cls):
        cls._terminate_process()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tmp.name) / "workspace.sqlite3")
        self.store.initialize()
        self.task = self.store.create_task("windows interaction live", "verify governed native Windows UIA mutation")
        self.plan = sha("cu170-live-plan")
        self.repo = RuntimeWriterLeaseRepository(self.store)
        self.repo.initialize()
        self.observation_backend = WindowsPowerShellObservationBackend(timeout_seconds=20)
        self.interaction_backend = WindowsPowerShellInteractionBackend(
            timeout_seconds=20,
            observation_backend=self.observation_backend,
            observation_config=WindowsObservationConfig(max_uia_nodes=64, max_uia_depth=5),
        )

    def tearDown(self):
        self.tmp.cleanup()

    @classmethod
    def _terminate_process(cls):
        process = getattr(cls, "_process", None)
        if process is None or process.poll() is not None:
            return
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)

    @staticmethod
    def _wait_for_window(
        title: str,
        *,
        timeout_seconds: int,
        process: subprocess.Popen,
    ) -> int:
        user32 = ctypes.windll.user32
        found = {"hwnd": 0}
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def enum_callback(hwnd, _lparam):
            length = user32.GetWindowTextLengthW(hwnd)
            if length <= 0:
                return True
            buffer = ctypes.create_unicode_buffer(length + 1)
            user32.GetWindowTextW(hwnd, buffer, length + 1)
            if buffer.value == title:
                found["hwnd"] = int(hwnd)
                return False
            return True

        callback = callback_type(enum_callback)
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return 0
            found["hwnd"] = 0
            user32.EnumWindows(callback, 0)
            if found["hwnd"]:
                return found["hwnd"]
            time.sleep(0.25)
        return 0

    @staticmethod
    def _focus_window(hwnd: int) -> None:
        user32 = ctypes.windll.user32
        user32.ShowWindow(wintypes.HWND(hwnd), 9)
        user32.BringWindowToTop(wintypes.HWND(hwnd))
        if not user32.SetForegroundWindow(wintypes.HWND(hwnd)):
            raise RuntimeError("CU170_ACCEPTANCE_SET_FOREGROUND_FAILED")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if int(user32.GetForegroundWindow()) == hwnd:
                return
            time.sleep(0.1)
        raise RuntimeError("CU170_ACCEPTANCE_FOREGROUND_NOT_CONFIRMED")

    @staticmethod
    def _window_text(hwnd: int) -> str:
        user32 = ctypes.windll.user32
        length = user32.GetWindowTextLengthW(wintypes.HWND(hwnd))
        buffer = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(wintypes.HWND(hwnd), buffer, length + 1)
        return buffer.value

    @staticmethod
    def _read_value(hwnd: int) -> str:
        script = rf'''
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$root = [System.Windows.Automation.AutomationElement]::FromHandle([IntPtr]{hwnd})
$condition = [System.Windows.Automation.PropertyCondition]::new(
  [System.Windows.Automation.AutomationElement]::AutomationIdProperty,
  '{VALUE_AUTOMATION_ID}'
)
$matches = $root.FindAll([System.Windows.Automation.TreeScope]::Descendants, $condition)
if ($matches.Count -ne 1) {{ throw 'CU170_VALUE_TARGET_NOT_UNIQUE' }}
$element = $matches.Item(0)
$pattern = $null
if (-not $element.TryGetCurrentPattern([System.Windows.Automation.ValuePattern]::Pattern, [ref]$pattern)) {{
  throw 'CU170_VALUE_PATTERN_UNAVAILABLE'
}}
([System.Windows.Automation.ValuePattern]$pattern).Current.Value
'''
        completed = subprocess.run(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-STA", "-Command", script],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            raise RuntimeError(f"CU170_VALUE_READ_FAILED: {completed.stderr[-1000:]}")
        return completed.stdout.strip()

    def _observe(self):
        self._focus_window(self._hwnd)
        return capture_windows_observation(
            config=WindowsObservationConfig(max_uia_nodes=64, max_uia_depth=5),
            backend=self.observation_backend,
            session_id="session:cu170-live",
            task_id=self.task.task_id,
        )

    def _execute(self, *, interaction: str, automation_id: str, control_type: str, value: str | None = None, action_id: str):
        pre = self._observe()
        window_id = pre.structured_observation["window_id"]
        arguments = {
            "interaction": interaction,
            "automation_id": automation_id,
            "control_type": control_type,
        }
        if value is not None:
            arguments["value"] = value
        expected = {
            "invoke": "WINDOWS_UIA_INVOKED",
            "value": "WINDOWS_UIA_VALUE_SET",
        }[interaction]
        action = ComputerActionRequest(
            session_id="session:cu170-live",
            action_id=action_id,
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            node_id="node:cu170-live",
            operation="computer.accessibility.interact",
            effect="write",
            resource_kind="accessibility_target",
            resource_ref=f"local:desktop:window:{window_id}",
            arguments=arguments,
            state_precondition_sha256=pre.state_sha256,
            idempotency_key=sha("idem:" + action_id),
            risk_class="R2_STATE_CHANGE",
            requires_writer=True,
            expected_postcondition=expected,
        ).validate()
        contract = TaskContractCompiler().compile(
            task_id=self.task.task_id,
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("computer.accessibility.interact",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        capability = authority.require(
            action.operation,
            resource_kind=action.resource_kind,
            resource_ref=action.resource_ref,
            effect=action.effect,
        )
        policy = decide_computer_action(action, capability)
        self.assertEqual(policy.outcome, "REQUIRE_APPROVAL")
        grant = issue_computer_approval(
            approval_id="approval:" + action_id.replace(":", "-"),
            action=action,
            policy_decision=policy,
            approver_session_ref="user-session:cu170-live",
            scope="one_shot",
            issued_at="2026-09-10T00:00:00Z",
            expires_at="2026-09-10T00:10:00Z",
        )
        lease = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-CU170-LIVE-" + action_id.replace(":", "-"),
            issued_at="2026-09-10T00:00:00Z",
        )
        binding = bind_current_writer(action=action, lease_repository=self.repo, lease=lease)
        result = execute_governed_windows_action(
            action=action,
            pre_observation=pre,
            capability_decision=capability,
            policy_decision=policy,
            backend=self.interaction_backend,
            replay_ledger=ComputerActionReplayLedger(),
            approver_session_ref="user-session:cu170-live",
            now="2026-09-10T00:01:00Z",
            approval=grant,
            lease_repository=self.repo,
            lease=lease,
            writer_binding=binding,
            user_takeover_active=False,
        )
        self.assertEqual(result.consumed_approval.status, "CONSUMED")
        self.assertIn(expected, result.backend_result.observed_postconditions)
        self.assertEqual(result.backend_result.post_observation.surface, "desktop")
        return result

    def test_live_value_pattern_changes_real_wpf_textbox(self):
        self._execute(
            interaction="value",
            automation_id=VALUE_AUTOMATION_ID,
            control_type="ControlType.Edit",
            value=VALUE_TEXT,
            action_id="action:cu170-live-value",
        )
        self.assertEqual(self._read_value(self._hwnd), VALUE_TEXT)

    def test_live_invoke_pattern_triggers_real_wpf_button(self):
        self._execute(
            interaction="invoke",
            automation_id=BUTTON_AUTOMATION_ID,
            control_type="ControlType.Button",
            action_id="action:cu170-live-invoke",
        )
        deadline = time.monotonic() + 5
        expected_title = FORM_TITLE + " INVOKED"
        while time.monotonic() < deadline:
            if self._window_text(self._hwnd) == expected_title:
                return
            time.sleep(0.1)
        self.fail(f"InvokePattern did not trigger the WPF button; title={self._window_text(self._hwnd)!r}")


if __name__ == "__main__":
    unittest.main()
