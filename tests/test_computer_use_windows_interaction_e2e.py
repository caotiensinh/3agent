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
from three_agent.computer_use import ComputerActionRequest, ComputerObservation, decide_computer_action
from three_agent.computer_use_approval import issue_computer_approval
from three_agent.computer_use_replay import ComputerActionReplayLedger
from three_agent.computer_use_windows_interaction import (
    WindowsInteractionBackendResult,
    WindowsInteractionCommand,
    WindowsInteractionError,
    WindowsTargetInspection,
    WindowsPowerShellInteractionBackend,
    execute_governed_windows_action,
)
from three_agent.computer_use_windows_observation import (
    WindowsObservationConfig,
    WindowsPowerShellObservationBackend,
    capture_windows_observation,
)
from three_agent.computer_use_writer import bind_current_writer
from three_agent.runtime_writer_lease import RuntimeWriterLeaseRepository
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


def sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def contains_uia_name(value, expected: str) -> bool:
    if not isinstance(value, dict):
        return False
    if value.get("name") == expected:
        return True
    children = value.get("children")
    if not isinstance(children, list):
        return False
    return any(contains_uia_name(child, expected) for child in children)


class FakeWindowsInteractionBackend:
    def __init__(self, inspection: WindowsTargetInspection, result: WindowsInteractionBackendResult):
        self.inspection = inspection
        self.result = result
        self.inspections: list[WindowsInteractionCommand] = []
        self.dispatches: list[WindowsInteractionCommand] = []

    def inspect_target(self, command, *, session_id, task_id):
        self.inspections.append(command)
        return self.inspection

    def dispatch(self, command, *, session_id, task_id):
        self.dispatches.append(command)
        return self.result


class GovernedWindowsInteractionBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tmp.name) / "workspace.sqlite3")
        self.store.initialize()
        self.task = self.store.create_task("windows interaction", "govern one Windows UI action")
        self.plan = sha("cu170-plan")
        self.state = sha("cu170-state")
        self.window_id = "0x1234"
        self.process_id = 4321
        self.session_id = "session:cu170"
        self.resource_ref = f"local:desktop:window:{self.window_id}"
        self.writer_repo = RuntimeWriterLeaseRepository(self.store)
        self.writer_repo.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def observation(self, *, state=None):
        return ComputerObservation(
            session_id=self.session_id,
            task_id=self.task.task_id,
            state_id="state:cu170",
            state_sha256=state or self.state,
            surface="desktop",
            active_target_ref=f"windows:window:{self.window_id}/process:{self.process_id}",
            captured_at="2026-09-10T00:00:00Z",
            structured_observation={
                "platform": "windows",
                "window_id": self.window_id,
                "process_id": self.process_id,
                "process_name": "fixture",
                "metadata": {},
                "accessibility": {},
            },
        ).validate()

    def action(self):
        return ComputerActionRequest(
            session_id=self.session_id,
            action_id="action:cu170-set-value",
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            node_id="node:cu170",
            operation="computer.keyboard.interact",
            effect="write",
            resource_kind="keyboard_target",
            resource_ref=self.resource_ref,
            arguments={"interaction": "set_value", "automation_id": "InputBox", "text": "safe text"},
            state_precondition_sha256=self.state,
            idempotency_key=sha("idem:cu170-set-value"),
            risk_class="R2_STATE_CHANGE",
            requires_writer=True,
            expected_postcondition="uia_value_set",
        ).validate()

    def authority(self, action):
        contract = TaskContractCompiler().compile(
            task_id=self.task.task_id,
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=(action.operation,),
        )
        capability = TaskCapabilityAuthority.from_contract(contract).require(
            action.operation,
            resource_kind=action.resource_kind,
            resource_ref=action.resource_ref,
            effect=action.effect,
        )
        return capability, decide_computer_action(action, capability)

    def approval(self, action, policy):
        return issue_computer_approval(
            approval_id="approval:cu170",
            action=action,
            policy_decision=policy,
            approver_session_ref="user-session:cu170",
            scope="one_shot",
            issued_at="2026-09-10T00:00:00Z",
            expires_at="2026-09-10T00:05:00Z",
        )

    def writer(self, action):
        lease = self.writer_repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-CU170",
            issued_at="2026-09-10T00:00:00Z",
        )
        return lease, bind_current_writer(action=action, lease_repository=self.writer_repo, lease=lease)

    def safe_backend(self, *, secure=False, inspection_state=None):
        post = ComputerObservation(
            session_id=self.session_id,
            task_id=self.task.task_id,
            state_id="state:cu170:post",
            state_sha256=sha("cu170-post"),
            surface="desktop",
            active_target_ref=f"windows:window:{self.window_id}/process:{self.process_id}",
            captured_at="2026-09-10T00:00:01Z",
            structured_observation={
                "platform": "windows",
                "window_id": self.window_id,
                "process_id": self.process_id,
                "process_name": "fixture",
                "metadata": {},
                "accessibility": {},
            },
        ).validate()
        return FakeWindowsInteractionBackend(
            WindowsTargetInspection(
                state_sha256=inspection_state or self.state,
                window_id=self.window_id,
                process_id=self.process_id,
                secure_input=secure,
                is_enabled=True,
                control_type="ControlType.Edit",
            ),
            WindowsInteractionBackendResult(
                post_observation=post,
                observed_postconditions=("uia_value_set",),
                result={"verified": True},
            ),
        )

    def execute(self, *, user_takeover_active=False, backend=None):
        action = self.action()
        capability, policy = self.authority(action)
        approval = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = backend or self.safe_backend()
        result = execute_governed_windows_action(
            action=action,
            pre_observation=self.observation(),
            capability_decision=capability,
            policy_decision=policy,
            backend=backend,
            replay_ledger=ComputerActionReplayLedger(),
            approver_session_ref="user-session:cu170",
            now="2026-09-10T00:01:00Z",
            approval=approval,
            lease_repository=self.writer_repo,
            lease=lease,
            writer_binding=binding,
            user_takeover_active=user_takeover_active,
        )
        return result, backend

    def test_valid_action_consumes_approval_and_dispatches_once(self):
        result, backend = self.execute()
        self.assertEqual(result.consumed_approval.status, "CONSUMED")
        self.assertEqual(len(backend.inspections), 1)
        self.assertEqual(len(backend.dispatches), 1)
        self.assertEqual(backend.dispatches[0].interaction_kind, "set_value")

    def test_user_takeover_blocks_before_inspection_and_dispatch(self):
        backend = self.safe_backend()
        with self.assertRaisesRegex(WindowsInteractionError, "WINDOWS_USER_TAKEOVER_ACTIVE"):
            self.execute(user_takeover_active=True, backend=backend)
        self.assertEqual(backend.inspections, [])
        self.assertEqual(backend.dispatches, [])

    def test_stale_inspection_blocks_before_dispatch(self):
        backend = self.safe_backend(inspection_state=sha("newer-state"))
        with self.assertRaisesRegex(WindowsInteractionError, "WINDOWS_TARGET_INSPECTION_STALE"):
            self.execute(backend=backend)
        self.assertEqual(len(backend.inspections), 1)
        self.assertEqual(backend.dispatches, [])

    def test_secure_input_requires_user_takeover(self):
        backend = self.safe_backend(secure=True)
        with self.assertRaisesRegex(WindowsInteractionError, "WINDOWS_SECURE_INPUT_USER_TAKEOVER_REQUIRED"):
            self.execute(backend=backend)
        self.assertEqual(backend.dispatches, [])


WINDOW_TITLE = "WorkSpace CU-170 E2E Window"
E2E_TEXT = "CU-170 E2E VERIFIED"


@unittest.skipUnless(os.name == "nt", "live Windows interaction E2E requires Windows")
class WindowsInteractionLiveE2ETests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        script = rf'''
Add-Type -AssemblyName System.Windows.Forms
$form = New-Object System.Windows.Forms.Form
$form.Text = "{WINDOW_TITLE}"
$form.Width = 700
$form.Height = 300
$form.TopMost = $true

$textbox = New-Object System.Windows.Forms.TextBox
$textbox.Name = "InputBox"
$textbox.Left = 24
$textbox.Top = 35
$textbox.Width = 420
$form.Controls.Add($textbox)

$button = New-Object System.Windows.Forms.Button
$button.Name = "ApplyButton"
$button.Text = "Apply"
$button.Left = 24
$button.Top = 85
$button.Width = 100
$form.Controls.Add($button)

$status = New-Object System.Windows.Forms.Label
$status.Name = "StatusLabel"
$status.Text = "WAITING"
$status.AutoSize = $true
$status.Left = 24
$status.Top = 145
$form.Controls.Add($status)

$button.Add_Click({{ $status.Text = $textbox.Text }})
$form.Add_Shown({{ $form.Activate() }})
[System.Windows.Forms.Application]::Run($form)
'''
        cls._process = subprocess.Popen(
            ["powershell.exe", "-NoLogo", "-NoProfile", "-STA", "-Command", script],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        cls._hwnd = cls._wait_for_window(WINDOW_TITLE, timeout_seconds=15)
        if not cls._hwnd:
            stderr = ""
            if cls._process.poll() is not None and cls._process.stderr is not None:
                stderr = cls._process.stderr.read()
            cls._terminate_process()
            raise RuntimeError(f"CU170_E2E_WINDOW_NOT_FOUND: {stderr[:1000]}")
        cls._focus_window(cls._hwnd)

    @classmethod
    def tearDownClass(cls):
        cls._terminate_process()

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
    def _wait_for_window(title, *, timeout_seconds):
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
            found["hwnd"] = 0
            user32.EnumWindows(callback, 0)
            if found["hwnd"]:
                return found["hwnd"]
            time.sleep(0.25)
        return 0

    @staticmethod
    def _focus_window(hwnd):
        user32 = ctypes.windll.user32
        user32.ShowWindow(wintypes.HWND(hwnd), 9)
        user32.BringWindowToTop(wintypes.HWND(hwnd))
        if not user32.SetForegroundWindow(wintypes.HWND(hwnd)):
            raise RuntimeError("CU170_E2E_SET_FOREGROUND_FAILED")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if int(user32.GetForegroundWindow()) == hwnd:
                return
            time.sleep(0.1)
        raise RuntimeError("CU170_E2E_FOREGROUND_NOT_CONFIRMED")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tmp.name) / "workspace.sqlite3")
        self.store.initialize()
        self.task = self.store.create_task("CU-170 E2E", "set text and invoke one local test button")
        self.plan = sha("cu170-e2e-plan")
        self.session_id = "session:cu170-e2e"
        self.approver = "user-session:cu170-e2e"
        self.writer_repo = RuntimeWriterLeaseRepository(self.store)
        self.writer_repo.initialize()
        self.observation_config = WindowsObservationConfig(max_uia_nodes=64, max_uia_depth=5)
        self.observation_backend = WindowsPowerShellObservationBackend(timeout_seconds=20)
        self.backend = WindowsPowerShellInteractionBackend(
            observation_backend=self.observation_backend,
            observation_config=self.observation_config,
            timeout_seconds=20,
        )
        self._focus_window(self._hwnd)

    def tearDown(self):
        self.tmp.cleanup()

    def capture(self):
        self._focus_window(self._hwnd)
        return capture_windows_observation(
            config=self.observation_config,
            backend=self.observation_backend,
            session_id=self.session_id,
            task_id=self.task.task_id,
        )

    def authority(self, action):
        contract = TaskContractCompiler().compile(
            task_id=self.task.task_id,
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("computer.keyboard.interact", "computer.pointer.interact"),
        )
        capability = TaskCapabilityAuthority.from_contract(contract).require(
            action.operation,
            resource_kind=action.resource_kind,
            resource_ref=action.resource_ref,
            effect=action.effect,
        )
        return capability, decide_computer_action(action, capability)

    def approval(self, action, policy, suffix):
        return issue_computer_approval(
            approval_id=f"approval:cu170-e2e-{suffix}",
            action=action,
            policy_decision=policy,
            approver_session_ref=self.approver,
            scope="one_shot",
            issued_at="2026-09-10T00:00:00Z",
            expires_at="2026-09-10T00:10:00Z",
        )

    def test_governed_uia_value_then_invoke_changes_live_window(self):
        pre_text = self.capture()
        window_id = pre_text.structured_observation["window_id"]
        resource_ref = f"local:desktop:window:{window_id}"

        text_action = ComputerActionRequest(
            session_id=self.session_id,
            action_id="action:cu170-live-set-value",
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            node_id="node:cu170-text",
            operation="computer.keyboard.interact",
            effect="write",
            resource_kind="keyboard_target",
            resource_ref=resource_ref,
            arguments={"interaction": "set_value", "automation_id": "InputBox", "text": E2E_TEXT},
            state_precondition_sha256=pre_text.state_sha256,
            idempotency_key=sha("idem:cu170-live-set-value"),
            risk_class="R2_STATE_CHANGE",
            requires_writer=True,
            expected_postcondition="uia_value_set",
        ).validate()
        text_capability, text_policy = self.authority(text_action)
        text_approval = self.approval(text_action, text_policy, "text")
        lease = self.writer_repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-CU170-E2E",
            issued_at="2026-09-10T00:00:00Z",
        )
        text_binding = bind_current_writer(action=text_action, lease_repository=self.writer_repo, lease=lease)
        text_result = execute_governed_windows_action(
            action=text_action,
            pre_observation=pre_text,
            capability_decision=text_capability,
            policy_decision=text_policy,
            backend=self.backend,
            replay_ledger=ComputerActionReplayLedger(),
            approver_session_ref=self.approver,
            now="2026-09-10T00:01:00Z",
            approval=text_approval,
            lease_repository=self.writer_repo,
            lease=lease,
            writer_binding=text_binding,
        )
        self.assertEqual(text_result.consumed_approval.status, "CONSUMED")
        self.assertIn("uia_value_set", text_result.backend_result.observed_postconditions)

        pre_click = text_result.backend_result.post_observation
        click_action = ComputerActionRequest(
            session_id=self.session_id,
            action_id="action:cu170-live-invoke",
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            node_id="node:cu170-click",
            operation="computer.pointer.interact",
            effect="write",
            resource_kind="pointer_target",
            resource_ref=resource_ref,
            arguments={
                "interaction": "invoke",
                "automation_id": "ApplyButton",
                "expected_visible_text": E2E_TEXT,
            },
            state_precondition_sha256=pre_click.state_sha256,
            idempotency_key=sha("idem:cu170-live-invoke"),
            risk_class="R2_STATE_CHANGE",
            requires_writer=True,
            expected_postcondition="uia_text_visible",
        ).validate()
        click_capability, click_policy = self.authority(click_action)
        click_approval = self.approval(click_action, click_policy, "click")
        click_binding = bind_current_writer(action=click_action, lease_repository=self.writer_repo, lease=lease)
        click_result = execute_governed_windows_action(
            action=click_action,
            pre_observation=pre_click,
            capability_decision=click_capability,
            policy_decision=click_policy,
            backend=self.backend,
            replay_ledger=ComputerActionReplayLedger(),
            approver_session_ref=self.approver,
            now="2026-09-10T00:02:00Z",
            approval=click_approval,
            lease_repository=self.writer_repo,
            lease=lease,
            writer_binding=click_binding,
        )
        self.assertEqual(click_result.consumed_approval.status, "CONSUMED")
        self.assertIn("uia_text_visible", click_result.backend_result.observed_postconditions)
        self.assertTrue(
            contains_uia_name(
                click_result.backend_result.post_observation.structured_observation["accessibility"],
                E2E_TEXT,
            )
        )


if __name__ == "__main__":
    unittest.main()
