from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.computer_use import ComputerActionRequest, ComputerObservation, decide_computer_action
from three_agent.computer_use_approval import issue_computer_approval
from three_agent.computer_use_replay import ComputerActionReplayLedger
from three_agent.computer_use_windows_interaction import (
    WindowsDispatchError,
    WindowsInteractionBackendResult,
    WindowsInteractionCommand,
    WindowsInteractionError,
    WindowsTargetInspection,
    execute_governed_windows_action,
)
from three_agent.computer_use_windows_interaction_powershell import WindowsPowerShellInteractionBackend
from three_agent.computer_use_writer import bind_current_writer
from three_agent.runtime_writer_lease import RuntimeWriterLeaseRepository
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


def sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class FakeWindowsBackend:
    def __init__(self, *, inspection: WindowsTargetInspection, result: WindowsInteractionBackendResult | None = None):
        self.inspection = inspection
        self.result = result
        self.inspections: list[WindowsInteractionCommand] = []
        self.commands: list[WindowsInteractionCommand] = []

    def inspect_target(self, command: WindowsInteractionCommand) -> WindowsTargetInspection:
        self.inspections.append(command)
        return self.inspection

    def dispatch(self, command: WindowsInteractionCommand) -> WindowsInteractionBackendResult:
        self.commands.append(command)
        if self.result is None:
            raise AssertionError("unexpected dispatch")
        return self.result


class GovernedWindowsInteractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tmp.name) / "workspace.sqlite3")
        self.store.initialize()
        self.task = self.store.create_task("windows interaction", "govern one bounded Windows UI action")
        self.plan = sha("windows-plan")
        self.state = sha("windows-state")
        self.window_id = "0x1234ABCD"
        self.process_id = 4242
        self.process_name = "notepad"
        self.target_ref = f"windows:window:{self.window_id}/process:{self.process_id}"
        self.resource_ref = f"local:desktop:window:{self.window_id}"
        self.repo = RuntimeWriterLeaseRepository(self.store)
        self.repo.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def observation(self, *, state: str | None = None, window_id: str | None = None) -> ComputerObservation:
        window = window_id or self.window_id
        target = f"windows:window:{window}/process:{self.process_id}"
        return ComputerObservation(
            session_id="session:windows",
            task_id=self.task.task_id,
            state_id="state:windows",
            state_sha256=state or self.state,
            surface="desktop",
            active_target_ref=target,
            captured_at="2026-09-10T00:00:00Z",
            structured_observation={
                "platform": "windows",
                "window_id": window,
                "process_id": self.process_id,
                "process_name": self.process_name,
                "metadata": {"window_title": "Fixture"},
                "accessibility": {
                    "automation_id": "Root",
                    "control_type": "ControlType.Window",
                    "name": "Fixture",
                    "is_enabled": True,
                    "is_offscreen": False,
                    "is_password": False,
                    "children": [
                        {
                            "automation_id": "SaveButton",
                            "control_type": "ControlType.Button",
                            "name": "Save",
                            "is_enabled": True,
                            "is_offscreen": False,
                            "is_password": False,
                            "children": [],
                        },
                        {
                            "automation_id": "ValueBox",
                            "control_type": "ControlType.Edit",
                            "name": "Value",
                            "is_enabled": True,
                            "is_offscreen": False,
                            "is_password": False,
                            "children": [],
                        },
                    ],
                },
            },
        ).validate()

    def post(self) -> ComputerObservation:
        return ComputerObservation(
            session_id="session:windows",
            task_id=self.task.task_id,
            state_id="state:windows:post",
            state_sha256=sha("windows-post"),
            surface="desktop",
            active_target_ref=self.target_ref,
            captured_at="2026-09-10T00:00:01Z",
            structured_observation={
                "platform": "windows",
                "window_id": self.window_id,
                "process_id": self.process_id,
                "process_name": self.process_name,
                "metadata": {},
                "accessibility": {},
            },
        ).validate()

    def action(self, *, operation="computer.accessibility.interact", arguments=None, expected=None, action_id="action:uia"):
        if arguments is None:
            arguments = {
                "interaction": "invoke",
                "automation_id": "SaveButton",
                "control_type": "ControlType.Button",
            }
        expected = expected or {
            "computer.accessibility.interact": "WINDOWS_UIA_INVOKED",
            "computer.pointer.interact": "WINDOWS_POINTER_CLICK_SENT",
            "computer.keyboard.interact": "WINDOWS_KEYBOARD_TEXT_SENT",
        }[operation]
        resource_kind = {
            "computer.accessibility.interact": "accessibility_target",
            "computer.pointer.interact": "pointer_target",
            "computer.keyboard.interact": "keyboard_target",
        }[operation]
        return ComputerActionRequest(
            session_id="session:windows",
            action_id=action_id,
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            node_id="node:windows",
            operation=operation,
            effect="write",
            resource_kind=resource_kind,
            resource_ref=self.resource_ref,
            arguments=arguments,
            state_precondition_sha256=self.state,
            idempotency_key=sha("idem:" + action_id),
            risk_class="R2_STATE_CHANGE",
            requires_writer=True,
            expected_postcondition=expected,
        ).validate()

    def governed(self, action: ComputerActionRequest):
        contract = TaskContractCompiler().compile(
            task_id=self.task.task_id,
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=(action.operation,),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        capability = authority.require(
            action.operation,
            resource_kind=action.resource_kind,
            resource_ref=action.resource_ref,
            effect=action.effect,
        )
        policy = decide_computer_action(action, capability)
        grant = issue_computer_approval(
            approval_id="approval:" + action.action_id.replace(":", "-"),
            action=action,
            policy_decision=policy,
            approver_session_ref="user-session:windows",
            scope="one_shot",
            issued_at="2026-09-10T00:00:00Z",
            expires_at="2026-09-10T00:05:00Z",
        )
        lease = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-WINDOWS",
            issued_at="2026-09-10T00:00:00Z",
        )
        binding = bind_current_writer(action=action, lease_repository=self.repo, lease=lease)
        return capability, policy, grant, lease, binding

    def good_backend(self, *, secure=False, focused=False, postcondition="WINDOWS_UIA_INVOKED"):
        return FakeWindowsBackend(
            inspection=WindowsTargetInspection(
                window_id=self.window_id,
                process_id=self.process_id,
                process_name=self.process_name,
                automation_id="SaveButton",
                name="Save",
                control_type="ControlType.Button",
                secure_input=secure,
                focused=focused,
            ),
            result=WindowsInteractionBackendResult(
                post_observation=self.post(),
                observed_postconditions=(postcondition,),
                result={"ok": True},
            ),
        )

    def test_accessibility_interaction_is_canonical_r2_authority(self):
        action = self.action()
        capability, policy, *_ = self.governed(action)
        self.assertTrue(capability.allowed)
        self.assertEqual(policy.outcome, "REQUIRE_APPROVAL")
        self.assertTrue(action.requires_writer)

    def test_valid_uia_invoke_consumes_approval_and_dispatches_once(self):
        action = self.action()
        backend = self.good_backend()
        capability, policy, grant, lease, binding = self.governed(action)
        ledger = ComputerActionReplayLedger()
        result = execute_governed_windows_action(
            action=action,
            pre_observation=self.observation(),
            capability_decision=capability,
            policy_decision=policy,
            backend=backend,
            replay_ledger=ledger,
            approver_session_ref="user-session:windows",
            now="2026-09-10T00:01:00Z",
            approval=grant,
            lease_repository=self.repo,
            lease=lease,
            writer_binding=binding,
            user_takeover_active=False,
        )
        self.assertEqual(result.consumed_approval.status, "CONSUMED")
        self.assertEqual(len(backend.inspections), 1)
        self.assertEqual(len(backend.commands), 1)
        self.assertEqual(len(ledger.receipts), 1)
        self.assertEqual(backend.commands[0].interaction_kind, "invoke")

    def test_user_takeover_blocks_before_inspection_or_dispatch(self):
        action = self.action()
        backend = self.good_backend()
        capability, policy, grant, lease, binding = self.governed(action)
        ledger = ComputerActionReplayLedger()
        with self.assertRaisesRegex(WindowsInteractionError, "WINDOWS_USER_TAKEOVER_ACTIVE"):
            execute_governed_windows_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ledger,
                approver_session_ref="user-session:windows",
                now="2026-09-10T00:01:00Z",
                approval=grant,
                lease_repository=self.repo,
                lease=lease,
                writer_binding=binding,
                user_takeover_active=True,
            )
        self.assertEqual(backend.inspections, [])
        self.assertEqual(backend.commands, [])
        self.assertEqual(ledger.receipts, ())

    def test_wrong_window_resource_fails_closed_before_backend(self):
        original = self.action()
        action = ComputerActionRequest(**{**original.__dict__, "resource_ref": "local:desktop:window:0xDEAD"})
        contract = TaskContractCompiler().compile(
            task_id=self.task.task_id,
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=(action.operation,),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        capability = authority.require(
            action.operation,
            resource_kind=action.resource_kind,
            resource_ref=action.resource_ref,
            effect=action.effect,
        )
        policy = decide_computer_action(action, capability)
        backend = self.good_backend()
        with self.assertRaisesRegex(WindowsInteractionError, "WINDOWS_ACTION_WINDOW_RESOURCE_STALE"):
            execute_governed_windows_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:windows",
                now="2026-09-10T00:01:00Z",
                approval=None,
                lease_repository=None,
                lease=None,
                writer_binding=None,
                user_takeover_active=False,
            )
        self.assertEqual(backend.inspections, [])

    def test_backend_focus_identity_mismatch_fails_before_approval_consumption(self):
        action = self.action()
        capability, policy, grant, lease, binding = self.governed(action)
        backend = FakeWindowsBackend(
            inspection=WindowsTargetInspection(
                window_id="0x9999",
                process_id=self.process_id,
                process_name=self.process_name,
                automation_id="SaveButton",
                control_type="ControlType.Button",
            )
        )
        ledger = ComputerActionReplayLedger()
        with self.assertRaisesRegex(WindowsInteractionError, "WINDOWS_FOREGROUND_TARGET_STALE"):
            execute_governed_windows_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ledger,
                approver_session_ref="user-session:windows",
                now="2026-09-10T00:01:00Z",
                approval=grant,
                lease_repository=self.repo,
                lease=lease,
                writer_binding=binding,
                user_takeover_active=False,
            )
        self.assertEqual(grant.status, "ACTIVE")
        self.assertEqual(ledger.receipts, ())
        self.assertEqual(backend.commands, [])

    def test_secure_value_input_requires_user_takeover(self):
        action = self.action(
            action_id="action:value",
            arguments={
                "interaction": "value",
                "automation_id": "ValueBox",
                "control_type": "ControlType.Edit",
                "value": "bounded text",
            },
            expected="WINDOWS_UIA_VALUE_SET",
        )
        capability, policy, grant, lease, binding = self.governed(action)
        backend = FakeWindowsBackend(
            inspection=WindowsTargetInspection(
                window_id=self.window_id,
                process_id=self.process_id,
                process_name=self.process_name,
                automation_id="ValueBox",
                control_type="ControlType.Edit",
                secure_input=True,
            )
        )
        ledger = ComputerActionReplayLedger()
        with self.assertRaisesRegex(WindowsInteractionError, "WINDOWS_SECURE_INPUT_USER_TAKEOVER_REQUIRED"):
            execute_governed_windows_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ledger,
                approver_session_ref="user-session:windows",
                now="2026-09-10T00:01:00Z",
                approval=grant,
                lease_repository=self.repo,
                lease=lease,
                writer_binding=binding,
                user_takeover_active=False,
            )
        self.assertEqual(grant.status, "ACTIVE")
        self.assertEqual(ledger.receipts, ())

    def test_pointer_fallback_is_denied_without_explicit_flag(self):
        action = self.action(
            operation="computer.pointer.interact",
            action_id="action:pointer",
            arguments={"interaction": "click", "x": 100, "y": 200},
        )
        capability, policy, grant, lease, binding = self.governed(action)
        backend = self.good_backend(postcondition="WINDOWS_POINTER_CLICK_SENT")
        with self.assertRaisesRegex(WindowsInteractionError, "WINDOWS_INPUT_FALLBACK_NOT_AUTHORIZED"):
            execute_governed_windows_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:windows",
                now="2026-09-10T00:01:00Z",
                approval=grant,
                lease_repository=self.repo,
                lease=lease,
                writer_binding=binding,
                user_takeover_active=False,
            )
        self.assertEqual(backend.inspections, [])
        self.assertEqual(backend.commands, [])

    def test_missing_approval_does_not_reserve_replay_or_dispatch(self):
        action = self.action()
        backend = self.good_backend()
        capability, policy, _grant, lease, binding = self.governed(action)
        ledger = ComputerActionReplayLedger()
        with self.assertRaisesRegex(WindowsInteractionError, "WINDOWS_ACTION_APPROVAL_REQUIRED"):
            execute_governed_windows_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ledger,
                approver_session_ref="user-session:windows",
                now="2026-09-10T00:01:00Z",
                approval=None,
                lease_repository=self.repo,
                lease=lease,
                writer_binding=binding,
                user_takeover_active=False,
            )
        self.assertEqual(ledger.receipts, ())
        self.assertEqual(backend.commands, [])

    def test_postcondition_failure_exposes_consumed_approval(self):
        action = self.action()
        backend = self.good_backend(postcondition="SOMETHING_ELSE")
        capability, policy, grant, lease, binding = self.governed(action)
        with self.assertRaises(WindowsDispatchError) as caught:
            execute_governed_windows_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:windows",
                now="2026-09-10T00:01:00Z",
                approval=grant,
                lease_repository=self.repo,
                lease=lease,
                writer_binding=binding,
                user_takeover_active=False,
            )
        self.assertEqual(caught.exception.consumed_approval.status, "CONSUMED")

    def test_extra_provider_argument_is_rejected(self):
        action = self.action(
            action_id="action:extra",
            arguments={
                "interaction": "invoke",
                "automation_id": "SaveButton",
                "shell_command": "whoami",
            },
        )
        capability, policy, _grant, _lease, _binding = self.governed(action)
        backend = self.good_backend()
        with self.assertRaisesRegex(WindowsInteractionError, "WINDOWS_INTERACTION_ARGUMENT_NOT_ALLOWED"):
            execute_governed_windows_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:windows",
                now="2026-09-10T00:01:00Z",
                approval=None,
                lease_repository=None,
                lease=None,
                writer_binding=None,
                user_takeover_active=False,
            )
        self.assertEqual(backend.inspections, [])


class WindowsPowerShellInteractionContractTests(unittest.TestCase):
    def command(self):
        return WindowsInteractionCommand(
            session_id="session:1",
            task_id="task:1",
            operation="computer.accessibility.interact",
            interaction_kind="value",
            resource_ref="local:desktop:window:0x1234",
            window_id="0x1234",
            process_id=100,
            process_name="notepad",
            arguments={
                "interaction": "value",
                "automation_id": "ValueBox",
                "control_type": "ControlType.Edit",
                "value": "user text ; $(whoami) ' \" & | < >",
            },
            expected_postcondition="WINDOWS_UIA_VALUE_SET",
        )

    def test_powershell_command_has_exactly_one_fixed_command_payload_and_shell_false(self):
        backend = WindowsPowerShellInteractionBackend()
        completed = SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "window_id": "0x1234",
                    "process_id": 100,
                    "process_name": "notepad",
                    "automation_id": "ValueBox",
                    "name": "Value",
                    "control_type": "ControlType.Edit",
                    "secure_input": False,
                    "focused": False,
                }
            ),
            stderr="",
        )
        with patch.object(backend, "_require_windows_host"), patch(
            "three_agent.computer_use_windows_interaction_powershell.subprocess.run",
            return_value=completed,
        ) as run:
            backend.inspect_target(self.command())

        args, kwargs = run.call_args
        argv = args[0]
        command_index = argv.index("-Command")
        self.assertEqual(argv[command_index + 1 :], [backend._SCRIPT])
        self.assertFalse(kwargs["shell"])
        self.assertNotIn("user text", " ".join(argv))
        encoded = kwargs["env"][backend._PAYLOAD_ENV]
        payload = json.loads(base64.b64decode(encoded).decode("utf-8"))
        self.assertEqual(payload["arguments"]["value"], self.command().arguments["value"])

    def test_fixed_backend_contains_no_elevation_or_dynamic_shell_primitives(self):
        script = WindowsPowerShellInteractionBackend._SCRIPT.lower()
        for forbidden in ("invoke-expression", "start-process", "-verb runas", "cmd.exe", "powershell -command"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, script)

    def test_backend_error_is_bounded_to_reviewed_reason_code(self):
        self.assertEqual(
            WindowsPowerShellInteractionBackend._bounded_backend_error(
                "At line:1 + throw WINDOWS_UIA_TARGET_NOT_FOUND; C:\\Users\\someone\\secret.txt"
            ),
            "WINDOWS_UIA_TARGET_NOT_FOUND",
        )
        self.assertEqual(
            WindowsPowerShellInteractionBackend._bounded_backend_error("arbitrary private stderr"),
            "WINDOWS_INTERACTION_BACKEND_FAILED",
        )


if __name__ == "__main__":
    unittest.main()
