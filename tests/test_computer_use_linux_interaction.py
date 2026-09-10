from __future__ import annotations

import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path

import three_agent.computer_use_linux_interaction as linux_interaction
from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.computer_use import ComputerActionRequest, ComputerObservation, decide_computer_action
from three_agent.computer_use_approval import issue_computer_approval
from three_agent.computer_use_linux_interaction import (
    LinuxAtspiInteractionBackend,
    LinuxDispatchError,
    LinuxInteractionBackendResult,
    LinuxInteractionCommand,
    LinuxInteractionError,
    LinuxTargetInspection,
    execute_governed_linux_action,
)
from three_agent.computer_use_replay import ComputerActionReplayLedger
from three_agent.computer_use_writer import bind_current_writer
from three_agent.runtime_writer_lease import RuntimeWriterLeaseRepository
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler

TARGET = "atspi-0123456789abcdef0123456789abcdef"
ELEMENT = "atspi-11111111111111111111111111111111"
STATE = "sha256:" + "2" * 64


def sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class FakeLinuxBackend:
    def __init__(self, *, inspection: LinuxTargetInspection, result: LinuxInteractionBackendResult | None = None):
        self.inspection = inspection
        self.result = result
        self.inspections: list[LinuxInteractionCommand] = []
        self.commands: list[LinuxInteractionCommand] = []

    def inspect_target(self, command: LinuxInteractionCommand) -> LinuxTargetInspection:
        self.inspections.append(command)
        return self.inspection

    def dispatch(self, command: LinuxInteractionCommand) -> LinuxInteractionBackendResult:
        self.commands.append(command)
        if self.result is None:
            raise AssertionError("unexpected dispatch")
        return self.result


class GovernedLinuxInteractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tmp.name) / "workspace.sqlite3")
        self.store.initialize()
        self.task = self.store.create_task("linux interaction", "govern one semantic Linux AT-SPI action")
        self.plan = sha("linux-plan")
        self.repo = RuntimeWriterLeaseRepository(self.store)
        self.repo.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def observation(self, *, role: str = "push button", secure: bool = False) -> ComputerObservation:
        return ComputerObservation(
            session_id="session:linux",
            task_id=self.task.task_id,
            state_id="state:linux",
            state_sha256=STATE,
            surface="desktop",
            active_target_ref=f"linux:atspi:{TARGET}/process:4242",
            captured_at="2026-09-10T14:45:00Z",
            structured_observation={
                "platform": "linux",
                "backend": "atspi2",
                "target_id": TARGET,
                "process_id": 4242,
                "application_name": "Fixture",
                "metadata": {},
                "accessibility": {
                    "accessible_id": TARGET,
                    "role": "frame",
                    "name": "Fixture",
                    "is_enabled": True,
                    "is_showing": True,
                    "is_visible": True,
                    "is_secure": False,
                    "children": [{
                        "accessible_id": ELEMENT,
                        "role": role,
                        "name": "[REDACTED_SECURE_UI]" if secure else "Target",
                        "is_enabled": True,
                        "is_showing": True,
                        "is_visible": True,
                        "is_secure": secure,
                        "children": [],
                    }],
                },
            },
        ).validate()

    def post(self) -> ComputerObservation:
        return ComputerObservation(
            session_id="session:linux",
            task_id=self.task.task_id,
            state_id="state:linux:post",
            state_sha256=sha("linux-post"),
            surface="desktop",
            active_target_ref=f"linux:atspi:{TARGET}/process:4242",
            captured_at="2026-09-10T14:45:01Z",
            structured_observation={
                "platform": "linux", "backend": "atspi2", "target_id": TARGET,
                "process_id": 4242, "application_name": "Fixture", "metadata": {},
                "accessibility": {"accessible_id": TARGET, "children": []},
            },
        ).validate()

    def action(self, *, interaction="invoke", value=None, action_id="action:linux") -> ComputerActionRequest:
        role = "push button" if interaction == "invoke" else "text"
        arguments = {"interaction": interaction, "accessible_id": ELEMENT, "role": role}
        if value is not None:
            arguments["value"] = value
        return ComputerActionRequest(
            session_id="session:linux",
            action_id=action_id,
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            node_id="node:linux",
            operation="computer.accessibility.interact",
            effect="write",
            resource_kind="accessibility_target",
            resource_ref=f"local:desktop:window:{TARGET}",
            arguments=arguments,
            state_precondition_sha256=STATE,
            idempotency_key=sha("idem:" + action_id),
            risk_class="R2_STATE_CHANGE",
            requires_writer=True,
            expected_postcondition=(
                "LINUX_ATSPI_ACTION_INVOKED" if interaction == "invoke" else "LINUX_ATSPI_TEXT_SET"
            ),
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
            approver_session_ref="user-session:linux",
            scope="one_shot",
            issued_at="2026-09-10T14:45:00Z",
            expires_at="2026-09-10T14:50:00Z",
        )
        lease = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-LINUX-" + action.action_id.replace(":", "-"),
            issued_at="2026-09-10T14:45:00Z",
        )
        binding = bind_current_writer(action=action, lease_repository=self.repo, lease=lease)
        return capability, policy, grant, lease, binding

    def backend(self, *, interaction="invoke", secure=False, dispatch=True) -> FakeLinuxBackend:
        postcondition = "LINUX_ATSPI_ACTION_INVOKED" if interaction == "invoke" else "LINUX_ATSPI_TEXT_SET"
        return FakeLinuxBackend(
            inspection=LinuxTargetInspection(
                target_id=TARGET,
                process_id=4242,
                accessible_id=ELEMENT,
                role="push button" if interaction == "invoke" else "text",
                secure_input=secure,
            ),
            result=(
                LinuxInteractionBackendResult(
                    post_observation=self.post(),
                    observed_postconditions=(postcondition,),
                    result={"ok": True},
                ) if dispatch else None
            ),
        )

    def execute(self, action, backend, *, observation=None):
        capability, policy, grant, lease, binding = self.governed(action)
        ledger = ComputerActionReplayLedger()
        result = execute_governed_linux_action(
            action=action,
            pre_observation=observation or self.observation(),
            capability_decision=capability,
            policy_decision=policy,
            backend=backend,
            replay_ledger=ledger,
            approver_session_ref="user-session:linux",
            now="2026-09-10T14:46:00Z",
            approval=grant,
            lease_repository=self.repo,
            lease=lease,
            writer_binding=binding,
            user_takeover_active=False,
        )
        return result, ledger

    def test_valid_invoke_requires_canonical_approval_and_writer(self):
        action = self.action()
        backend = self.backend()
        result, ledger = self.execute(action, backend)
        self.assertEqual(result.consumed_approval.status, "CONSUMED")
        self.assertEqual(len(ledger.receipts), 1)
        self.assertEqual(len(backend.commands), 1)

    def test_value_mutation_uses_matching_semantic_role(self):
        action = self.action(interaction="value", value="bounded text", action_id="action:linux-value")
        backend = self.backend(interaction="value")
        result, _ = self.execute(action, backend, observation=self.observation(role="text"))
        self.assertIn("LINUX_ATSPI_TEXT_SET", result.backend_result.observed_postconditions)
        self.assertEqual(backend.commands[0].arguments["value"], "bounded text")

    def test_missing_approval_fails_before_replay_or_dispatch(self):
        action = self.action()
        backend = self.backend()
        capability, policy, _grant, lease, binding = self.governed(action)
        ledger = ComputerActionReplayLedger()
        with self.assertRaisesRegex(LinuxInteractionError, "LINUX_ACTION_APPROVAL_REQUIRED"):
            execute_governed_linux_action(
                action=action, pre_observation=self.observation(), capability_decision=capability,
                policy_decision=policy, backend=backend, replay_ledger=ledger,
                approver_session_ref="user-session:linux", now="2026-09-10T14:46:00Z",
                approval=None, lease_repository=self.repo, lease=lease, writer_binding=binding,
                user_takeover_active=False,
            )
        self.assertEqual(ledger.receipts, ())
        self.assertEqual(backend.commands, [])

    def test_user_takeover_blocks_before_backend(self):
        action = self.action()
        backend = self.backend()
        capability, policy, grant, lease, binding = self.governed(action)
        with self.assertRaisesRegex(LinuxInteractionError, "LINUX_USER_TAKEOVER_ACTIVE"):
            execute_governed_linux_action(
                action=action, pre_observation=self.observation(), capability_decision=capability,
                policy_decision=policy, backend=backend, replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:linux", now="2026-09-10T14:46:00Z",
                approval=grant, lease_repository=self.repo, lease=lease, writer_binding=binding,
                user_takeover_active=True,
            )
        self.assertEqual(backend.inspections, [])

    def test_secure_value_input_requires_user_takeover_before_backend(self):
        action = self.action(interaction="value", value="secret", action_id="action:linux-secret")
        backend = self.backend(interaction="value", secure=True)
        capability, policy, grant, lease, binding = self.governed(action)
        with self.assertRaisesRegex(LinuxInteractionError, "LINUX_SECURE_INPUT_USER_TAKEOVER_REQUIRED"):
            execute_governed_linux_action(
                action=action, pre_observation=self.observation(role="text", secure=True),
                capability_decision=capability, policy_decision=policy, backend=backend,
                replay_ledger=ComputerActionReplayLedger(), approver_session_ref="user-session:linux",
                now="2026-09-10T14:46:00Z", approval=grant, lease_repository=self.repo,
                lease=lease, writer_binding=binding, user_takeover_active=False,
            )
        self.assertEqual(backend.inspections, [])
        self.assertEqual(backend.commands, [])

    def test_stale_window_resource_fails_closed_before_backend(self):
        original = self.action()
        action = ComputerActionRequest(**{
            **original.__dict__,
            "resource_ref": "local:desktop:window:atspi-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        }).validate()
        backend = self.backend()
        capability, policy, *_ = self.governed(action)
        with self.assertRaisesRegex(LinuxInteractionError, "LINUX_ACTION_WINDOW_RESOURCE_STALE"):
            execute_governed_linux_action(
                action=action, pre_observation=self.observation(), capability_decision=capability,
                policy_decision=policy, backend=backend, replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:linux", now="2026-09-10T14:46:00Z",
                approval=None, lease_repository=None, lease=None, writer_binding=None,
                user_takeover_active=False,
            )
        self.assertEqual(backend.inspections, [])

    def test_pointer_and_keyboard_fallback_fail_closed(self):
        for operation, resource_kind, arguments in (
            ("computer.pointer.interact", "pointer_target", {"interaction": "click", "x": 1, "y": 1}),
            ("computer.keyboard.interact", "keyboard_target", {"interaction": "text", "text": "x"}),
        ):
            original = self.action(action_id="action:" + operation.split(".")[1])
            action = ComputerActionRequest(**{
                **original.__dict__, "operation": operation, "resource_kind": resource_kind,
                "arguments": arguments, "idempotency_key": sha(operation),
            }).validate()
            contract = TaskContractCompiler().compile(
                task_id=self.task.task_id, task_type="analysis", sensitivity="internal",
                allowed_tools=(operation,),
            )
            capability = TaskCapabilityAuthority.from_contract(contract).require(
                operation, resource_kind=resource_kind, resource_ref=action.resource_ref, effect="write",
            )
            policy = decide_computer_action(action, capability)
            with self.assertRaisesRegex(LinuxInteractionError, "LINUX_INPUT_FALLBACK_NOT_IMPLEMENTED"):
                execute_governed_linux_action(
                    action=action, pre_observation=self.observation(), capability_decision=capability,
                    policy_decision=policy, backend=self.backend(), replay_ledger=ComputerActionReplayLedger(),
                    approver_session_ref="user-session:linux", now="2026-09-10T14:46:00Z",
                    approval=None, lease_repository=None, lease=None, writer_binding=None,
                    user_takeover_active=False,
                )

    def test_dispatch_failure_exposes_consumed_approval(self):
        action = self.action()
        backend = self.backend(dispatch=False)
        capability, policy, grant, lease, binding = self.governed(action)
        with self.assertRaises(LinuxDispatchError) as caught:
            execute_governed_linux_action(
                action=action, pre_observation=self.observation(), capability_decision=capability,
                policy_decision=policy, backend=backend, replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:linux", now="2026-09-10T14:46:00Z",
                approval=grant, lease_repository=self.repo, lease=lease, writer_binding=binding,
                user_takeover_active=False,
            )
        self.assertEqual(caught.exception.consumed_approval.status, "CONSUMED")


class FakeActionInterface:
    def __init__(self, names):
        self.names = names
        self.called = []

    def get_n_actions(self): return len(self.names)
    def get_action_name(self, index): return self.names[index]
    def do_action(self, index):
        self.called.append(index)
        return True


class FakeEditableText:
    def __init__(self): self.value = ""
    def set_text_contents(self, value):
        self.value = value
        return True


class FakeText:
    def __init__(self, editable): self.editable = editable
    def get_text(self, _start, _end): return self.editable.value


class FakeAtspiTextApi:
    @staticmethod
    def get_text(interface, start, end):
        return interface.get_text(start, end)


class FakeAtspiApi:
    Text = FakeAtspiTextApi


class FakeAtspiElement:
    def __init__(self):
        self.action = FakeActionInterface(["show menu", "click"])
        self.editable = FakeEditableText()
        self.text = FakeText(self.editable)

    def get_action_iface(self): return self.action
    def get_editable_text_iface(self): return self.editable
    def get_text_iface(self): return self.text


class LinuxAtspiBackendContractTests(unittest.TestCase):
    def test_invoke_selects_only_reviewed_semantic_action_name(self):
        element = FakeAtspiElement()
        LinuxAtspiInteractionBackend._invoke(element)
        self.assertEqual(element.action.called, [1])

    def test_value_uses_editable_text_interface_and_explicit_text_readback(self):
        element = FakeAtspiElement()
        LinuxAtspiInteractionBackend._set_value(FakeAtspiApi, element, "semantic-value")
        self.assertEqual(element.editable.value, "semantic-value")

    def test_value_readback_mismatch_fails_closed(self):
        element = FakeAtspiElement()
        element.text.get_text = lambda _start, _end: "different"
        with self.assertRaisesRegex(LinuxInteractionError, "LINUX_ATSPI_TEXT_POSTCONDITION_FAILED"):
            LinuxAtspiInteractionBackend._set_value(FakeAtspiApi, element, "semantic-value")

    def test_module_has_no_shell_or_privilege_surface(self):
        source = inspect.getsource(linux_interaction)
        for forbidden in (
            "subprocess", "os.system", "shell=True", "sudo", "pkexec",
            "generate_mouse_event", "generate_keyboard_event",
        ):
            haystack = source.lower() if forbidden in {"sudo", "pkexec"} else source
            self.assertNotIn(forbidden, haystack)


if __name__ == "__main__":
    unittest.main()
