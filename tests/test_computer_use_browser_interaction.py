from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.computer_use import ComputerActionRequest, ComputerObservation, decide_computer_action
from three_agent.computer_use_approval import issue_computer_approval
from three_agent.computer_use_browser_interaction import (
    BrowserDispatchError,
    BrowserInteractionBackendResult,
    BrowserInteractionError,
    BrowserTargetInspection,
    execute_governed_browser_action,
)
from three_agent.computer_use_replay import ComputerActionReplayLedger, ComputerReplayError
from three_agent.computer_use_writer import bind_current_writer
from three_agent.runtime_writer_lease import RuntimeWriterLeaseError, RuntimeWriterLeaseRepository
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


def sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class FakeBackend:
    def __init__(self, result=None, error=None, *, inspection=None):
        self.result = result
        self.error = error
        self.inspection = inspection
        self.commands = []
        self.inspections = []

    def inspect_target(self, command):
        self.inspections.append(command)
        return self.inspection

    def dispatch(self, command):
        self.commands.append(command)
        if self.error is not None:
            raise self.error
        return self.result


class GovernedBrowserInteractionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = TaskStore(Path(self.tmp.name) / "workspace.sqlite3")
        self.store.initialize()
        self.task = self.store.create_task("browser interaction", "govern one bounded browser action")
        self.plan = sha("browser-plan")
        self.state = sha("browser-state")
        self.repo = RuntimeWriterLeaseRepository(self.store)
        self.repo.initialize()

    def tearDown(self):
        self.tmp.cleanup()

    def observation(self, *, target="browser:profile:isolated/tab:tab1", state=None):
        return ComputerObservation(
            session_id="session:browser",
            task_id=self.task.task_id,
            state_id="state:browser",
            state_sha256=state or self.state,
            surface="browser",
            active_target_ref=target,
            captured_at="2026-09-10T00:00:00Z",
            structured_observation={"target": target},
        ).validate()

    def post(self, *, target="browser:profile:isolated/tab:tab1"):
        return ComputerObservation(
            session_id="session:browser",
            task_id=self.task.task_id,
            state_id="state:browser:post",
            state_sha256=sha("browser-state-post:" + target),
            surface="browser",
            active_target_ref=target,
            captured_at="2026-09-10T00:00:01Z",
            structured_observation={"target": target},
        ).validate()

    def interact_action(self, *, action_id="action:click", expected="dialog closed", target=None, arguments=None):
        return ComputerActionRequest(
            session_id="session:browser",
            action_id=action_id,
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            node_id="node:browser",
            operation="browser.interact",
            effect="write",
            resource_kind="browser_document",
            resource_ref=target or "browser:profile:isolated/tab:tab1",
            arguments=arguments or {"interaction": "click", "selector": "#confirm"},
            state_precondition_sha256=self.state,
            idempotency_key=sha("idem:" + action_id),
            risk_class="R2_STATE_CHANGE",
            requires_writer=True,
            expected_postcondition=expected,
        ).validate()

    def navigate_action(self, *, url="https://example.test/account", expected="page loaded"):
        return ComputerActionRequest(
            session_id="session:browser",
            action_id="action:navigate",
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            node_id="node:browser",
            operation="browser.navigate",
            effect="network_read",
            resource_kind="browser_profile",
            resource_ref="browser:profile:isolated",
            arguments={"url": url},
            state_precondition_sha256=self.state,
            idempotency_key=sha("idem:navigate"),
            risk_class="R1_REVERSIBLE_INTERACTION",
            requires_writer=False,
            expected_postcondition=expected,
        ).validate()

    def interact_authority(self, action):
        contract = TaskContractCompiler().compile(
            task_id=self.task.task_id,
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("browser.interact",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        capability = authority.require(
            action.operation,
            resource_kind=action.resource_kind,
            resource_ref=action.resource_ref,
            effect=action.effect,
        )
        return capability, decide_computer_action(action, capability)

    def navigate_authority(self, action):
        contract = TaskContractCompiler().compile(
            task_id=self.task.task_id,
            task_type="analysis",
            sensitivity="public",
            allowed_tools=("browser.navigate",),
            public_web=True,
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        capability = authority.require(
            action.operation,
            resource_kind=action.resource_kind,
            resource_ref=action.resource_ref,
            effect=action.effect,
        )
        return capability, decide_computer_action(action, capability)

    def approval(self, action, policy):
        return issue_computer_approval(
            approval_id="approval:" + action.action_id.replace(":", "-"),
            action=action,
            policy_decision=policy,
            approver_session_ref="user-session:browser",
            scope="one_shot",
            issued_at="2026-09-10T00:00:00Z",
            expires_at="2026-09-10T00:05:00Z",
        )

    def writer(self, action, *, run_id="RUN-A", issued_at="2026-09-10T00:00:00Z"):
        lease = self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id=run_id,
            issued_at=issued_at,
        )
        return lease, bind_current_writer(action=action, lease_repository=self.repo, lease=lease)

    def safe_backend(self, *, postcondition="dialog closed", result=None):
        return FakeBackend(
            BrowserInteractionBackendResult(
                post_observation=self.post(),
                observed_postconditions=(postcondition,),
                result=result,
            ),
            inspection=BrowserTargetInspection(state_sha256=self.state, secure_input=False),
        )

    def execute_click(self, action, capability, policy, grant, lease, binding, backend, ledger=None):
        return execute_governed_browser_action(
            action=action,
            pre_observation=self.observation(),
            capability_decision=capability,
            policy_decision=policy,
            backend=backend,
            replay_ledger=ledger or ComputerActionReplayLedger(),
            approver_session_ref="user-session:browser",
            now="2026-09-10T00:01:00Z",
            approval=grant,
            lease_repository=self.repo,
            lease=lease,
            writer_binding=binding,
        )

    def test_click_requires_valid_approval_and_does_not_reserve_replay_when_missing(self):
        action = self.interact_action()
        capability, policy = self.interact_authority(action)
        ledger = ComputerActionReplayLedger()
        backend = self.safe_backend()
        lease, binding = self.writer(action)
        with self.assertRaisesRegex(BrowserInteractionError, "BROWSER_ACTION_APPROVAL_REQUIRED"):
            execute_governed_browser_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ledger,
                approver_session_ref="user-session:browser",
                now="2026-09-10T00:01:00Z",
                lease_repository=self.repo,
                lease=lease,
                writer_binding=binding,
            )
        self.assertEqual(ledger.receipts, ())
        self.assertEqual(backend.commands, [])

    def test_valid_click_consumes_approval_checks_writer_and_verifies_postcondition(self):
        action = self.interact_action()
        capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = self.safe_backend(result={"clicked": True})
        result = self.execute_click(action, capability, policy, grant, lease, binding, backend)
        self.assertEqual(result.consumed_approval.status, "CONSUMED")
        self.assertEqual(len(backend.commands), 1)
        self.assertEqual(backend.commands[0].interaction_kind, "click")

    def test_stale_target_rejects_before_inspection_approval_or_dispatch(self):
        action = self.interact_action(target="browser:profile:isolated/tab:old")
        capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = self.safe_backend()
        with self.assertRaisesRegex(ComputerReplayError, "COMPUTER_ACTION_TARGET_REF_STALE"):
            execute_governed_browser_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:browser",
                now="2026-09-10T00:01:00Z",
                approval=grant,
                lease_repository=self.repo,
                lease=lease,
                writer_binding=binding,
            )
        self.assertEqual(backend.inspections, [])
        self.assertEqual(backend.commands, [])
        self.assertEqual(grant.status, "ACTIVE")

    def test_stale_writer_is_exactly_rejected_before_approval_consumption_or_replay(self):
        action = self.interact_action()
        capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        old_lease, old_binding = self.writer(action, run_id="RUN-A")
        self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-B",
            issued_at="2026-09-10T00:00:30Z",
        )
        ledger = ComputerActionReplayLedger()
        backend = self.safe_backend()
        with self.assertRaisesRegex(RuntimeWriterLeaseError, "WRITER_LEASE_STALE"):
            self.execute_click(action, capability, policy, grant, old_lease, old_binding, backend, ledger)
        self.assertEqual(grant.status, "ACTIVE")
        self.assertEqual(ledger.receipts, ())
        self.assertEqual(backend.commands, [])

    def test_backend_timeout_surfaces_consumed_approval_to_prevent_replay(self):
        action = self.interact_action()
        capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = FakeBackend(
            error=TimeoutError("ambiguous timeout"),
            inspection=BrowserTargetInspection(state_sha256=self.state),
        )
        with self.assertRaises(BrowserDispatchError) as caught:
            self.execute_click(action, capability, policy, grant, lease, binding, backend)
        self.assertEqual(caught.exception.consumed_approval.status, "CONSUMED")

    def test_secure_password_target_requires_user_takeover_before_approval_consumption(self):
        action = self.interact_action(
            action_id="action:type-secret",
            expected="credential entered",
            arguments={"interaction": "type", "selector": "#password", "text": "secret-value"},
        )
        capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = FakeBackend(
            inspection=BrowserTargetInspection(state_sha256=self.state, secure_input=True)
        )
        ledger = ComputerActionReplayLedger()
        with self.assertRaisesRegex(BrowserInteractionError, "BROWSER_SECURE_INPUT_USER_TAKEOVER_REQUIRED"):
            self.execute_click(action, capability, policy, grant, lease, binding, backend, ledger)
        self.assertEqual(grant.status, "ACTIVE")
        self.assertEqual(ledger.receipts, ())
        self.assertEqual(backend.commands, [])

    def test_stale_target_inspection_is_rejected(self):
        action = self.interact_action()
        capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = FakeBackend(
            inspection=BrowserTargetInspection(state_sha256=sha("newer-state"))
        )
        with self.assertRaisesRegex(BrowserInteractionError, "BROWSER_TARGET_INSPECTION_STALE"):
            self.execute_click(action, capability, policy, grant, lease, binding, backend)
        self.assertEqual(backend.commands, [])

    def test_navigation_target_requires_independent_https_host_allowlist(self):
        action = self.navigate_action(url="https://evil.example/steal")
        capability, policy = self.navigate_authority(action)
        grant = self.approval(action, policy)
        backend = FakeBackend()
        with self.assertRaisesRegex(BrowserInteractionError, "BROWSER_NAVIGATION_HOST_NOT_ALLOWLISTED"):
            execute_governed_browser_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:browser",
                now="2026-09-10T00:01:00Z",
                approval=grant,
                allowed_navigation_hosts=("example.test",),
            )
        self.assertEqual(backend.commands, [])

    def test_navigation_query_is_rejected_to_avoid_unreviewed_exfiltration(self):
        action = self.navigate_action(url="https://example.test/search?q=secret")
        capability, policy = self.navigate_authority(action)
        grant = self.approval(action, policy)
        with self.assertRaisesRegex(BrowserInteractionError, "BROWSER_NAVIGATION_URL_UNSAFE"):
            execute_governed_browser_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=FakeBackend(),
                replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:browser",
                now="2026-09-10T00:01:00Z",
                approval=grant,
                allowed_navigation_hosts=("example.test",),
            )

    def test_provider_extra_argument_is_rejected_before_backend_inspection(self):
        action = self.interact_action(
            action_id="action:extra",
            arguments={"interaction": "click", "selector": "#confirm", "shell_command": "whoami"},
        )
        capability, policy = self.interact_authority(action)
        backend = self.safe_backend()
        with self.assertRaisesRegex(BrowserInteractionError, "BROWSER_INTERACTION_ARGUMENT_NOT_ALLOWED"):
            execute_governed_browser_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:browser",
                now="2026-09-10T00:01:00Z",
            )
        self.assertEqual(backend.inspections, [])
        self.assertEqual(backend.commands, [])

    def test_supported_interaction_schemas_are_normalized(self):
        cases = (
            ("click", {"interaction": "click", "selector": "#a"}),
            ("type", {"interaction": "type", "selector": "#a", "text": "hello"}),
            ("select", {"interaction": "select", "selector": "#a", "value": "one"}),
            ("scroll", {"interaction": "scroll", "delta_y": 120}),
            ("form_submit", {"interaction": "form_submit", "selector": "#form"}),
        )
        for index, (kind, arguments) in enumerate(cases):
            with self.subTest(kind=kind):
                action = self.interact_action(
                    action_id=f"action:{index}",
                    expected="done",
                    arguments=arguments,
                )
                capability, policy = self.interact_authority(action)
                grant = self.approval(action, policy)
                lease, binding = self.writer(action, run_id=f"RUN-{index}", issued_at=f"2026-09-10T00:00:0{index}Z")
                backend = FakeBackend(
                    BrowserInteractionBackendResult(
                        post_observation=self.post(),
                        observed_postconditions=("done",),
                    ),
                    inspection=BrowserTargetInspection(state_sha256=self.state),
                )
                self.execute_click(action, capability, policy, grant, lease, binding, backend)
                self.assertEqual(backend.commands[0].interaction_kind, kind)

    def test_download_requires_matching_quarantine_receipt(self):
        action = self.interact_action(
            action_id="action:download",
            expected="download quarantined",
            arguments={"interaction": "download_request", "selector": "#download"},
        )
        capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = FakeBackend(
            BrowserInteractionBackendResult(
                post_observation=self.post(),
                observed_postconditions=("download quarantined",),
                download_quarantine_ref="quarantine:wrong",
            ),
            inspection=BrowserTargetInspection(state_sha256=self.state),
        )
        with self.assertRaisesRegex(BrowserDispatchError, "DOWNLOAD_NOT_QUARANTINED"):
            execute_governed_browser_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:browser",
                now="2026-09-10T00:01:00Z",
                approval=grant,
                lease_repository=self.repo,
                lease=lease,
                writer_binding=binding,
                download_quarantine_ref="quarantine:expected",
            )

    def test_postcondition_mismatch_fails_closed_with_consumed_approval(self):
        action = self.interact_action(expected="dialog closed")
        capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = self.safe_backend(postcondition="dialog still open")
        with self.assertRaisesRegex(BrowserDispatchError, "BROWSER_POSTCONDITION_NOT_SATISFIED") as caught:
            self.execute_click(action, capability, policy, grant, lease, binding, backend)
        self.assertEqual(caught.exception.consumed_approval.status, "CONSUMED")

    def test_action_without_declared_postcondition_never_dispatches(self):
        action = self.interact_action(expected=None)
        capability, policy = self.interact_authority(action)
        backend = self.safe_backend()
        with self.assertRaisesRegex(BrowserInteractionError, "BROWSER_EXPECTED_POSTCONDITION_REQUIRED"):
            execute_governed_browser_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ComputerActionReplayLedger(),
                approver_session_ref="user-session:browser",
                now="2026-09-10T00:01:00Z",
            )
        self.assertEqual(backend.commands, [])


if __name__ == "__main__":
    unittest.main()
