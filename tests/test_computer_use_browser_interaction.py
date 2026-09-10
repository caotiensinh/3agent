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
    execute_governed_browser_action,
)
from three_agent.computer_use_replay import ComputerActionReplayLedger, ComputerReplayError
from three_agent.computer_use_writer import bind_current_writer
from three_agent.runtime_writer_lease import RuntimeWriterLeaseRepository
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler


def sha(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


class FakeBackend:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.commands = []

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

    def interact_action(self, *, action_id="action:click", expected="dialog closed", target=None, kind="click"):
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
            arguments={"interaction": kind, "selector": "#confirm"},
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
        return authority, capability, decide_computer_action(action, capability)

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
        return authority, capability, decide_computer_action(action, capability)

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
        binding = bind_current_writer(
            action=action,
            lease_repository=self.repo,
            lease=lease,
        )
        return lease, binding

    def test_click_requires_valid_approval_and_does_not_reserve_replay_when_missing(self):
        action = self.interact_action()
        _, capability, policy = self.interact_authority(action)
        ledger = ComputerActionReplayLedger()
        backend = FakeBackend()
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
        _, capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = FakeBackend(
            BrowserInteractionBackendResult(
                post_observation=self.post(),
                observed_postconditions=("dialog closed",),
                result={"clicked": True},
            )
        )
        result = execute_governed_browser_action(
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
        self.assertEqual(result.consumed_approval.status, "CONSUMED")
        self.assertEqual(len(backend.commands), 1)
        self.assertEqual(backend.commands[0].interaction_kind, "click")

    def test_stale_target_rejects_before_approval_consumption_or_dispatch(self):
        action = self.interact_action(target="browser:profile:isolated/tab:old")
        _, capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = FakeBackend()
        with self.assertRaisesRegex(ComputerReplayError, "COMPUTER_ACTION_TARGET_REF_STALE"):
            execute_governed_browser_action(
                action=action,
                pre_observation=self.observation(target="browser:profile:isolated/tab:tab1"),
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
        self.assertEqual(grant.status, "ACTIVE")
        self.assertEqual(backend.commands, [])

    def test_stale_writer_is_rejected_before_approval_consumption_and_replay_reservation(self):
        action = self.interact_action()
        _, capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        old_lease, old_binding = self.writer(action, run_id="RUN-A")
        self.repo.claim(
            task_id=self.task.task_id,
            plan_fingerprint=self.plan,
            run_id="RUN-B",
            issued_at="2026-09-10T00:00:30Z",
        )
        ledger = ComputerActionReplayLedger()
        backend = FakeBackend()
        with self.assertRaises(Exception):
            execute_governed_browser_action(
                action=action,
                pre_observation=self.observation(),
                capability_decision=capability,
                policy_decision=policy,
                backend=backend,
                replay_ledger=ledger,
                approver_session_ref="user-session:browser",
                now="2026-09-10T00:01:00Z",
                approval=grant,
                lease_repository=self.repo,
                lease=old_lease,
                writer_binding=old_binding,
            )
        self.assertEqual(grant.status, "ACTIVE")
        self.assertEqual(ledger.receipts, ())
        self.assertEqual(backend.commands, [])

    def test_backend_timeout_surfaces_consumed_approval_to_prevent_replay(self):
        action = self.interact_action()
        _, capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = FakeBackend(error=TimeoutError("ambiguous timeout"))
        with self.assertRaises(BrowserDispatchError) as caught:
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
        self.assertEqual(caught.exception.consumed_approval.status, "CONSUMED")

    def test_navigation_target_requires_independent_https_host_allowlist(self):
        action = self.navigate_action(url="https://evil.example/steal")
        _, capability, policy = self.navigate_authority(action)
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
        _, capability, policy = self.navigate_authority(action)
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

    def test_postcondition_mismatch_fails_closed_with_consumed_approval(self):
        action = self.interact_action(expected="dialog closed")
        _, capability, policy = self.interact_authority(action)
        grant = self.approval(action, policy)
        lease, binding = self.writer(action)
        backend = FakeBackend(
            BrowserInteractionBackendResult(
                post_observation=self.post(),
                observed_postconditions=("dialog still open",),
            )
        )
        with self.assertRaisesRegex(BrowserDispatchError, "BROWSER_POSTCONDITION_NOT_SATISFIED") as caught:
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
        self.assertEqual(caught.exception.consumed_approval.status, "CONSUMED")

    def test_action_without_declared_postcondition_never_dispatches(self):
        action = self.interact_action(expected=None)
        _, capability, policy = self.interact_authority(action)
        backend = FakeBackend()
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
