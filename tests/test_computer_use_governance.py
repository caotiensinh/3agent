from __future__ import annotations

import unittest

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.computer_use import (
    ComputerActionRequest,
    decide_computer_action,
)
from three_agent.computer_use_approval import (
    ComputerApprovalError,
    consume_computer_approval,
    issue_computer_approval,
    require_valid_computer_approval,
)
from three_agent.task_contract import TaskContractCompiler, TaskContractError

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
NOW = "2026-09-10T00:00:00Z"
LATER = "2026-09-10T00:05:00Z"
EXPIRED = "2026-09-10T00:11:00Z"


def action(
    operation: str,
    *,
    resource_kind: str,
    resource_ref: str,
    state: str = H1,
    action_id: str = "action:1",
) -> ComputerActionRequest:
    policies = {
        "computer.screen.observe": ("read", "R0_OBSERVE", False),
        "browser.navigate": ("network_read", "R1_REVERSIBLE_INTERACTION", False),
        "browser.interact": ("write", "R2_STATE_CHANGE", True),
    }
    effect, risk, writer = policies[operation]
    return ComputerActionRequest(
        session_id="session:1",
        action_id=action_id,
        task_id="task:computer",
        plan_fingerprint=H2,
        node_id="node:1",
        operation=operation,
        effect=effect,
        resource_kind=resource_kind,
        resource_ref=resource_ref,
        arguments={},
        state_precondition_sha256=state,
        idempotency_key=H2,
        risk_class=risk,
        requires_writer=writer,
    ).validate()


class ComputerUseGovernanceTests(unittest.TestCase):
    def test_computer_tools_are_never_added_by_default(self):
        contract = TaskContractCompiler().compile(task_id="task:default")
        self.assertNotIn("computer.screen.observe", contract.allowed_tools)
        self.assertNotIn("browser.interact", contract.allowed_tools)

    def test_browser_navigation_requires_allowlisted_egress(self):
        with self.assertRaises(TaskContractError):
            TaskContractCompiler().compile(
                task_id="task:computer",
                sensitivity="public",
                allowed_tools=("browser.navigate",),
                public_web=False,
            )

    def test_public_browser_navigation_requires_and_receives_web_gateway(self):
        contract = TaskContractCompiler().compile(
            task_id="task:computer",
            sensitivity="public",
            allowed_tools=("browser.navigate",),
            public_web=True,
        )
        self.assertIn("web_gateway", contract.allowed_tools)
        authority = TaskCapabilityAuthority.from_contract(contract)
        decision = authority.authorize(
            "browser.navigate",
            resource_kind="browser_profile",
            resource_ref="browser:profile:isolated",
            effect="network_read",
        )
        self.assertTrue(decision.allowed)

    def test_confidential_task_cannot_turn_browser_navigation_into_core_egress(self):
        contract = TaskContractCompiler().compile(
            task_id="task:computer",
            sensitivity="confidential",
            allowed_tools=("browser.navigate",),
            public_web=True,
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        decision = authority.authorize(
            "browser.navigate",
            resource_kind="browser_profile",
            resource_ref="browser:profile:isolated",
            effect="network_read",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "NETWORK_SCOPE_NOT_AUTHORIZED")

    def test_computer_resource_shape_is_enforced(self):
        contract = TaskContractCompiler().compile(
            task_id="task:computer",
            sensitivity="internal",
            allowed_tools=("computer.screen.observe",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        wrong = authority.authorize(
            "computer.screen.observe",
            resource_kind="screen",
            resource_ref="local:desktop:window:main",
            effect="read",
        )
        self.assertFalse(wrong.allowed)
        self.assertEqual(wrong.reason_code, "RESOURCE_REF_NOT_AUTHORIZED")

    def test_r0_explicitly_authorized_observation_is_automatic(self):
        contract = TaskContractCompiler().compile(
            task_id="task:computer",
            sensitivity="internal",
            allowed_tools=("computer.screen.observe",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        item = action(
            "computer.screen.observe",
            resource_kind="screen",
            resource_ref="local:desktop:screen:primary",
        )
        cap = authority.authorize(
            item.operation,
            resource_kind=item.resource_kind,
            resource_ref=item.resource_ref,
            effect=item.effect,
        )
        policy = decide_computer_action(item, cap)
        self.assertEqual(policy.outcome, "ALLOW_AUTOMATIC")

    def test_r2_ui_write_requires_approval_without_filesystem_write_scope(self):
        contract = TaskContractCompiler().compile(
            task_id="task:computer",
            sensitivity="internal",
            allowed_tools=("browser.interact",),
            write_scope="none",
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        item = action(
            "browser.interact",
            resource_kind="browser_document",
            resource_ref="browser:profile:isolated/tab:tab1",
        )
        cap = authority.authorize(
            item.operation,
            resource_kind=item.resource_kind,
            resource_ref=item.resource_ref,
            effect=item.effect,
        )
        self.assertTrue(cap.allowed)
        policy = decide_computer_action(item, cap)
        self.assertEqual(policy.outcome, "REQUIRE_APPROVAL")

    def test_capability_denial_becomes_policy_denial(self):
        contract = TaskContractCompiler().compile(
            task_id="task:computer",
            sensitivity="internal",
            allowed_tools=("computer.screen.observe",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        item = action(
            "browser.interact",
            resource_kind="browser_document",
            resource_ref="browser:profile:isolated/tab:tab1",
        )
        cap = authority.authorize(
            item.operation,
            resource_kind=item.resource_kind,
            resource_ref=item.resource_ref,
            effect=item.effect,
        )
        policy = decide_computer_action(item, cap)
        self.assertEqual(policy.outcome, "DENY")

    def _approved_action(self):
        contract = TaskContractCompiler().compile(
            task_id="task:computer",
            sensitivity="internal",
            allowed_tools=("browser.interact",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        item = action(
            "browser.interact",
            resource_kind="browser_document",
            resource_ref="browser:profile:isolated/tab:tab1",
        )
        cap = authority.require(
            item.operation,
            resource_kind=item.resource_kind,
            resource_ref=item.resource_ref,
            effect=item.effect,
        )
        return item, decide_computer_action(item, cap)

    def test_approval_is_bound_to_exact_action_and_state(self):
        item, policy = self._approved_action()
        grant = issue_computer_approval(
            approval_id="approval:1",
            action=item,
            policy_decision=policy,
            approver_session_ref="user-session:1",
            scope="one_shot",
            issued_at=NOW,
            expires_at="2026-09-10T00:10:00Z",
        )
        require_valid_computer_approval(
            grant=grant,
            action=item,
            policy_decision=policy,
            approver_session_ref="user-session:1",
            now=LATER,
        )
        changed = action(
            "browser.interact",
            resource_kind="browser_document",
            resource_ref="browser:profile:isolated/tab:tab1",
            state=H2,
            action_id="action:2",
        )
        with self.assertRaises(ComputerApprovalError):
            require_valid_computer_approval(
                grant=grant,
                action=changed,
                policy_decision=policy,
                approver_session_ref="user-session:1",
                now=LATER,
            )

    def test_expired_approval_fails_closed(self):
        item, policy = self._approved_action()
        grant = issue_computer_approval(
            approval_id="approval:1",
            action=item,
            policy_decision=policy,
            approver_session_ref="user-session:1",
            scope="one_shot",
            issued_at=NOW,
            expires_at="2026-09-10T00:10:00Z",
        )
        with self.assertRaisesRegex(ComputerApprovalError, "APPROVAL_EXPIRED"):
            require_valid_computer_approval(
                grant=grant,
                action=item,
                policy_decision=policy,
                approver_session_ref="user-session:1",
                now=EXPIRED,
            )

    def test_one_shot_approval_cannot_be_replayed(self):
        item, policy = self._approved_action()
        grant = issue_computer_approval(
            approval_id="approval:1",
            action=item,
            policy_decision=policy,
            approver_session_ref="user-session:1",
            scope="one_shot",
            issued_at=NOW,
            expires_at="2026-09-10T00:10:00Z",
        )
        consumed = consume_computer_approval(
            grant=grant,
            action=item,
            policy_decision=policy,
            approver_session_ref="user-session:1",
            now=LATER,
        )
        self.assertEqual(consumed.status, "CONSUMED")
        with self.assertRaisesRegex(ComputerApprovalError, "APPROVAL_NOT_ACTIVE"):
            require_valid_computer_approval(
                grant=consumed,
                action=item,
                policy_decision=policy,
                approver_session_ref="user-session:1",
                now=LATER,
            )


if __name__ == "__main__":
    unittest.main()
