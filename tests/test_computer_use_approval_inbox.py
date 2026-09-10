import json
import unittest

from three_agent.computer_use import ComputerActionRequest, ComputerPolicyDecision
from three_agent.computer_use_approval_inbox import (
    ComputerApprovalInbox,
    ComputerApprovalInboxError,
    PendingComputerApproval,
)
from three_agent.computer_use_approval_view import ComputerApprovalViewError

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64
H4 = "sha256:" + "4" * 64
H5 = "sha256:" + "5" * 64
NOW = "2026-09-10T03:00:00Z"
VIEW_EXPIRY = "2026-09-10T03:05:00Z"
GRANT_EXPIRY = "2026-09-10T03:02:00Z"


def action(*, arguments=None):
    return ComputerActionRequest(
        session_id="session:approval",
        action_id="action:approval",
        task_id="task:approval",
        plan_fingerprint=H1,
        node_id="node:approval",
        provider_ref="local:approval",
        operation="browser.interact",
        effect="write",
        resource_kind="browser_document",
        resource_ref="browser:profile:isolated/tab:1",
        arguments=arguments or {"interaction": "click", "selector": "#confirm"},
        state_precondition_sha256=H2,
        idempotency_key=H3,
        risk_class="R2_STATE_CHANGE",
        requires_writer=True,
        expected_postcondition="confirmation-visible",
    ).validate()


def policy(a):
    return ComputerPolicyDecision(
        task_id=a.task_id,
        action_fingerprint=a.fingerprint,
        authority_fingerprint=H4,
        outcome="REQUIRE_APPROVAL",
        reason_code="STATE_CHANGE_REQUIRES_APPROVAL",
    ).validate()


def pending(*, allow_session_scope=False, requires_user_takeover=False, arguments=None):
    a = action(arguments=arguments)
    return PendingComputerApproval(
        action=a,
        policy_decision=policy(a),
        expires_at=VIEW_EXPIRY,
        allow_session_scope=allow_session_scope,
        requires_user_takeover=requires_user_takeover,
    ).validate()


def intent_payload(view, *, decision="APPROVE", scope="one_shot"):
    payload = {
        "decision": decision,
        "task_id": view.task_id,
        "session_id": view.session_id,
        "action_fingerprint": view.action_fingerprint,
        "state_precondition_sha256": view.state_precondition_sha256,
        "approval_view_fingerprint": view.fingerprint,
    }
    if decision == "APPROVE":
        payload["scope"] = scope
    return payload


class ComputerApprovalInboxTests(unittest.TestCase):
    def test_frontend_view_is_rebuilt_from_canonical_pending_state_without_arguments(self):
        box = ComputerApprovalInbox()
        p = pending(arguments={
            "interaction": "type",
            "selector": "#password",
            "text": "TOP-SECRET-PASSWORD",
        })
        box.register(p)
        view = box.get_view(
            task_id=p.action.task_id,
            session_id=p.action.session_id,
            action_fingerprint=p.action.fingerprint,
            current_state_sha256=H2,
            now=NOW,
        )
        rendered = json.dumps(view.canonical_dict(), sort_keys=True)
        self.assertEqual(view.view_state, "ACTIONABLE")
        self.assertNotIn("TOP-SECRET-PASSWORD", rendered)
        self.assertNotIn("arguments", rendered)

    def test_approve_issues_only_canonical_action_bound_grant_and_closes_pending_request(self):
        box = ComputerApprovalInbox()
        p = pending()
        box.register(p)
        view = box.get_view(
            task_id=p.action.task_id,
            session_id=p.action.session_id,
            action_fingerprint=p.action.fingerprint,
            current_state_sha256=H2,
            now=NOW,
        )
        result = box.decide(
            payload=intent_payload(view),
            current_state_sha256=H2,
            now=NOW,
            approver_session_ref="user-session:1",
            approval_id="approval:1",
            approval_expires_at=GRANT_EXPIRY,
        )
        self.assertEqual(result.decision, "APPROVE")
        self.assertIsNotNone(result.grant)
        self.assertEqual(result.grant.action_fingerprint, p.action.fingerprint)
        self.assertEqual(result.grant.authority_fingerprint, p.policy_decision.authority_fingerprint)
        closed = box.get_view(
            task_id=p.action.task_id,
            session_id=p.action.session_id,
            action_fingerprint=p.action.fingerprint,
            current_state_sha256=H2,
            now=NOW,
        )
        self.assertEqual(closed.view_state, "CLOSED")
        with self.assertRaisesRegex(ComputerApprovalViewError, "APPROVAL_VIEW_NOT_ACTIONABLE"):
            box.decide(
                payload=intent_payload(view),
                current_state_sha256=H2,
                now=NOW,
                approver_session_ref="user-session:1",
                approval_id="approval:2",
                approval_expires_at=GRANT_EXPIRY,
            )

    def test_stale_state_cannot_issue_grant_even_with_previous_actionable_view(self):
        box = ComputerApprovalInbox()
        p = pending()
        box.register(p)
        view = box.get_view(
            task_id=p.action.task_id,
            session_id=p.action.session_id,
            action_fingerprint=p.action.fingerprint,
            current_state_sha256=H2,
            now=NOW,
        )
        with self.assertRaisesRegex(ComputerApprovalViewError, "APPROVAL_INTENT_VIEW_STALE"):
            box.decide(
                payload=intent_payload(view),
                current_state_sha256=H5,
                now=NOW,
                approver_session_ref="user-session:1",
                approval_id="approval:stale",
                approval_expires_at=GRANT_EXPIRY,
            )

    def test_deny_and_ambiguous_dismissal_close_without_grant(self):
        for mode in ("deny", "dismiss"):
            with self.subTest(mode=mode):
                box = ComputerApprovalInbox()
                p = pending()
                box.register(p)
                view = box.get_view(
                    task_id=p.action.task_id,
                    session_id=p.action.session_id,
                    action_fingerprint=p.action.fingerprint,
                    current_state_sha256=H2,
                    now=NOW,
                )
                if mode == "deny":
                    result = box.decide(
                        payload=intent_payload(view, decision="DENY"),
                        current_state_sha256=H2,
                        now=NOW,
                        approver_session_ref="user-session:1",
                    )
                    self.assertIsNone(result.grant)
                else:
                    box.dismiss(
                        task_id=p.action.task_id,
                        session_id=p.action.session_id,
                        action_fingerprint=p.action.fingerprint,
                    )
                closed = box.get_view(
                    task_id=p.action.task_id,
                    session_id=p.action.session_id,
                    action_fingerprint=p.action.fingerprint,
                    current_state_sha256=H2,
                    now=NOW,
                )
                self.assertEqual(closed.view_state, "CLOSED")

    def test_takeover_entry_and_exit_change_only_orchestration_state(self):
        box = ComputerApprovalInbox()
        p = pending(requires_user_takeover=True)
        box.register(p)
        waiting = box.get_view(
            task_id=p.action.task_id,
            session_id=p.action.session_id,
            action_fingerprint=p.action.fingerprint,
            current_state_sha256=H2,
            now=NOW,
        )
        self.assertEqual(waiting.view_state, "TAKEOVER_REQUIRED")
        begin = box.decide(
            payload=intent_payload(waiting, decision="BEGIN_TAKEOVER"),
            current_state_sha256=H2,
            now=NOW,
            approver_session_ref="user-session:1",
        )
        self.assertIsNone(begin.grant)
        active = box.get_view(
            task_id=p.action.task_id,
            session_id=p.action.session_id,
            action_fingerprint=p.action.fingerprint,
            current_state_sha256=H2,
            now=NOW,
        )
        self.assertTrue(active.takeover_active)
        box.decide(
            payload=intent_payload(active, decision="END_TAKEOVER"),
            current_state_sha256=H2,
            now=NOW,
            approver_session_ref="user-session:1",
        )
        returned = box.get_view(
            task_id=p.action.task_id,
            session_id=p.action.session_id,
            action_fingerprint=p.action.fingerprint,
            current_state_sha256=H2,
            now=NOW,
        )
        self.assertFalse(returned.takeover_active)
        self.assertEqual(returned.view_state, "TAKEOVER_REQUIRED")

    def test_session_scope_is_backend_gated_and_action_count_is_bounded(self):
        box = ComputerApprovalInbox()
        p = pending(allow_session_scope=True)
        box.register(p)
        view = box.get_view(
            task_id=p.action.task_id,
            session_id=p.action.session_id,
            action_fingerprint=p.action.fingerprint,
            current_state_sha256=H2,
            now=NOW,
        )
        result = box.decide(
            payload=intent_payload(view, scope="session_bounded"),
            current_state_sha256=H2,
            now=NOW,
            approver_session_ref="user-session:1",
            approval_id="approval:session",
            approval_expires_at=GRANT_EXPIRY,
            session_max_actions=3,
        )
        self.assertEqual(result.grant.scope, "session_bounded")
        self.assertEqual(result.grant.max_actions, 3)

    def test_duplicate_live_registration_is_rejected(self):
        box = ComputerApprovalInbox()
        p = pending()
        box.register(p)
        with self.assertRaisesRegex(ComputerApprovalInboxError, "PENDING_APPROVAL_ALREADY_REGISTERED"):
            box.register(p)


if __name__ == "__main__":
    unittest.main()
