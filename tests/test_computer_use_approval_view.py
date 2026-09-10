import json
import unittest

from three_agent.computer_use import ComputerActionRequest, ComputerPolicyDecision
from three_agent.computer_use_approval_view import (
    ComputerApprovalIntent,
    ComputerApprovalViewError,
    build_computer_approval_view,
    require_intent_matches_view,
)

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64
H4 = "sha256:" + "4" * 64


def action(*, action_id="action:1", state=H2, arguments=None):
    return ComputerActionRequest(
        session_id="session:approval",
        action_id=action_id,
        task_id="task:approval",
        plan_fingerprint=H1,
        node_id="node:approval",
        provider_ref="local:approval",
        operation="browser.interact",
        effect="write",
        resource_kind="browser_document",
        resource_ref="browser:profile:isolated/tab:1",
        arguments=arguments or {"interaction": "click", "selector": "#confirm"},
        state_precondition_sha256=state,
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


def view_for(a=None, **kwargs):
    a = a or action()
    return build_computer_approval_view(
        action=a,
        policy_decision=policy(a),
        current_state_sha256=kwargs.pop("current_state_sha256", a.state_precondition_sha256),
        now=kwargs.pop("now", "2026-09-10T03:00:00Z"),
        expires_at=kwargs.pop("expires_at", "2026-09-10T03:05:00Z"),
        **kwargs,
    )


def intent_for(v, *, decision="APPROVE", scope="one_shot"):
    payload = {
        "decision": decision,
        "task_id": v.task_id,
        "session_id": v.session_id,
        "action_fingerprint": v.action_fingerprint,
        "state_precondition_sha256": v.state_precondition_sha256,
        "approval_view_fingerprint": v.fingerprint,
    }
    if decision == "APPROVE":
        payload["scope"] = scope
    return ComputerApprovalIntent.from_mapping(payload)


class ComputerApprovalViewTests(unittest.TestCase):
    def test_actionable_view_defaults_to_one_shot_and_explains_trusted_fields(self):
        v = view_for()
        d = v.canonical_dict()
        self.assertEqual(v.view_state, "ACTIONABLE")
        self.assertEqual(v.scope_options, ("one_shot",))
        self.assertEqual(d["operation"], "browser.interact")
        self.assertEqual(d["resource_ref"], "browser:profile:isolated/tab:1")
        self.assertEqual(d["risk_class"], "R2_STATE_CHANGE")
        self.assertEqual(d["reason_code"], "STATE_CHANGE_REQUIRES_APPROVAL")

    def test_session_scope_is_exposed_only_when_trusted_backend_allows_it(self):
        self.assertEqual(view_for().scope_options, ("one_shot",))
        self.assertEqual(
            view_for(allow_session_scope=True).scope_options,
            ("one_shot", "session_bounded"),
        )

    def test_view_never_contains_raw_arguments_or_credentials(self):
        a = action(arguments={
            "interaction": "type",
            "selector": "#password",
            "text": "TOP-SECRET-PASSWORD",
            "authorization": "Bearer SECRET-TOKEN",
        })
        rendered = json.dumps(view_for(a).canonical_dict(), sort_keys=True)
        self.assertNotIn("TOP-SECRET-PASSWORD", rendered)
        self.assertNotIn("SECRET-TOKEN", rendered)
        self.assertNotIn("arguments", rendered)
        self.assertNotIn("text", rendered)
        self.assertNotIn("authorization", rendered)

    def test_stale_expired_and_closed_views_have_no_scope(self):
        stale = view_for(current_state_sha256=H4)
        expired = view_for(now="2026-09-10T03:05:00Z", expires_at="2026-09-10T03:05:00Z")
        closed = view_for(closed=True)
        self.assertEqual((stale.view_state, stale.scope_options), ("STALE", ()))
        self.assertEqual((expired.view_state, expired.scope_options), ("EXPIRED", ()))
        self.assertEqual((closed.view_state, closed.scope_options), ("CLOSED", ()))
        for v in (stale, expired, closed):
            with self.assertRaisesRegex(ComputerApprovalViewError, "APPROVAL_VIEW_NOT_ACTIONABLE"):
                require_intent_matches_view(intent=intent_for(v, decision="DENY"), view=v)

    def test_policy_must_bind_exact_action(self):
        a1 = action(action_id="action:one")
        a2 = action(action_id="action:two")
        with self.assertRaisesRegex(ComputerApprovalViewError, "APPROVAL_VIEW_POLICY_ACTION_MISMATCH"):
            build_computer_approval_view(
                action=a2,
                policy_decision=policy(a1),
                current_state_sha256=a2.state_precondition_sha256,
                now="2026-09-10T03:00:00Z",
                expires_at="2026-09-10T03:05:00Z",
            )

    def test_action_a_view_cannot_authorize_action_b_or_changed_state(self):
        a1 = action(action_id="action:one")
        a2 = action(action_id="action:two")
        v1 = view_for(a1)
        i = intent_for(v1)
        v2 = view_for(a2)
        with self.assertRaisesRegex(ComputerApprovalViewError, "APPROVAL_INTENT_ACTION_MISMATCH"):
            require_intent_matches_view(intent=i, view=v2)
        stale_payload = {
            "decision": "APPROVE",
            "task_id": v1.task_id,
            "session_id": v1.session_id,
            "action_fingerprint": v1.action_fingerprint,
            "state_precondition_sha256": H4,
            "approval_view_fingerprint": v1.fingerprint,
            "scope": "one_shot",
        }
        with self.assertRaisesRegex(ComputerApprovalViewError, "APPROVAL_INTENT_STATE_MISMATCH"):
            require_intent_matches_view(
                intent=ComputerApprovalIntent.from_mapping(stale_payload), view=v1
            )

    def test_view_fingerprint_change_requires_fresh_confirmation(self):
        v1 = view_for()
        v2 = view_for(allow_session_scope=True)
        with self.assertRaisesRegex(ComputerApprovalViewError, "APPROVAL_INTENT_VIEW_STALE"):
            require_intent_matches_view(intent=intent_for(v1), view=v2)

    def test_unoffered_session_scope_and_extra_authority_fields_fail_closed(self):
        v = view_for()
        with self.assertRaisesRegex(ComputerApprovalViewError, "APPROVAL_INTENT_SCOPE_NOT_OFFERED"):
            require_intent_matches_view(
                intent=intent_for(v, scope="session_bounded"), view=v
            )
        base = {
            "decision": "APPROVE",
            "task_id": v.task_id,
            "session_id": v.session_id,
            "action_fingerprint": v.action_fingerprint,
            "state_precondition_sha256": v.state_precondition_sha256,
            "approval_view_fingerprint": v.fingerprint,
            "scope": "one_shot",
        }
        for forbidden in ("password", "token", "authority_fingerprint", "risk_class", "arguments"):
            with self.subTest(forbidden=forbidden):
                with self.assertRaisesRegex(ComputerApprovalViewError, "APPROVAL_INTENT_FIELD_NOT_ALLOWED"):
                    ComputerApprovalIntent.from_mapping({**base, forbidden: "attacker-controlled"})

    def test_takeover_entry_and_exit_are_explicit_and_approval_is_unavailable(self):
        waiting = view_for(requires_user_takeover=True)
        self.assertEqual(waiting.view_state, "TAKEOVER_REQUIRED")
        self.assertEqual(waiting.scope_options, ())
        begin = intent_for(waiting, decision="BEGIN_TAKEOVER")
        require_intent_matches_view(intent=begin, view=waiting)
        with self.assertRaisesRegex(ComputerApprovalViewError, "APPROVAL_VIEW_NOT_ACTIONABLE"):
            require_intent_matches_view(intent=intent_for(waiting), view=waiting)

        active = view_for(requires_user_takeover=True, takeover_active=True)
        require_intent_matches_view(intent=intent_for(active, decision="END_TAKEOVER"), view=active)
        with self.assertRaisesRegex(ComputerApprovalViewError, "TAKEOVER_ENTRY_NOT_AVAILABLE"):
            require_intent_matches_view(intent=intent_for(active, decision="BEGIN_TAKEOVER"), view=active)

    def test_deny_is_only_valid_for_live_actionable_or_takeover_views(self):
        actionable = view_for()
        takeover = view_for(requires_user_takeover=True)
        require_intent_matches_view(intent=intent_for(actionable, decision="DENY"), view=actionable)
        require_intent_matches_view(intent=intent_for(takeover, decision="DENY"), view=takeover)


if __name__ == "__main__":
    unittest.main()
