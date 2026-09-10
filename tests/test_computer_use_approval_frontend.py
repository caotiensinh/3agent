import unittest

from three_agent.computer_use import ComputerActionRequest, ComputerPolicyDecision
from three_agent.computer_use_approval_frontend import render_computer_approval_dialog
from three_agent.computer_use_approval_view import build_computer_approval_view

H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64
H3 = "sha256:" + "3" * 64
H4 = "sha256:" + "4" * 64


def action(*, arguments=None):
    return ComputerActionRequest(
        session_id="session:frontend",
        action_id="action:frontend",
        task_id="task:frontend",
        plan_fingerprint=H1,
        node_id="node:frontend",
        provider_ref="local:frontend",
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


def view(*, current_state=H2, now="2026-09-10T03:00:00Z", expires="2026-09-10T03:05:00Z", **kwargs):
    a = action(arguments=kwargs.pop("arguments", None))
    return build_computer_approval_view(
        action=a,
        policy_decision=policy(a),
        current_state_sha256=current_state,
        now=now,
        expires_at=expires,
        **kwargs,
    )


class ComputerApprovalFrontendTests(unittest.TestCase):
    def test_actionable_dialog_explains_action_resource_risk_and_exact_binding(self):
        v = view(allow_session_scope=True)
        html = render_computer_approval_dialog(v)
        self.assertIn('role="dialog"', html)
        self.assertIn("Interact with the isolated browser", html)
        self.assertIn("browser:profile:isolated/tab:1", html)
        self.assertIn("R2_STATE_CHANGE", html)
        self.assertIn("STATE_CHANGE_REQUIRES_APPROVAL", html)
        self.assertIn('data-scope="one_shot"', html)
        self.assertIn('data-scope="session_bounded"', html)
        self.assertIn(v.action_fingerprint, html)
        self.assertIn(v.state_precondition_sha256, html)
        self.assertIn(v.fingerprint, html)

    def test_stale_expired_closed_dialogs_have_no_decision_buttons(self):
        cases = (
            view(current_state=H4),
            view(now="2026-09-10T03:05:00Z", expires="2026-09-10T03:05:00Z"),
            view(closed=True),
        )
        for v in cases:
            with self.subTest(state=v.view_state):
                html = render_computer_approval_dialog(v)
                self.assertNotIn('data-decision="APPROVE"', html)
                self.assertNotIn('data-decision="DENY"', html)
                self.assertNotIn('data-decision="BEGIN_TAKEOVER"', html)
                self.assertNotIn('data-decision="END_TAKEOVER"', html)

    def test_takeover_entry_exit_are_explicit(self):
        waiting = render_computer_approval_dialog(view(requires_user_takeover=True))
        self.assertIn('data-decision="BEGIN_TAKEOVER"', waiting)
        self.assertIn('data-decision="DENY"', waiting)
        self.assertNotIn('data-decision="APPROVE"', waiting)

        active = render_computer_approval_dialog(
            view(requires_user_takeover=True, takeover_active=True)
        )
        self.assertNotIn('data-decision="BEGIN_TAKEOVER"', active)
        self.assertIn('data-decision="END_TAKEOVER"', active)
        self.assertNotIn('data-decision="APPROVE"', active)

    def test_raw_credentials_provider_text_and_html_injection_never_render(self):
        malicious = '<img src=x onerror=alert(1)>TOP-SECRET-PASSWORD'
        v = view(arguments={
            "interaction": "type",
            "selector": "#password",
            "text": malicious,
            "authorization": "Bearer SECRET-TOKEN",
        })
        html = render_computer_approval_dialog(v)
        self.assertNotIn("TOP-SECRET-PASSWORD", html)
        self.assertNotIn("SECRET-TOKEN", html)
        self.assertNotIn("onerror", html)
        self.assertNotIn("authorization", html)
        self.assertNotIn("selector", html)

    def test_renderer_uses_backend_scope_options_only(self):
        html = render_computer_approval_dialog(view(allow_session_scope=False))
        self.assertIn('data-scope="one_shot"', html)
        self.assertNotIn('data-scope="session_bounded"', html)


if __name__ == "__main__":
    unittest.main()
