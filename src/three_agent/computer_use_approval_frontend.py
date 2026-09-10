from __future__ import annotations

from html import escape

from .computer_use_approval_view import ComputerApprovalView


def render_computer_approval_dialog(view: ComputerApprovalView) -> str:
    """Render a bounded Computer Use approval dialog from trusted view data only.

    The renderer never receives ComputerActionRequest.arguments and therefore
    cannot expose typed credentials, provider text, DOM instructions, or model
    prose. It renders plain escaped text and declarative decision buttons only;
    backend approval authority remains canonical.
    """

    data = view.canonical_dict()
    state = data["view_state"]
    actionable = state == "ACTIONABLE"
    takeover_waiting = state == "TAKEOVER_REQUIRED" and not data["takeover_active"]
    takeover_active = bool(data["takeover_active"])

    def text(value: object) -> str:
        return escape(str(value), quote=True)

    def button(label: str, decision: str, *, scope: str | None = None) -> str:
        attributes = [
            'type="button"',
            'class="soft-btn computer-approval-action"',
            f'data-decision="{text(decision)}"',
        ]
        if scope is not None:
            attributes.append(f'data-scope="{text(scope)}"')
        return f"<button {' '.join(attributes)}>{text(label)}</button>"

    actions: list[str] = []
    if actionable:
        actions.append(button("Approve once", "APPROVE", scope="one_shot"))
        if "session_bounded" in data["scope_options"]:
            actions.append(button("Approve for bounded session", "APPROVE", scope="session_bounded"))
        actions.append(button("Deny", "DENY"))
    elif takeover_waiting:
        actions.append(button("Take over", "BEGIN_TAKEOVER"))
        actions.append(button("Deny", "DENY"))
    if takeover_active:
        actions.append(button("Return control", "END_TAKEOVER"))

    fingerprint_fields = (
        f'<input type="hidden" data-computer-approval-field="task_id" value="{text(data["task_id"])}">'
        f'<input type="hidden" data-computer-approval-field="session_id" value="{text(data["session_id"])}">'
        f'<input type="hidden" data-computer-approval-field="action_fingerprint" value="{text(data["action_fingerprint"])}">'
        f'<input type="hidden" data-computer-approval-field="state_precondition_sha256" value="{text(data["state_precondition_sha256"])}">'
        f'<input type="hidden" data-computer-approval-field="approval_view_fingerprint" value="{text(view.fingerprint)}">'
    )

    status_copy = {
        "ACTIONABLE": "Review the exact action before allowing it.",
        "STALE": "This request is stale because the observed computer state changed. Refresh before deciding.",
        "EXPIRED": "This approval request expired. A fresh request is required.",
        "CLOSED": "This approval request is closed and cannot be acted on.",
        "TAKEOVER_REQUIRED": "Automation cannot continue safely. User takeover is required.",
    }[state]

    return (
        '<section class="computer-approval-modal" role="dialog" aria-modal="true" '
        'aria-labelledby="computerApprovalTitle" data-computer-approval-state="' + text(state) + '">'
        '<div class="computer-approval-card">'
        '<h2 id="computerApprovalTitle">Computer Use approval</h2>'
        f'<p class="computer-approval-status">{text(status_copy)}</p>'
        '<dl class="computer-approval-summary">'
        f'<dt>Action</dt><dd>{text(data["action_summary"])}</dd>'
        f'<dt>Operation</dt><dd>{text(data["operation"])}</dd>'
        f'<dt>Resource</dt><dd>{text(data["resource_kind"])} · {text(data["resource_ref"])}</dd>'
        f'<dt>Risk</dt><dd>{text(data["risk_class"])}</dd>'
        f'<dt>Why approval</dt><dd>{text(data["reason_code"])}</dd>'
        f'<dt>Expires</dt><dd>{text(data["expires_at"])}</dd>'
        '</dl>'
        '<p class="computer-approval-boundary">The page, model, and provider cannot grant this permission. '
        'The backend will re-check action, state, authority, approval scope, and writer ownership before execution.</p>'
        f'{fingerprint_fields}'
        '<div class="computer-approval-actions">' + ''.join(actions) + '</div>'
        '</div></section>'
    )
