from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Mapping

from .computer_use import ComputerActionRequest, ComputerPolicyDecision
from .computer_use_approval import ComputerApprovalGrant, issue_computer_approval
from .computer_use_approval_view import (
    ComputerApprovalIntent,
    ComputerApprovalView,
    ComputerApprovalViewError,
    build_computer_approval_view,
    require_intent_matches_view,
)


class ComputerApprovalInboxError(RuntimeError):
    """Pending approval orchestration failed closed without granting authority."""


@dataclass(frozen=True)
class PendingComputerApproval:
    action: ComputerActionRequest
    policy_decision: ComputerPolicyDecision
    expires_at: str
    allow_session_scope: bool = False
    requires_user_takeover: bool = False
    takeover_active: bool = False
    closed: bool = False

    def validate(self) -> "PendingComputerApproval":
        self.action.validate()
        self.policy_decision.validate()
        if self.policy_decision.task_id != self.action.task_id:
            raise ComputerApprovalInboxError("PENDING_APPROVAL_POLICY_TASK_MISMATCH")
        if self.policy_decision.action_fingerprint != self.action.fingerprint:
            raise ComputerApprovalInboxError("PENDING_APPROVAL_POLICY_ACTION_MISMATCH")
        if self.policy_decision.outcome != "REQUIRE_APPROVAL":
            raise ComputerApprovalInboxError("PENDING_APPROVAL_POLICY_NOT_APPROVAL")
        if not isinstance(self.allow_session_scope, bool):
            raise ComputerApprovalInboxError("INVALID_PENDING_APPROVAL_SESSION_SCOPE")
        if not isinstance(self.requires_user_takeover, bool) or not isinstance(self.takeover_active, bool):
            raise ComputerApprovalInboxError("INVALID_PENDING_APPROVAL_TAKEOVER_STATE")
        if not isinstance(self.closed, bool):
            raise ComputerApprovalInboxError("INVALID_PENDING_APPROVAL_CLOSED_STATE")
        if self.takeover_active and not self.requires_user_takeover:
            raise ComputerApprovalInboxError("TAKEOVER_ACTIVE_WITHOUT_TAKEOVER_REQUIREMENT")
        return self

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.action.task_id, self.action.session_id, self.action.fingerprint)

    def view(self, *, current_state_sha256: str, now: str) -> ComputerApprovalView:
        self.validate()
        return build_computer_approval_view(
            action=self.action,
            policy_decision=self.policy_decision,
            current_state_sha256=current_state_sha256,
            now=now,
            expires_at=self.expires_at,
            allow_session_scope=self.allow_session_scope,
            requires_user_takeover=self.requires_user_takeover,
            takeover_active=self.takeover_active,
            closed=self.closed,
        )


@dataclass(frozen=True)
class ComputerApprovalInboxDecision:
    decision: str
    view: ComputerApprovalView
    grant: ComputerApprovalGrant | None = None


class ComputerApprovalInbox:
    """Process-local pending approval inbox; orchestration only, never authority.

    The inbox keeps canonical action/policy objects so a fresh backend view can be
    rebuilt against current state before every user decision. Only the bounded
    ComputerApprovalView is exposed to frontend callers. Approval authority is
    still minted exclusively by issue_computer_approval().
    """

    def __init__(self) -> None:
        self._pending: dict[tuple[str, str, str], PendingComputerApproval] = {}

    def register(self, pending: PendingComputerApproval) -> None:
        pending.validate()
        if pending.key in self._pending and not self._pending[pending.key].closed:
            raise ComputerApprovalInboxError("PENDING_APPROVAL_ALREADY_REGISTERED")
        self._pending[pending.key] = pending

    def _lookup(self, *, task_id: str, session_id: str, action_fingerprint: str) -> PendingComputerApproval:
        key = (task_id, session_id, action_fingerprint)
        pending = self._pending.get(key)
        if pending is None:
            raise ComputerApprovalInboxError("PENDING_APPROVAL_NOT_FOUND")
        return pending.validate()

    def get_view(
        self,
        *,
        task_id: str,
        session_id: str,
        action_fingerprint: str,
        current_state_sha256: str,
        now: str,
    ) -> ComputerApprovalView:
        return self._lookup(
            task_id=task_id,
            session_id=session_id,
            action_fingerprint=action_fingerprint,
        ).view(current_state_sha256=current_state_sha256, now=now)

    def dismiss(
        self,
        *,
        task_id: str,
        session_id: str,
        action_fingerprint: str,
    ) -> None:
        """Ambiguous UI dismissal is fail-closed and can never create approval."""

        pending = self._lookup(
            task_id=task_id,
            session_id=session_id,
            action_fingerprint=action_fingerprint,
        )
        self._pending[pending.key] = replace(pending, closed=True, takeover_active=False)

    def decide(
        self,
        *,
        payload: Mapping[str, Any],
        current_state_sha256: str,
        now: str,
        approver_session_ref: str,
        approval_id: str | None = None,
        approval_expires_at: str | None = None,
        session_max_actions: int = 1,
    ) -> ComputerApprovalInboxDecision:
        intent = ComputerApprovalIntent.from_mapping(payload)
        pending = self._lookup(
            task_id=intent.task_id,
            session_id=intent.session_id,
            action_fingerprint=intent.action_fingerprint,
        )
        view = pending.view(current_state_sha256=current_state_sha256, now=now)
        require_intent_matches_view(intent=intent, view=view)

        if intent.decision == "DENY":
            self._pending[pending.key] = replace(pending, closed=True, takeover_active=False)
            return ComputerApprovalInboxDecision(decision="DENY", view=view)

        if intent.decision == "BEGIN_TAKEOVER":
            updated = replace(pending, takeover_active=True)
            updated.validate()
            self._pending[pending.key] = updated
            return ComputerApprovalInboxDecision(decision="BEGIN_TAKEOVER", view=view)

        if intent.decision == "END_TAKEOVER":
            updated = replace(pending, takeover_active=False)
            updated.validate()
            self._pending[pending.key] = updated
            return ComputerApprovalInboxDecision(decision="END_TAKEOVER", view=view)

        if intent.decision != "APPROVE":
            raise ComputerApprovalInboxError("UNSUPPORTED_APPROVAL_INBOX_DECISION")
        if approval_id is None or approval_expires_at is None:
            raise ComputerApprovalInboxError("APPROVAL_ISSUANCE_METADATA_REQUIRED")

        max_actions = 1 if intent.scope == "one_shot" else session_max_actions
        grant = issue_computer_approval(
            approval_id=approval_id,
            action=pending.action,
            policy_decision=pending.policy_decision,
            approver_session_ref=approver_session_ref,
            scope=intent.scope,
            issued_at=now,
            expires_at=approval_expires_at,
            max_actions=max_actions,
        )
        self._pending[pending.key] = replace(pending, closed=True, takeover_active=False)
        return ComputerApprovalInboxDecision(decision="APPROVE", view=view, grant=grant)
