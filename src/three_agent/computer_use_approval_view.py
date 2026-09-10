from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Mapping

from .computer_use import ComputerActionRequest, ComputerPolicyDecision

COMPUTER_APPROVAL_VIEW_SCHEMA = "workspace-computer-approval-view/v1"
COMPUTER_APPROVAL_INTENT_SCHEMA = "workspace-computer-approval-intent/v1"
APPROVAL_VIEW_STATES = frozenset({"ACTIONABLE", "STALE", "EXPIRED", "CLOSED", "TAKEOVER_REQUIRED"})
APPROVAL_DECISIONS = frozenset({"APPROVE", "DENY", "BEGIN_TAKEOVER", "END_TAKEOVER"})
APPROVAL_SCOPE_OPTIONS = frozenset({"one_shot", "session_bounded"})
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class ComputerApprovalViewError(ValueError):
    """Approval UX data is malformed, stale, or attempts to exceed backend authority."""


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError) as exc:
        raise ComputerApprovalViewError("APPROVAL_VIEW_NOT_CANONICAL_JSON") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _ref(value: Any, field: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _REF_RE.fullmatch(value):
        raise ComputerApprovalViewError(f"INVALID_{field.upper()}")
    if "://" in value or any(part == ".." for part in value.split("/")):
        raise ComputerApprovalViewError(f"INVALID_{field.upper()}")
    return value


def _sha(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ComputerApprovalViewError(f"INVALID_{field.upper()}")
    return value


def _instant(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ComputerApprovalViewError(f"INVALID_{field.upper()}")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ComputerApprovalViewError(f"INVALID_{field.upper()}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ComputerApprovalViewError(f"{field.upper()}_MUST_BE_TIMEZONE_AWARE")
    parsed = parsed.astimezone(timezone.utc)
    if parsed.isoformat().replace("+00:00", "Z") != value:
        raise ComputerApprovalViewError(f"{field.upper()}_MUST_BE_NORMALIZED_UTC")
    return parsed


def _summary_for(action: ComputerActionRequest) -> str:
    labels = {
        "browser.navigate": "Navigate the isolated browser",
        "browser.interact": "Interact with the isolated browser",
        "computer.pointer.interact": "Use the governed pointer",
        "computer.keyboard.interact": "Use the governed keyboard",
        "computer.clipboard.write": "Write to the governed clipboard",
    }
    return labels.get(action.operation, action.operation)


@dataclass(frozen=True)
class ComputerApprovalView:
    task_id: str
    session_id: str
    action_fingerprint: str
    state_precondition_sha256: str
    policy_decision_fingerprint: str
    operation: str
    resource_kind: str
    resource_ref: str
    risk_class: str
    reason_code: str
    action_summary: str
    view_state: str
    scope_options: tuple[str, ...]
    expires_at: str
    takeover_active: bool = False
    schema_version: str = COMPUTER_APPROVAL_VIEW_SCHEMA

    def canonical_dict(self) -> dict[str, Any]:
        if self.schema_version != COMPUTER_APPROVAL_VIEW_SCHEMA:
            raise ComputerApprovalViewError("APPROVAL_VIEW_SCHEMA_VERSION_MISMATCH")
        _ref(self.task_id, "task_id")
        _ref(self.session_id, "session_id")
        _sha(self.action_fingerprint, "action_fingerprint")
        _sha(self.state_precondition_sha256, "state_precondition_sha256")
        _sha(self.policy_decision_fingerprint, "policy_decision_fingerprint")
        _ref(self.operation, "operation")
        _ref(self.resource_kind, "resource_kind")
        _ref(self.resource_ref, "resource_ref")
        _ref(self.risk_class, "risk_class")
        _ref(self.reason_code, "reason_code")
        if not isinstance(self.action_summary, str) or not self.action_summary or len(self.action_summary) > 160:
            raise ComputerApprovalViewError("INVALID_APPROVAL_ACTION_SUMMARY")
        if self.view_state not in APPROVAL_VIEW_STATES:
            raise ComputerApprovalViewError("UNKNOWN_APPROVAL_VIEW_STATE")
        if not isinstance(self.scope_options, tuple) or not set(self.scope_options).issubset(APPROVAL_SCOPE_OPTIONS):
            raise ComputerApprovalViewError("INVALID_APPROVAL_SCOPE_OPTIONS")
        if len(set(self.scope_options)) != len(self.scope_options):
            raise ComputerApprovalViewError("DUPLICATE_APPROVAL_SCOPE_OPTION")
        _instant(self.expires_at, "expires_at")
        if not isinstance(self.takeover_active, bool):
            raise ComputerApprovalViewError("INVALID_TAKEOVER_ACTIVE")
        if self.view_state == "ACTIONABLE" and not self.scope_options:
            raise ComputerApprovalViewError("ACTIONABLE_APPROVAL_REQUIRES_SCOPE")
        if self.view_state != "ACTIONABLE" and self.scope_options:
            raise ComputerApprovalViewError("NON_ACTIONABLE_APPROVAL_HAS_SCOPE")
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "session_id": self.session_id,
            "action_fingerprint": self.action_fingerprint,
            "state_precondition_sha256": self.state_precondition_sha256,
            "policy_decision_fingerprint": self.policy_decision_fingerprint,
            "operation": self.operation,
            "resource_kind": self.resource_kind,
            "resource_ref": self.resource_ref,
            "risk_class": self.risk_class,
            "reason_code": self.reason_code,
            "action_summary": self.action_summary,
            "view_state": self.view_state,
            "scope_options": list(self.scope_options),
            "expires_at": self.expires_at,
            "takeover_active": self.takeover_active,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


@dataclass(frozen=True)
class ComputerApprovalIntent:
    decision: str
    task_id: str
    session_id: str
    action_fingerprint: str
    state_precondition_sha256: str
    approval_view_fingerprint: str
    scope: str | None = None
    schema_version: str = COMPUTER_APPROVAL_INTENT_SCHEMA

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ComputerApprovalIntent":
        if not isinstance(payload, Mapping):
            raise ComputerApprovalViewError("APPROVAL_INTENT_MUST_BE_OBJECT")
        allowed = {
            "schema_version", "decision", "task_id", "session_id", "action_fingerprint",
            "state_precondition_sha256", "approval_view_fingerprint", "scope",
        }
        if set(payload) - allowed:
            raise ComputerApprovalViewError("APPROVAL_INTENT_FIELD_NOT_ALLOWED")
        return cls(
            schema_version=payload.get("schema_version", COMPUTER_APPROVAL_INTENT_SCHEMA),
            decision=payload.get("decision"),
            task_id=payload.get("task_id"),
            session_id=payload.get("session_id"),
            action_fingerprint=payload.get("action_fingerprint"),
            state_precondition_sha256=payload.get("state_precondition_sha256"),
            approval_view_fingerprint=payload.get("approval_view_fingerprint"),
            scope=payload.get("scope"),
        ).validate()

    def validate(self) -> "ComputerApprovalIntent":
        if self.schema_version != COMPUTER_APPROVAL_INTENT_SCHEMA:
            raise ComputerApprovalViewError("APPROVAL_INTENT_SCHEMA_VERSION_MISMATCH")
        if self.decision not in APPROVAL_DECISIONS:
            raise ComputerApprovalViewError("UNKNOWN_APPROVAL_INTENT_DECISION")
        _ref(self.task_id, "task_id")
        _ref(self.session_id, "session_id")
        _sha(self.action_fingerprint, "action_fingerprint")
        _sha(self.state_precondition_sha256, "state_precondition_sha256")
        _sha(self.approval_view_fingerprint, "approval_view_fingerprint")
        if self.scope is not None and self.scope not in APPROVAL_SCOPE_OPTIONS:
            raise ComputerApprovalViewError("UNKNOWN_APPROVAL_INTENT_SCOPE")
        if self.decision == "APPROVE" and self.scope is None:
            raise ComputerApprovalViewError("APPROVAL_INTENT_SCOPE_REQUIRED")
        if self.decision != "APPROVE" and self.scope is not None:
            raise ComputerApprovalViewError("NON_APPROVAL_INTENT_HAS_SCOPE")
        return self


def build_computer_approval_view(
    *,
    action: ComputerActionRequest,
    policy_decision: ComputerPolicyDecision,
    current_state_sha256: str,
    now: str,
    expires_at: str,
    allow_session_scope: bool = False,
    requires_user_takeover: bool = False,
    takeover_active: bool = False,
    closed: bool = False,
) -> ComputerApprovalView:
    action.validate()
    policy_decision.validate()
    _sha(current_state_sha256, "current_state_sha256")
    now_dt = _instant(now, "now")
    expires_dt = _instant(expires_at, "expires_at")
    if policy_decision.task_id != action.task_id or policy_decision.action_fingerprint != action.fingerprint:
        raise ComputerApprovalViewError("APPROVAL_VIEW_POLICY_ACTION_MISMATCH")
    if policy_decision.outcome != "REQUIRE_APPROVAL":
        raise ComputerApprovalViewError("APPROVAL_VIEW_POLICY_NOT_APPROVAL")

    if closed:
        state = "CLOSED"
    elif current_state_sha256 != action.state_precondition_sha256:
        state = "STALE"
    elif now_dt >= expires_dt:
        state = "EXPIRED"
    elif requires_user_takeover:
        state = "TAKEOVER_REQUIRED"
    else:
        state = "ACTIONABLE"
    scopes: tuple[str, ...] = ()
    if state == "ACTIONABLE":
        scopes = ("one_shot", "session_bounded") if allow_session_scope else ("one_shot",)
    return ComputerApprovalView(
        task_id=action.task_id,
        session_id=action.session_id,
        action_fingerprint=action.fingerprint,
        state_precondition_sha256=action.state_precondition_sha256,
        policy_decision_fingerprint=policy_decision.fingerprint,
        operation=action.operation,
        resource_kind=action.resource_kind,
        resource_ref=action.resource_ref,
        risk_class=action.risk_class,
        reason_code=policy_decision.reason_code,
        action_summary=_summary_for(action),
        view_state=state,
        scope_options=scopes,
        expires_at=expires_at,
        takeover_active=takeover_active,
    )


def require_intent_matches_view(*, intent: ComputerApprovalIntent, view: ComputerApprovalView) -> None:
    intent.validate()
    view.canonical_dict()
    if intent.task_id != view.task_id or intent.session_id != view.session_id:
        raise ComputerApprovalViewError("APPROVAL_INTENT_TASK_OR_SESSION_MISMATCH")
    if intent.action_fingerprint != view.action_fingerprint:
        raise ComputerApprovalViewError("APPROVAL_INTENT_ACTION_MISMATCH")
    if intent.state_precondition_sha256 != view.state_precondition_sha256:
        raise ComputerApprovalViewError("APPROVAL_INTENT_STATE_MISMATCH")
    if intent.approval_view_fingerprint != view.fingerprint:
        raise ComputerApprovalViewError("APPROVAL_INTENT_VIEW_STALE")
    if intent.decision == "APPROVE":
        if view.view_state != "ACTIONABLE":
            raise ComputerApprovalViewError("APPROVAL_VIEW_NOT_ACTIONABLE")
        if intent.scope not in view.scope_options:
            raise ComputerApprovalViewError("APPROVAL_INTENT_SCOPE_NOT_OFFERED")
    elif intent.decision == "BEGIN_TAKEOVER":
        if view.view_state != "TAKEOVER_REQUIRED" or view.takeover_active:
            raise ComputerApprovalViewError("TAKEOVER_ENTRY_NOT_AVAILABLE")
    elif intent.decision == "END_TAKEOVER":
        if not view.takeover_active:
            raise ComputerApprovalViewError("TAKEOVER_EXIT_NOT_AVAILABLE")
