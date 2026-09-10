from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from typing import Any

from .computer_use import ComputerActionRequest, ComputerPolicyDecision

COMPUTER_APPROVAL_GRANT_SCHEMA = "workspace-computer-approval-grant/v1"
APPROVAL_SCOPES = frozenset({"one_shot", "session_bounded"})
APPROVAL_STATUSES = frozenset({"ACTIVE", "CONSUMED", "CANCELLED"})
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")
MAX_SESSION_ACTIONS = 32


class ComputerApprovalError(ValueError):
    """A computer-use approval is malformed, stale, expired, or mismatched."""


def _canonical_json(value: Any) -> str:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ComputerApprovalError("APPROVAL_NOT_CANONICAL_JSON") from exc


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(value).encode("utf-8")).hexdigest()


def _reference(value: Any, field: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _REF_RE.fullmatch(value):
        raise ComputerApprovalError(f"INVALID_{field.upper()}")
    if "://" in value or any(part == ".." for part in value.split("/")):
        raise ComputerApprovalError(f"INVALID_{field.upper()}")
    return value


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ComputerApprovalError(f"INVALID_{field.upper()}")
    return value


def _timestamp(value: Any, field: str) -> tuple[str, datetime]:
    if not isinstance(value, str) or value != value.strip() or not value:
        raise ComputerApprovalError(f"INVALID_{field.upper()}")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ComputerApprovalError(f"INVALID_{field.upper()}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ComputerApprovalError(f"{field.upper()}_MUST_BE_TIMEZONE_AWARE")
    parsed = parsed.astimezone(timezone.utc)
    canonical = parsed.isoformat().replace("+00:00", "Z")
    if canonical != value:
        raise ComputerApprovalError(f"{field.upper()}_MUST_BE_NORMALIZED_UTC")
    return canonical, parsed


@dataclass(frozen=True)
class ComputerApprovalGrant:
    approval_id: str
    task_id: str
    session_id: str
    action_fingerprint: str
    state_precondition_sha256: str
    authority_fingerprint: str
    policy_decision_fingerprint: str
    approver_session_ref: str
    scope: str
    issued_at: str
    expires_at: str
    max_actions: int = 1
    consumed_actions: int = 0
    status: str = "ACTIVE"
    schema_version: str = COMPUTER_APPROVAL_GRANT_SCHEMA

    def validate(self) -> "ComputerApprovalGrant":
        if self.schema_version != COMPUTER_APPROVAL_GRANT_SCHEMA:
            raise ComputerApprovalError("APPROVAL_SCHEMA_VERSION_MISMATCH")
        _reference(self.approval_id, "approval_id")
        _reference(self.task_id, "task_id")
        _reference(self.session_id, "session_id")
        _sha256(self.action_fingerprint, "action_fingerprint")
        _sha256(self.state_precondition_sha256, "state_precondition_sha256")
        _sha256(self.authority_fingerprint, "authority_fingerprint")
        _sha256(self.policy_decision_fingerprint, "policy_decision_fingerprint")
        _reference(self.approver_session_ref, "approver_session_ref")
        if self.scope not in APPROVAL_SCOPES:
            raise ComputerApprovalError("UNKNOWN_APPROVAL_SCOPE")
        if self.status not in APPROVAL_STATUSES:
            raise ComputerApprovalError("UNKNOWN_APPROVAL_STATUS")
        _, issued = _timestamp(self.issued_at, "issued_at")
        _, expires = _timestamp(self.expires_at, "expires_at")
        if expires <= issued:
            raise ComputerApprovalError("APPROVAL_EXPIRY_NOT_AFTER_ISSUE")
        if isinstance(self.max_actions, bool) or not isinstance(self.max_actions, int):
            raise ComputerApprovalError("INVALID_APPROVAL_MAX_ACTIONS")
        if self.scope == "one_shot" and self.max_actions != 1:
            raise ComputerApprovalError("ONE_SHOT_APPROVAL_REQUIRES_SINGLE_ACTION")
        if self.scope == "session_bounded" and not 1 <= self.max_actions <= MAX_SESSION_ACTIONS:
            raise ComputerApprovalError("SESSION_APPROVAL_ACTION_BOUND_INVALID")
        if isinstance(self.consumed_actions, bool) or not isinstance(self.consumed_actions, int):
            raise ComputerApprovalError("INVALID_APPROVAL_CONSUMED_ACTIONS")
        if not 0 <= self.consumed_actions <= self.max_actions:
            raise ComputerApprovalError("APPROVAL_CONSUMPTION_BOUND_INVALID")
        if self.status == "ACTIVE" and self.consumed_actions >= self.max_actions:
            raise ComputerApprovalError("ACTIVE_APPROVAL_EXHAUSTED")
        if self.status == "CONSUMED" and self.consumed_actions != self.max_actions:
            raise ComputerApprovalError("CONSUMED_APPROVAL_NOT_EXHAUSTED")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "approval_id": self.approval_id,
            "task_id": self.task_id,
            "session_id": self.session_id,
            "action_fingerprint": self.action_fingerprint,
            "state_precondition_sha256": self.state_precondition_sha256,
            "authority_fingerprint": self.authority_fingerprint,
            "policy_decision_fingerprint": self.policy_decision_fingerprint,
            "approver_session_ref": self.approver_session_ref,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "max_actions": self.max_actions,
            "consumed_actions": self.consumed_actions,
            "status": self.status,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


def issue_computer_approval(
    *,
    approval_id: str,
    action: ComputerActionRequest,
    policy_decision: ComputerPolicyDecision,
    approver_session_ref: str,
    scope: str,
    issued_at: str,
    expires_at: str,
    max_actions: int = 1,
) -> ComputerApprovalGrant:
    """Issue an approval that cannot broaden the already-authorized action."""

    action.validate()
    policy_decision.validate()
    if policy_decision.task_id != action.task_id:
        raise ComputerApprovalError("APPROVAL_POLICY_TASK_MISMATCH")
    if policy_decision.action_fingerprint != action.fingerprint:
        raise ComputerApprovalError("APPROVAL_POLICY_ACTION_MISMATCH")
    if policy_decision.outcome != "REQUIRE_APPROVAL":
        raise ComputerApprovalError("APPROVAL_NOT_REQUIRED_BY_POLICY")
    return ComputerApprovalGrant(
        approval_id=approval_id,
        task_id=action.task_id,
        session_id=action.session_id,
        action_fingerprint=action.fingerprint,
        state_precondition_sha256=action.state_precondition_sha256,
        authority_fingerprint=policy_decision.authority_fingerprint,
        policy_decision_fingerprint=policy_decision.fingerprint,
        approver_session_ref=approver_session_ref,
        scope=scope,
        issued_at=issued_at,
        expires_at=expires_at,
        max_actions=max_actions,
    ).validate()


def require_valid_computer_approval(
    *,
    grant: ComputerApprovalGrant,
    action: ComputerActionRequest,
    policy_decision: ComputerPolicyDecision,
    approver_session_ref: str,
    now: str,
) -> None:
    """Validate exact action, state, authority, identity, status, and expiry bindings."""

    grant.validate()
    action.validate()
    policy_decision.validate()
    if grant.status != "ACTIVE":
        raise ComputerApprovalError("APPROVAL_NOT_ACTIVE")
    _, now_dt = _timestamp(now, "now")
    _, issued_dt = _timestamp(grant.issued_at, "issued_at")
    _, expires_dt = _timestamp(grant.expires_at, "expires_at")
    if now_dt < issued_dt:
        raise ComputerApprovalError("APPROVAL_NOT_YET_VALID")
    if now_dt >= expires_dt:
        raise ComputerApprovalError("APPROVAL_EXPIRED")
    if grant.task_id != action.task_id or grant.session_id != action.session_id:
        raise ComputerApprovalError("APPROVAL_TASK_OR_SESSION_MISMATCH")
    if grant.action_fingerprint != action.fingerprint:
        raise ComputerApprovalError("APPROVAL_ACTION_MISMATCH")
    if grant.state_precondition_sha256 != action.state_precondition_sha256:
        raise ComputerApprovalError("APPROVAL_STATE_STALE")
    if grant.authority_fingerprint != policy_decision.authority_fingerprint:
        raise ComputerApprovalError("APPROVAL_AUTHORITY_MISMATCH")
    if grant.policy_decision_fingerprint != policy_decision.fingerprint:
        raise ComputerApprovalError("APPROVAL_POLICY_DECISION_MISMATCH")
    if policy_decision.outcome != "REQUIRE_APPROVAL":
        raise ComputerApprovalError("APPROVAL_POLICY_OUTCOME_MISMATCH")
    if policy_decision.action_fingerprint != action.fingerprint:
        raise ComputerApprovalError("APPROVAL_POLICY_ACTION_MISMATCH")
    if grant.approver_session_ref != _reference(approver_session_ref, "approver_session_ref"):
        raise ComputerApprovalError("APPROVER_SESSION_MISMATCH")


def consume_computer_approval(
    *,
    grant: ComputerApprovalGrant,
    action: ComputerActionRequest,
    policy_decision: ComputerPolicyDecision,
    approver_session_ref: str,
    now: str,
) -> ComputerApprovalGrant:
    """Consume one bounded approval unit and return immutable updated state."""

    require_valid_computer_approval(
        grant=grant,
        action=action,
        policy_decision=policy_decision,
        approver_session_ref=approver_session_ref,
        now=now,
    )
    consumed = grant.consumed_actions + 1
    status = "CONSUMED" if consumed >= grant.max_actions else "ACTIVE"
    return replace(grant, consumed_actions=consumed, status=status).validate()
