from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .computer_use import ComputerActionRequest
from .runtime_writer_lease import (
    RuntimeWriterLease,
    RuntimeWriterLeaseRepository,
)

COMPUTER_WRITER_BINDING_SCHEMA = "workspace-computer-writer-binding/v1"
COMPUTER_RETRY_DECISION_SCHEMA = "workspace-computer-retry-decision/v1"
POSTCONDITION_STATUSES = frozenset({"SATISFIED", "UNSATISFIED", "UNKNOWN"})
IDEMPOTENCY_STATUSES = frozenset({"SEEN", "NOT_SEEN", "UNKNOWN"})
RETRY_OUTCOMES = frozenset({"RETRY_ALLOWED", "NO_RETRY", "DENY_RETRY"})
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ComputerWriterError(RuntimeError):
    """Computer-use writer binding is missing, stale, or unsafe to retry."""


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ComputerWriterError("COMPUTER_WRITER_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _sha256(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ComputerWriterError(f"INVALID_{field.upper()}")
    return value


def _compact_id(value: Any, field: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _ID_RE.fullmatch(value):
        raise ComputerWriterError(f"INVALID_{field.upper()}")
    return value


@dataclass(frozen=True)
class ComputerWriterBinding:
    """Immutable binding between one mutating action and one writer generation.

    This object is not a writer authority. It is only a proof of which existing
    ``RuntimeWriterLease`` generation the action was admitted against. The lease
    repository must still be checked immediately before dispatch.
    """

    task_id: str
    plan_fingerprint: str
    action_fingerprint: str
    state_precondition_sha256: str
    idempotency_key: str
    lease_fingerprint: str
    run_id: str
    generation: int
    schema_version: str = COMPUTER_WRITER_BINDING_SCHEMA

    def validate(self) -> "ComputerWriterBinding":
        if self.schema_version != COMPUTER_WRITER_BINDING_SCHEMA:
            raise ComputerWriterError("COMPUTER_WRITER_BINDING_SCHEMA_VERSION_MISMATCH")
        _compact_id(self.task_id, "task_id")
        _sha256(self.plan_fingerprint, "plan_fingerprint")
        _sha256(self.action_fingerprint, "action_fingerprint")
        _sha256(self.state_precondition_sha256, "state_precondition_sha256")
        _sha256(self.idempotency_key, "idempotency_key")
        _sha256(self.lease_fingerprint, "lease_fingerprint")
        _compact_id(self.run_id, "run_id")
        if isinstance(self.generation, bool) or not isinstance(self.generation, int):
            raise ComputerWriterError("INVALID_COMPUTER_WRITER_GENERATION")
        if self.generation < 1:
            raise ComputerWriterError("INVALID_COMPUTER_WRITER_GENERATION")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_fingerprint": self.plan_fingerprint,
            "action_fingerprint": self.action_fingerprint,
            "state_precondition_sha256": self.state_precondition_sha256,
            "idempotency_key": self.idempotency_key,
            "lease_fingerprint": self.lease_fingerprint,
            "run_id": self.run_id,
            "generation": self.generation,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


@dataclass(frozen=True)
class ComputerRetryDecision:
    action_fingerprint: str
    writer_binding_fingerprint: str
    outcome: str
    reason_code: str
    schema_version: str = COMPUTER_RETRY_DECISION_SCHEMA

    def validate(self) -> "ComputerRetryDecision":
        if self.schema_version != COMPUTER_RETRY_DECISION_SCHEMA:
            raise ComputerWriterError("COMPUTER_RETRY_DECISION_SCHEMA_VERSION_MISMATCH")
        _sha256(self.action_fingerprint, "action_fingerprint")
        _sha256(self.writer_binding_fingerprint, "writer_binding_fingerprint")
        if self.outcome not in RETRY_OUTCOMES:
            raise ComputerWriterError("UNKNOWN_COMPUTER_RETRY_OUTCOME")
        _compact_id(self.reason_code, "reason_code")
        return self

    def canonical_dict(self) -> dict[str, str]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "action_fingerprint": self.action_fingerprint,
            "writer_binding_fingerprint": self.writer_binding_fingerprint,
            "outcome": self.outcome,
            "reason_code": self.reason_code,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


def _require_action_lease_match(
    action: ComputerActionRequest,
    lease: RuntimeWriterLease,
) -> None:
    action.validate()
    lease.validate()
    if action.requires_writer is not True:
        raise ComputerWriterError("COMPUTER_ACTION_DOES_NOT_REQUIRE_WRITER")
    if action.task_id != lease.task_id:
        raise ComputerWriterError("COMPUTER_WRITER_TASK_MISMATCH")
    if action.plan_fingerprint != lease.plan_fingerprint:
        raise ComputerWriterError("COMPUTER_WRITER_PLAN_MISMATCH")
    if lease.status != "ACTIVE":
        raise ComputerWriterError("COMPUTER_WRITER_LEASE_NOT_ACTIVE")


def bind_current_writer(
    *,
    action: ComputerActionRequest,
    lease_repository: RuntimeWriterLeaseRepository,
    lease: RuntimeWriterLease,
) -> ComputerWriterBinding:
    """Bind a mutating action to the exact current writer generation."""

    if not isinstance(lease_repository, RuntimeWriterLeaseRepository):
        raise TypeError("lease_repository must be RuntimeWriterLeaseRepository")
    _require_action_lease_match(action, lease)
    current = lease_repository.require_current(lease)
    return ComputerWriterBinding(
        task_id=action.task_id,
        plan_fingerprint=action.plan_fingerprint,
        action_fingerprint=action.fingerprint,
        state_precondition_sha256=action.state_precondition_sha256,
        idempotency_key=action.idempotency_key,
        lease_fingerprint=current.fingerprint,
        run_id=current.run_id,
        generation=current.generation,
    ).validate()


def require_current_writer_binding(
    *,
    action: ComputerActionRequest,
    binding: ComputerWriterBinding,
    lease_repository: RuntimeWriterLeaseRepository,
    lease: RuntimeWriterLease,
) -> RuntimeWriterLease:
    """Fail closed unless action, binding, and lease still name the current writer.

    Call this immediately before dispatch. A takeover after ``bind_current_writer``
    makes the old lease stale, so a previously issued binding cannot authorize a
    later side effect.
    """

    if not isinstance(lease_repository, RuntimeWriterLeaseRepository):
        raise TypeError("lease_repository must be RuntimeWriterLeaseRepository")
    action.validate()
    binding.validate()
    _require_action_lease_match(action, lease)
    if binding.task_id != action.task_id:
        raise ComputerWriterError("COMPUTER_WRITER_BINDING_TASK_MISMATCH")
    if binding.plan_fingerprint != action.plan_fingerprint:
        raise ComputerWriterError("COMPUTER_WRITER_BINDING_PLAN_MISMATCH")
    if binding.action_fingerprint != action.fingerprint:
        raise ComputerWriterError("COMPUTER_WRITER_BINDING_ACTION_STALE")
    if binding.state_precondition_sha256 != action.state_precondition_sha256:
        raise ComputerWriterError("COMPUTER_WRITER_BINDING_STATE_STALE")
    if binding.idempotency_key != action.idempotency_key:
        raise ComputerWriterError("COMPUTER_WRITER_BINDING_IDEMPOTENCY_MISMATCH")
    if binding.lease_fingerprint != lease.fingerprint:
        raise ComputerWriterError("COMPUTER_WRITER_BINDING_LEASE_MISMATCH")
    if binding.run_id != lease.run_id or binding.generation != lease.generation:
        raise ComputerWriterError("COMPUTER_WRITER_BINDING_GENERATION_STALE")
    current = lease_repository.require_current(lease)
    if current.fingerprint != binding.lease_fingerprint:
        raise ComputerWriterError("COMPUTER_WRITER_BINDING_NOT_CURRENT")
    return current


def decide_uncertain_side_effect_retry(
    *,
    action: ComputerActionRequest,
    binding: ComputerWriterBinding,
    lease_repository: RuntimeWriterLeaseRepository,
    lease: RuntimeWriterLease,
    postcondition_status: str,
    idempotency_status: str,
) -> ComputerRetryDecision:
    """Decide whether an uncertain mutating side effect may be re-executed.

    Retry is allowed only when the exact writer generation is still current, a
    declared postcondition is known to be unsatisfied, and the idempotency key is
    known not to have been observed. Unknown evidence fails closed.
    """

    require_current_writer_binding(
        action=action,
        binding=binding,
        lease_repository=lease_repository,
        lease=lease,
    )
    if postcondition_status not in POSTCONDITION_STATUSES:
        raise ComputerWriterError("UNKNOWN_POSTCONDITION_STATUS")
    if idempotency_status not in IDEMPOTENCY_STATUSES:
        raise ComputerWriterError("UNKNOWN_IDEMPOTENCY_STATUS")

    if action.expected_postcondition is None:
        outcome = "DENY_RETRY"
        reason = "RETRY_POSTCONDITION_NOT_DECLARED"
    elif postcondition_status == "SATISFIED":
        outcome = "NO_RETRY"
        reason = "POSTCONDITION_ALREADY_SATISFIED"
    elif idempotency_status == "SEEN":
        outcome = "NO_RETRY"
        reason = "IDEMPOTENCY_KEY_ALREADY_OBSERVED"
    elif postcondition_status == "UNKNOWN" or idempotency_status == "UNKNOWN":
        outcome = "DENY_RETRY"
        reason = "RETRY_EVIDENCE_UNCERTAIN"
    else:
        outcome = "RETRY_ALLOWED"
        reason = "POSTCONDITION_UNSATISFIED_AND_IDEMPOTENCY_NOT_SEEN"

    return ComputerRetryDecision(
        action_fingerprint=action.fingerprint,
        writer_binding_fingerprint=binding.fingerprint,
        outcome=outcome,
        reason_code=reason,
    ).validate()
