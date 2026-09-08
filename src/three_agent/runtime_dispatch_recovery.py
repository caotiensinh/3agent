from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable, Mapping, Protocol

from .capability_authority import TaskCapabilityAuthority
from .capability_revocation import CapabilityRevocation, REVOCATION_SCHEMA
from .execution_budget import ExecutionBudgetExceeded
from .execution_observation import ExecutionObservation
from .execution_plan import ExecutionPlan
from .runtime_checkpoint import (
    RuntimeCheckpoint,
    RuntimeCheckpointError,
    RuntimeRecovery,
    RuntimeRecoveryDecision,
)
from .task_context import TaskContext

RUNTIME_DISPATCH_RECOVERY_BINDING_SCHEMA = "workspace-runtime-dispatch-recovery-binding/v1"
RUNTIME_DISPATCH_RECOVERY_BINDING_ENVELOPE_SCHEMA = (
    "workspace-runtime-dispatch-recovery-binding-envelope/v1"
)
RUNTIME_DISPATCH_RECOVERY_DECISION_SCHEMA = "workspace-runtime-dispatch-recovery-decision/v1"
EXECUTION_SCHEDULER_SCHEMA = "workspace-execution-scheduler/v1"
BUDGET_STATE_SCHEMA = "workspace-task-execution-budget-state/v2"
MAX_SCHEDULER_CONCURRENCY = 24

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-=]{0,127}$")
_REASON_RE = re.compile(r"^[A-Z][A-Z0-9_]{1,127}$")
_RECOVERY_STATUSES = frozenset(
    {"RECOVERABLE", "MANUAL_RECONCILIATION", "BLOCKED", "COMPLETE"}
)


class RuntimeDispatchRecoveryError(ValueError):
    """Dispatch recovery state violates a fail-closed runtime invariant."""


class DispatchRecoveryBudgetGuard(Protocol):
    def assert_active(self) -> None: ...

    def snapshot(self) -> dict[str, int | str]: ...


class DispatchRecoveryRevocationGuard(Protocol):
    def list_for_task(self, task_id: str) -> tuple[CapabilityRevocation, ...]: ...


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
        raise RuntimeDispatchRecoveryError(
            "DISPATCH_RECOVERY_NOT_CANONICAL_JSON"
        ) from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(
        _canonical_json(payload).encode("utf-8")
    ).hexdigest()


def _compact(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _ID_RE.fullmatch(value):
        raise RuntimeDispatchRecoveryError(f"INVALID_{field_name.upper()}")
    return value


def _bounded_text(value: Any, field_name: str, *, max_len: int = 256) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > max_len
        or "\n" in value
        or "\r" in value
    ):
        raise RuntimeDispatchRecoveryError(f"INVALID_{field_name.upper()}")
    return value


def _sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise RuntimeDispatchRecoveryError(f"INVALID_{field_name.upper()}")
    return value


def _timestamp(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise RuntimeDispatchRecoveryError(f"INVALID_{field_name.upper()}")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise RuntimeDispatchRecoveryError(f"INVALID_{field_name.upper()}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RuntimeDispatchRecoveryError(
            f"{field_name.upper()}_MUST_BE_TIMEZONE_AWARE"
        )
    return value


def _nonnegative_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise RuntimeDispatchRecoveryError(f"INVALID_{field_name.upper()}")
    return value


def _positive_int(value: Any, field_name: str) -> int:
    result = _nonnegative_int(value, field_name)
    if result < 1:
        raise RuntimeDispatchRecoveryError(f"INVALID_{field_name.upper()}")
    return result


def _normalized_ids(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise RuntimeDispatchRecoveryError(f"INVALID_{field_name.upper()}")
    result = tuple(sorted(_compact(value, field_name) for value in values))
    if len(result) != len(set(result)):
        raise RuntimeDispatchRecoveryError(f"DUPLICATE_{field_name.upper()}")
    return result


def _normalized_hashes(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise RuntimeDispatchRecoveryError(f"INVALID_{field_name.upper()}")
    result = tuple(sorted(_sha256(value, field_name) for value in values))
    if len(result) != len(set(result)):
        raise RuntimeDispatchRecoveryError(f"DUPLICATE_{field_name.upper()}")
    return result


@dataclass(frozen=True)
class RuntimeBudgetSnapshot:
    task_id: str
    max_steps: int
    max_tool_calls: int
    max_model_retries: int
    max_model_escalations: int
    max_wall_time_ms: int
    steps_used: int
    tool_calls_used: int
    model_retries_used: int
    model_escalations_used: int
    deadline_at: str
    schema_version: str = BUDGET_STATE_SCHEMA

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "RuntimeBudgetSnapshot":
        if not isinstance(payload, Mapping):
            raise RuntimeDispatchRecoveryError("BUDGET_SNAPSHOT_NOT_MAPPING")
        expected = {
            "schema_version",
            "task_id",
            "max_steps",
            "max_tool_calls",
            "max_model_retries",
            "max_model_escalations",
            "max_wall_time_ms",
            "steps_used",
            "tool_calls_used",
            "model_retries_used",
            "model_escalations_used",
            "deadline_at",
        }
        if set(payload) != expected:
            raise RuntimeDispatchRecoveryError("BUDGET_SNAPSHOT_SHAPE_INVALID")
        return cls(
            task_id=payload["task_id"],
            max_steps=payload["max_steps"],
            max_tool_calls=payload["max_tool_calls"],
            max_model_retries=payload["max_model_retries"],
            max_model_escalations=payload["max_model_escalations"],
            max_wall_time_ms=payload["max_wall_time_ms"],
            steps_used=payload["steps_used"],
            tool_calls_used=payload["tool_calls_used"],
            model_retries_used=payload["model_retries_used"],
            model_escalations_used=payload["model_escalations_used"],
            deadline_at=payload["deadline_at"],
            schema_version=payload["schema_version"],
        ).validate()

    def validate(self) -> "RuntimeBudgetSnapshot":
        if self.schema_version != BUDGET_STATE_SCHEMA:
            raise RuntimeDispatchRecoveryError(
                "BUDGET_SNAPSHOT_SCHEMA_VERSION_MISMATCH"
            )
        _compact(self.task_id, "budget_task_id")
        _positive_int(self.max_steps, "max_steps")
        _nonnegative_int(self.max_tool_calls, "max_tool_calls")
        _nonnegative_int(self.max_model_retries, "max_model_retries")
        _nonnegative_int(self.max_model_escalations, "max_model_escalations")
        if _nonnegative_int(self.max_wall_time_ms, "max_wall_time_ms") < 100:
            raise RuntimeDispatchRecoveryError("INVALID_MAX_WALL_TIME_MS")
        for value, maximum, field_name in (
            (self.steps_used, self.max_steps, "steps_used"),
            (self.tool_calls_used, self.max_tool_calls, "tool_calls_used"),
            (self.model_retries_used, self.max_model_retries, "model_retries_used"),
            (
                self.model_escalations_used,
                self.max_model_escalations,
                "model_escalations_used",
            ),
        ):
            used = _nonnegative_int(value, field_name)
            if used > maximum:
                raise RuntimeDispatchRecoveryError(
                    f"{field_name.upper()}_EXCEEDS_LIMIT"
                )
        _timestamp(self.deadline_at, "budget_deadline_at")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "max_steps": self.max_steps,
            "max_tool_calls": self.max_tool_calls,
            "max_model_retries": self.max_model_retries,
            "max_model_escalations": self.max_model_escalations,
            "max_wall_time_ms": self.max_wall_time_ms,
            "steps_used": self.steps_used,
            "tool_calls_used": self.tool_calls_used,
            "model_retries_used": self.model_retries_used,
            "model_escalations_used": self.model_escalations_used,
            "deadline_at": self.deadline_at,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())

    @property
    def immutable_tuple(self) -> tuple[int | str, ...]:
        return (
            self.task_id,
            self.max_steps,
            self.max_tool_calls,
            self.max_model_retries,
            self.max_model_escalations,
            self.max_wall_time_ms,
            self.deadline_at,
        )

    @property
    def counters(self) -> tuple[int, int, int, int]:
        return (
            self.steps_used,
            self.tool_calls_used,
            self.model_retries_used,
            self.model_escalations_used,
        )


@dataclass(frozen=True)
class RuntimeRevocationSnapshot:
    task_id: str
    capability: str
    reason_code: str
    revoked_at: str

    @classmethod
    def from_revocation(
        cls,
        value: CapabilityRevocation | Mapping[str, Any],
    ) -> "RuntimeRevocationSnapshot":
        if isinstance(value, CapabilityRevocation):
            return cls(
                task_id=value.task_id,
                capability=value.capability,
                reason_code=value.reason_code,
                revoked_at=value.revoked_at,
            ).validate()
        if not isinstance(value, Mapping):
            raise RuntimeDispatchRecoveryError("INVALID_REVOCATION_SNAPSHOT")
        plain = {"task_id", "capability", "reason_code", "revoked_at"}
        with_schema = plain | {"schema_version"}
        if set(value) not in (plain, with_schema):
            raise RuntimeDispatchRecoveryError("REVOCATION_SNAPSHOT_SHAPE_INVALID")
        if "schema_version" in value and value["schema_version"] != REVOCATION_SCHEMA:
            raise RuntimeDispatchRecoveryError(
                "REVOCATION_SNAPSHOT_SCHEMA_VERSION_MISMATCH"
            )
        return cls(
            task_id=value["task_id"],
            capability=value["capability"],
            reason_code=value["reason_code"],
            revoked_at=value["revoked_at"],
        ).validate()

    def validate(self) -> "RuntimeRevocationSnapshot":
        _compact(self.task_id, "revocation_task_id")
        _compact(self.capability, "revoked_capability")
        if not isinstance(self.reason_code, str) or not _REASON_RE.fullmatch(
            self.reason_code
        ):
            raise RuntimeDispatchRecoveryError("INVALID_REVOCATION_REASON_CODE")
        _timestamp(self.revoked_at, "revoked_at")
        return self

    def canonical_dict(self) -> dict[str, str]:
        self.validate()
        return {
            "task_id": self.task_id,
            "capability": self.capability,
            "reason_code": self.reason_code,
            "revoked_at": self.revoked_at,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


@dataclass(frozen=True)
class RuntimeDispatchRecoveryBinding:
    binding_id: str
    runtime_checkpoint_fingerprint: str
    task_id: str
    task_context_fingerprint: str
    plan_fingerprint: str
    parent_authority_fingerprint: str
    scheduler_state_fingerprint: str
    max_concurrency: int
    cancelled: bool
    cancellation_reason: str | None
    dispatch_sequence: int
    approved_node_ids: tuple[str, ...]
    in_flight_ticket_fingerprints: tuple[str, ...]
    observation_fingerprints: tuple[str, ...]
    budget: RuntimeBudgetSnapshot
    revocations: tuple[RuntimeRevocationSnapshot, ...]
    captured_at: str
    schema_version: str = RUNTIME_DISPATCH_RECOVERY_BINDING_SCHEMA

    def validate(self) -> "RuntimeDispatchRecoveryBinding":
        if self.schema_version != RUNTIME_DISPATCH_RECOVERY_BINDING_SCHEMA:
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_BINDING_SCHEMA_VERSION_MISMATCH"
            )
        _compact(self.binding_id, "binding_id")
        _compact(self.task_id, "task_id")
        for value, field_name in (
            (
                self.runtime_checkpoint_fingerprint,
                "runtime_checkpoint_fingerprint",
            ),
            (self.task_context_fingerprint, "task_context_fingerprint"),
            (self.plan_fingerprint, "plan_fingerprint"),
            (self.parent_authority_fingerprint, "parent_authority_fingerprint"),
            (self.scheduler_state_fingerprint, "scheduler_state_fingerprint"),
        ):
            _sha256(value, field_name)
        if not isinstance(self.cancelled, bool):
            raise RuntimeDispatchRecoveryError("INVALID_CANCELLED_FLAG")
        concurrency = _positive_int(self.max_concurrency, "max_concurrency")
        if concurrency > MAX_SCHEDULER_CONCURRENCY:
            raise RuntimeDispatchRecoveryError("MAX_CONCURRENCY_EXCEEDS_RUNTIME_LIMIT")
        _nonnegative_int(self.dispatch_sequence, "dispatch_sequence")
        if self.cancelled:
            _bounded_text(self.cancellation_reason, "cancellation_reason")
        elif self.cancellation_reason is not None:
            raise RuntimeDispatchRecoveryError("UNEXPECTED_CANCELLATION_REASON")
        if self.approved_node_ids != _normalized_ids(
            self.approved_node_ids,
            "approved_node_id",
        ):
            raise RuntimeDispatchRecoveryError("APPROVED_NODE_IDS_NOT_NORMALIZED")
        if self.in_flight_ticket_fingerprints != _normalized_hashes(
            self.in_flight_ticket_fingerprints,
            "in_flight_ticket_fingerprint",
        ):
            raise RuntimeDispatchRecoveryError(
                "IN_FLIGHT_TICKET_FINGERPRINTS_NOT_NORMALIZED"
            )
        if self.observation_fingerprints != _normalized_hashes(
            self.observation_fingerprints,
            "observation_fingerprint",
        ):
            raise RuntimeDispatchRecoveryError(
                "OBSERVATION_FINGERPRINTS_NOT_NORMALIZED"
            )
        self.budget.validate()
        if self.budget.task_id != self.task_id:
            raise RuntimeDispatchRecoveryError("BUDGET_TASK_MISMATCH")
        seen: set[str] = set()
        for row in self.revocations:
            row.validate()
            if row.task_id != self.task_id:
                raise RuntimeDispatchRecoveryError("REVOCATION_TASK_MISMATCH")
            if row.capability in seen:
                raise RuntimeDispatchRecoveryError("DUPLICATE_REVOKED_CAPABILITY")
            seen.add(row.capability)
        if tuple(sorted(self.revocations, key=lambda row: row.capability)) != self.revocations:
            raise RuntimeDispatchRecoveryError("REVOCATIONS_NOT_NORMALIZED")
        _timestamp(self.captured_at, "captured_at")
        expected_id = "dispatch-recovery:" + self.fingerprint.split(":", 1)[1][:24]
        if self.binding_id != expected_id:
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_BINDING_IDENTITY_MISMATCH"
            )
        return self

    def _identity_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "runtime_checkpoint_fingerprint": self.runtime_checkpoint_fingerprint,
            "task_id": self.task_id,
            "task_context_fingerprint": self.task_context_fingerprint,
            "plan_fingerprint": self.plan_fingerprint,
            "parent_authority_fingerprint": self.parent_authority_fingerprint,
            "scheduler_state_fingerprint": self.scheduler_state_fingerprint,
            "max_concurrency": self.max_concurrency,
            "cancelled": self.cancelled,
            "cancellation_reason": self.cancellation_reason,
            "dispatch_sequence": self.dispatch_sequence,
            "approved_node_ids": list(self.approved_node_ids),
            "in_flight_ticket_fingerprints": list(
                self.in_flight_ticket_fingerprints
            ),
            "observation_fingerprints": list(self.observation_fingerprints),
            "budget": self.budget.canonical_dict(),
            "revocations": [row.canonical_dict() for row in self.revocations],
            "captured_at": self.captured_at,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self._identity_dict())

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {"binding_id": self.binding_id, **self._identity_dict()}


class RuntimeDispatchRecoveryBindingBuilder:
    @staticmethod
    def build(
        *,
        checkpoint: RuntimeCheckpoint,
        scheduler_snapshot: Mapping[str, Any],
        budget_snapshot: Mapping[str, Any],
        revocations: Iterable[CapabilityRevocation | Mapping[str, Any]] = (),
    ) -> RuntimeDispatchRecoveryBinding:
        try:
            checkpoint.validate()
        except RuntimeCheckpointError as exc:
            raise RuntimeDispatchRecoveryError(
                "RUNTIME_CHECKPOINT_REVALIDATION_FAILED"
            ) from exc
        if not isinstance(scheduler_snapshot, Mapping):
            raise RuntimeDispatchRecoveryError("SCHEDULER_SNAPSHOT_NOT_MAPPING")
        expected_scheduler_keys = {
            "schema_version",
            "task_id",
            "task_context_fingerprint",
            "plan_fingerprint",
            "parent_authority_fingerprint",
            "max_concurrency",
            "cancelled",
            "cancellation_reason",
            "dispatch_sequence",
            "approved_node_ids",
            "in_flight",
            "observations",
        }
        if set(scheduler_snapshot) != expected_scheduler_keys:
            raise RuntimeDispatchRecoveryError("SCHEDULER_SNAPSHOT_SHAPE_INVALID")
        if scheduler_snapshot["schema_version"] != EXECUTION_SCHEDULER_SCHEMA:
            raise RuntimeDispatchRecoveryError(
                "SCHEDULER_SNAPSHOT_SCHEMA_VERSION_MISMATCH"
            )
        if scheduler_snapshot["task_id"] != checkpoint.task_id:
            raise RuntimeDispatchRecoveryError("SCHEDULER_TASK_MISMATCH")
        if (
            scheduler_snapshot["task_context_fingerprint"]
            != checkpoint.task_context_fingerprint
        ):
            raise RuntimeDispatchRecoveryError("SCHEDULER_TASK_CONTEXT_MISMATCH")
        if scheduler_snapshot["plan_fingerprint"] != checkpoint.plan_fingerprint:
            raise RuntimeDispatchRecoveryError("SCHEDULER_PLAN_MISMATCH")
        if (
            scheduler_snapshot["parent_authority_fingerprint"]
            != checkpoint.parent_authority_fingerprint
        ):
            raise RuntimeDispatchRecoveryError("SCHEDULER_AUTHORITY_MISMATCH")

        approvals = _normalized_ids(
            scheduler_snapshot["approved_node_ids"],
            "approved_node_id",
        )
        observations = _normalized_hashes(
            scheduler_snapshot["observations"],
            "observation_fingerprint",
        )
        in_flight = _normalized_hashes(
            scheduler_snapshot["in_flight"],
            "in_flight_ticket_fingerprint",
        )
        if approvals != checkpoint.approved_node_ids:
            raise RuntimeDispatchRecoveryError("SCHEDULER_APPROVAL_STATE_MISMATCH")
        if observations != checkpoint.observation_fingerprints:
            raise RuntimeDispatchRecoveryError(
                "SCHEDULER_OBSERVATION_STATE_MISMATCH"
            )

        budget = RuntimeBudgetSnapshot.from_mapping(budget_snapshot)
        if budget.task_id != checkpoint.task_id:
            raise RuntimeDispatchRecoveryError("BUDGET_TASK_MISMATCH")
        normalized_revocations = tuple(
            sorted(
                (
                    RuntimeRevocationSnapshot.from_revocation(row)
                    for row in revocations
                ),
                key=lambda row: row.capability,
            )
        )
        if len({row.capability for row in normalized_revocations}) != len(
            normalized_revocations
        ):
            raise RuntimeDispatchRecoveryError("DUPLICATE_REVOKED_CAPABILITY")
        for row in normalized_revocations:
            if row.task_id != checkpoint.task_id:
                raise RuntimeDispatchRecoveryError("REVOCATION_TASK_MISMATCH")

        max_concurrency = _positive_int(
            scheduler_snapshot["max_concurrency"],
            "max_concurrency",
        )
        if max_concurrency > MAX_SCHEDULER_CONCURRENCY:
            raise RuntimeDispatchRecoveryError("MAX_CONCURRENCY_EXCEEDS_RUNTIME_LIMIT")
        cancelled = scheduler_snapshot["cancelled"]
        if not isinstance(cancelled, bool):
            raise RuntimeDispatchRecoveryError("INVALID_CANCELLED_FLAG")
        cancellation_reason = scheduler_snapshot["cancellation_reason"]
        if cancelled:
            _bounded_text(cancellation_reason, "cancellation_reason")
        elif cancellation_reason is not None:
            raise RuntimeDispatchRecoveryError("UNEXPECTED_CANCELLATION_REASON")
        dispatch_sequence = _nonnegative_int(
            scheduler_snapshot["dispatch_sequence"],
            "dispatch_sequence",
        )
        scheduler_identity = {
            "schema_version": EXECUTION_SCHEDULER_SCHEMA,
            "task_id": checkpoint.task_id,
            "task_context_fingerprint": checkpoint.task_context_fingerprint,
            "plan_fingerprint": checkpoint.plan_fingerprint,
            "parent_authority_fingerprint": checkpoint.parent_authority_fingerprint,
            "max_concurrency": max_concurrency,
            "cancelled": cancelled,
            "cancellation_reason": cancellation_reason,
            "dispatch_sequence": dispatch_sequence,
            "approved_node_ids": list(approvals),
            "in_flight": list(in_flight),
            "observations": list(observations),
        }
        identity = {
            "schema_version": RUNTIME_DISPATCH_RECOVERY_BINDING_SCHEMA,
            "runtime_checkpoint_fingerprint": checkpoint.fingerprint,
            "task_id": checkpoint.task_id,
            "task_context_fingerprint": checkpoint.task_context_fingerprint,
            "plan_fingerprint": checkpoint.plan_fingerprint,
            "parent_authority_fingerprint": checkpoint.parent_authority_fingerprint,
            "scheduler_state_fingerprint": _digest(scheduler_identity),
            "max_concurrency": max_concurrency,
            "cancelled": cancelled,
            "cancellation_reason": cancellation_reason,
            "dispatch_sequence": dispatch_sequence,
            "approved_node_ids": list(approvals),
            "in_flight_ticket_fingerprints": list(in_flight),
            "observation_fingerprints": list(observations),
            "budget": budget.canonical_dict(),
            "revocations": [
                row.canonical_dict() for row in normalized_revocations
            ],
            "captured_at": checkpoint.captured_at,
        }
        binding = RuntimeDispatchRecoveryBinding(
            binding_id="dispatch-recovery:"
            + _digest(identity).split(":", 1)[1][:24],
            runtime_checkpoint_fingerprint=checkpoint.fingerprint,
            task_id=checkpoint.task_id,
            task_context_fingerprint=checkpoint.task_context_fingerprint,
            plan_fingerprint=checkpoint.plan_fingerprint,
            parent_authority_fingerprint=checkpoint.parent_authority_fingerprint,
            scheduler_state_fingerprint=identity["scheduler_state_fingerprint"],
            max_concurrency=max_concurrency,
            cancelled=cancelled,
            cancellation_reason=cancellation_reason,
            dispatch_sequence=dispatch_sequence,
            approved_node_ids=approvals,
            in_flight_ticket_fingerprints=in_flight,
            observation_fingerprints=observations,
            budget=budget,
            revocations=normalized_revocations,
            captured_at=checkpoint.captured_at,
        )
        return binding.validate()


class RuntimeDispatchRecoveryBindingCodec:
    @staticmethod
    def dumps(binding: RuntimeDispatchRecoveryBinding) -> str:
        binding.validate()
        return _canonical_json(
            {
                "schema_version": RUNTIME_DISPATCH_RECOVERY_BINDING_ENVELOPE_SCHEMA,
                "binding": binding.canonical_dict(),
                "binding_fingerprint": binding.fingerprint,
            }
        )

    @staticmethod
    def loads(payload: str) -> RuntimeDispatchRecoveryBinding:
        if not isinstance(payload, str) or not payload:
            raise RuntimeDispatchRecoveryError(
                "INVALID_DISPATCH_RECOVERY_BINDING_PAYLOAD"
            )
        try:
            envelope = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_BINDING_JSON_INVALID"
            ) from exc
        if not isinstance(envelope, dict) or set(envelope) != {
            "schema_version",
            "binding",
            "binding_fingerprint",
        }:
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_BINDING_ENVELOPE_SHAPE_INVALID"
            )
        if (
            envelope["schema_version"]
            != RUNTIME_DISPATCH_RECOVERY_BINDING_ENVELOPE_SCHEMA
        ):
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_BINDING_ENVELOPE_SCHEMA_MISMATCH"
            )
        raw = envelope["binding"]
        if not isinstance(raw, dict):
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_BINDING_RECORD_NOT_OBJECT"
            )
        expected = {
            "binding_id",
            "schema_version",
            "runtime_checkpoint_fingerprint",
            "task_id",
            "task_context_fingerprint",
            "plan_fingerprint",
            "parent_authority_fingerprint",
            "scheduler_state_fingerprint",
            "max_concurrency",
            "cancelled",
            "cancellation_reason",
            "dispatch_sequence",
            "approved_node_ids",
            "in_flight_ticket_fingerprints",
            "observation_fingerprints",
            "budget",
            "revocations",
            "captured_at",
        }
        if (
            set(raw) != expected
            or not isinstance(raw["budget"], dict)
            or not isinstance(raw["revocations"], list)
        ):
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_BINDING_RECORD_SHAPE_INVALID"
            )
        try:
            binding = RuntimeDispatchRecoveryBinding(
                binding_id=raw["binding_id"],
                runtime_checkpoint_fingerprint=raw[
                    "runtime_checkpoint_fingerprint"
                ],
                task_id=raw["task_id"],
                task_context_fingerprint=raw["task_context_fingerprint"],
                plan_fingerprint=raw["plan_fingerprint"],
                parent_authority_fingerprint=raw[
                    "parent_authority_fingerprint"
                ],
                scheduler_state_fingerprint=raw[
                    "scheduler_state_fingerprint"
                ],
                max_concurrency=raw["max_concurrency"],
                cancelled=raw["cancelled"],
                cancellation_reason=raw["cancellation_reason"],
                dispatch_sequence=raw["dispatch_sequence"],
                approved_node_ids=tuple(raw["approved_node_ids"]),
                in_flight_ticket_fingerprints=tuple(
                    raw["in_flight_ticket_fingerprints"]
                ),
                observation_fingerprints=tuple(
                    raw["observation_fingerprints"]
                ),
                budget=RuntimeBudgetSnapshot.from_mapping(raw["budget"]),
                revocations=tuple(
                    RuntimeRevocationSnapshot.from_revocation(row)
                    for row in raw["revocations"]
                ),
                captured_at=raw["captured_at"],
                schema_version=raw["schema_version"],
            ).validate()
        except (KeyError, TypeError) as exc:
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_BINDING_RECORD_SHAPE_INVALID"
            ) from exc
        if envelope["binding_fingerprint"] != binding.fingerprint:
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_BINDING_INTEGRITY_FAILED"
            )
        if _canonical_json(envelope) != payload:
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_BINDING_ENVELOPE_NOT_CANONICAL"
            )
        return binding


@dataclass(frozen=True)
class RuntimeDispatchRecoveryDecision:
    status: str
    reason_code: str
    checkpoint_recovery: RuntimeRecoveryDecision
    manual_dispatch_fingerprints: tuple[str, ...]
    newly_revoked_capabilities: tuple[str, ...]
    live_budget_fingerprint: str
    schema_version: str = RUNTIME_DISPATCH_RECOVERY_DECISION_SCHEMA

    def canonical_dict(self) -> dict[str, Any]:
        if self.schema_version != RUNTIME_DISPATCH_RECOVERY_DECISION_SCHEMA:
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_DECISION_SCHEMA_VERSION_MISMATCH"
            )
        if self.status not in _RECOVERY_STATUSES:
            raise RuntimeDispatchRecoveryError(
                "INVALID_DISPATCH_RECOVERY_STATUS"
            )
        if not isinstance(self.reason_code, str) or not _REASON_RE.fullmatch(
            self.reason_code
        ):
            raise RuntimeDispatchRecoveryError(
                "INVALID_DISPATCH_RECOVERY_REASON_CODE"
            )
        if self.manual_dispatch_fingerprints != _normalized_hashes(
            self.manual_dispatch_fingerprints,
            "manual_dispatch_fingerprint",
        ):
            raise RuntimeDispatchRecoveryError(
                "MANUAL_DISPATCH_FINGERPRINTS_NOT_NORMALIZED"
            )
        if self.newly_revoked_capabilities != _normalized_ids(
            self.newly_revoked_capabilities,
            "newly_revoked_capability",
        ):
            raise RuntimeDispatchRecoveryError(
                "NEWLY_REVOKED_CAPABILITIES_NOT_NORMALIZED"
            )
        _sha256(self.live_budget_fingerprint, "live_budget_fingerprint")
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "reason_code": self.reason_code,
            "checkpoint_recovery": self.checkpoint_recovery.canonical_dict(),
            "manual_dispatch_fingerprints": list(
                self.manual_dispatch_fingerprints
            ),
            "newly_revoked_capabilities": list(
                self.newly_revoked_capabilities
            ),
            "live_budget_fingerprint": self.live_budget_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


class RuntimeDispatchRecovery:
    """Revalidate transient dispatch state without replaying or executing work."""

    @staticmethod
    def evaluate(
        *,
        binding: RuntimeDispatchRecoveryBinding,
        checkpoint: RuntimeCheckpoint,
        task_context: TaskContext,
        plan: ExecutionPlan,
        parent_authority: TaskCapabilityAuthority,
        budget_guard: DispatchRecoveryBudgetGuard,
        revocation_guard: DispatchRecoveryRevocationGuard,
        observations: tuple[ExecutionObservation, ...] = (),
    ) -> RuntimeDispatchRecoveryDecision:
        binding.validate()
        checkpoint.validate()
        if binding.runtime_checkpoint_fingerprint != checkpoint.fingerprint:
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_CHECKPOINT_MISMATCH"
            )
        if (
            binding.task_id != checkpoint.task_id
            or binding.task_context_fingerprint
            != checkpoint.task_context_fingerprint
            or binding.plan_fingerprint != checkpoint.plan_fingerprint
            or binding.parent_authority_fingerprint
            != checkpoint.parent_authority_fingerprint
        ):
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_CANONICAL_BINDING_MISMATCH"
            )

        try:
            base = RuntimeRecovery.evaluate(
                checkpoint=checkpoint,
                task_context=task_context,
                plan=plan,
                parent_authority=parent_authority,
                observations=observations,
            )
        except RuntimeCheckpointError as exc:
            raise RuntimeDispatchRecoveryError(
                "DISPATCH_RECOVERY_CHECKPOINT_REVALIDATION_FAILED"
            ) from exc

        try:
            live_budget = RuntimeBudgetSnapshot.from_mapping(
                budget_guard.snapshot()
            )
        except (KeyError, TypeError, ValueError, RuntimeError) as exc:
            if isinstance(exc, RuntimeDispatchRecoveryError):
                raise
            raise RuntimeDispatchRecoveryError(
                "LIVE_BUDGET_SNAPSHOT_FAILED"
            ) from exc
        if live_budget.immutable_tuple != binding.budget.immutable_tuple:
            raise RuntimeDispatchRecoveryError(
                "LIVE_BUDGET_IMMUTABLE_STATE_MISMATCH"
            )
        if any(
            live < captured
            for live, captured in zip(
                live_budget.counters,
                binding.budget.counters,
            )
        ):
            raise RuntimeDispatchRecoveryError(
                "LIVE_BUDGET_COUNTER_ROLLBACK_DETECTED"
            )

        try:
            live_revocations = tuple(
                sorted(
                    (
                        RuntimeRevocationSnapshot.from_revocation(row)
                        for row in revocation_guard.list_for_task(
                            checkpoint.task_id
                        )
                    ),
                    key=lambda row: row.capability,
                )
            )
        except (KeyError, TypeError, ValueError, RuntimeError) as exc:
            if isinstance(exc, RuntimeDispatchRecoveryError):
                raise
            raise RuntimeDispatchRecoveryError(
                "LIVE_REVOCATION_SNAPSHOT_FAILED"
            ) from exc
        captured_by_capability = {
            row.capability: row for row in binding.revocations
        }
        live_by_capability = {
            row.capability: row for row in live_revocations
        }
        if len(live_by_capability) != len(live_revocations):
            raise RuntimeDispatchRecoveryError(
                "DUPLICATE_LIVE_REVOKED_CAPABILITY"
            )
        for capability, captured in captured_by_capability.items():
            live = live_by_capability.get(capability)
            if live is None or live != captured:
                raise RuntimeDispatchRecoveryError(
                    "LIVE_REVOCATION_ROLLBACK_DETECTED"
                )
        newly_revoked = tuple(
            sorted(set(live_by_capability) - set(captured_by_capability))
        )

        if base.status == "COMPLETE":
            status, reason = "COMPLETE", "DISPATCH_RECOVERY_COMPLETE"
        elif base.status == "MANUAL_RECONCILIATION":
            status = "MANUAL_RECONCILIATION"
            reason = "CHECKPOINT_REQUIRES_MANUAL_RECONCILIATION"
        elif binding.in_flight_ticket_fingerprints:
            status = "MANUAL_RECONCILIATION"
            reason = "IN_FLIGHT_DISPATCH_REQUIRES_MANUAL_RECONCILIATION"
        elif binding.cancelled:
            status, reason = "BLOCKED", "SCHEDULER_CANCELLED_AT_CHECKPOINT"
        elif base.status == "BLOCKED":
            status, reason = "BLOCKED", "CHECKPOINT_RECOVERY_BLOCKED"
        else:
            try:
                budget_guard.assert_active()
            except ExecutionBudgetExceeded:
                status, reason = "BLOCKED", "LIVE_BUDGET_NOT_ACTIVE"
            except (ValueError, RuntimeError) as exc:
                raise RuntimeDispatchRecoveryError(
                    "LIVE_BUDGET_REVALIDATION_FAILED"
                ) from exc
            else:
                status = "RECOVERABLE"
                reason = (
                    "DISPATCH_RECOVERY_REVALIDATED_WITH_NEW_REVOCATIONS"
                    if newly_revoked
                    else "DISPATCH_RECOVERY_REVALIDATED_NO_EXECUTION_PERFORMED"
                )

        decision = RuntimeDispatchRecoveryDecision(
            status=status,
            reason_code=reason,
            checkpoint_recovery=base,
            manual_dispatch_fingerprints=(
                binding.in_flight_ticket_fingerprints
                if status == "MANUAL_RECONCILIATION"
                else ()
            ),
            newly_revoked_capabilities=newly_revoked,
            live_budget_fingerprint=live_budget.fingerprint,
        )
        decision.canonical_dict()
        return decision
