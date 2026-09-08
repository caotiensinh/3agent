from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from .capability_authority import TaskCapabilityAuthority
from .execution_observation import ExecutionObservation, ExecutionObservationError
from .execution_plan import ExecutionPlan, ExecutionPlanError
from .runtime_scheduler import RuntimeScheduler, RuntimeSchedulerError, SchedulingDecision
from .task_context import TaskContext, TaskContextError

RUNTIME_CHECKPOINT_SCHEMA = "workspace-runtime-checkpoint/v1"
RUNTIME_CHECKPOINT_ENVELOPE_SCHEMA = "workspace-runtime-checkpoint-envelope/v1"
RUNTIME_RECOVERY_DECISION_SCHEMA = "workspace-runtime-recovery-decision/v1"

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_RECOVERY_STATUSES = frozenset({"RECOVERABLE", "MANUAL_RECONCILIATION", "BLOCKED", "COMPLETE"})
_TERMINAL_OBSERVATION_STATUSES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})


class RuntimeCheckpointError(ValueError):
    """Checkpoint or recovery state violates a canonical runtime invariant."""


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
        raise RuntimeCheckpointError("RUNTIME_CHECKPOINT_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise RuntimeCheckpointError(f"INVALID_{field_name.upper()}")
    return value


def _compact_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _ID_RE.fullmatch(value):
        raise RuntimeCheckpointError(f"INVALID_{field_name.upper()}")
    return value


def _timestamp(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise RuntimeCheckpointError(f"INVALID_{field_name.upper()}")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise RuntimeCheckpointError(f"INVALID_{field_name.upper()}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise RuntimeCheckpointError(f"{field_name.upper()}_MUST_BE_TIMEZONE_AWARE")
    canonical = parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if canonical != value:
        raise RuntimeCheckpointError(f"{field_name.upper()}_MUST_BE_NORMALIZED_UTC")
    return value


def _iso8601(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise RuntimeCheckpointError("CAPTURED_AT_MUST_BE_TIMEZONE_AWARE")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalized_ids(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise RuntimeCheckpointError(f"INVALID_{field_name.upper()}")
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = _compact_id(value, field_name)
        if item in seen:
            raise RuntimeCheckpointError(f"DUPLICATE_{field_name.upper()}")
        seen.add(item)
        result.append(item)
    return tuple(sorted(result))


def _normalized_hashes(values: Iterable[str], field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise RuntimeCheckpointError(f"INVALID_{field_name.upper()}")
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = _sha256(value, field_name)
        if item in seen:
            raise RuntimeCheckpointError(f"DUPLICATE_{field_name.upper()}")
        seen.add(item)
        result.append(item)
    return tuple(sorted(result))


def _observation_fingerprints(
    observations: tuple[ExecutionObservation, ...],
    *,
    plan: ExecutionPlan,
    parent_authority: TaskCapabilityAuthority,
) -> tuple[str, ...]:
    if not isinstance(observations, tuple):
        raise RuntimeCheckpointError("OBSERVATIONS_MUST_BE_TUPLE")
    by_id: dict[str, str] = {}
    fingerprints: list[str] = []
    for observation in observations:
        if not isinstance(observation, ExecutionObservation):
            raise RuntimeCheckpointError("INVALID_EXECUTION_OBSERVATION")
        try:
            observation.validate(plan=plan, parent_authority=parent_authority)
        except ExecutionObservationError as exc:
            raise RuntimeCheckpointError("CHECKPOINT_OBSERVATION_REVALIDATION_FAILED") from exc
        previous = by_id.get(observation.observation_id)
        if previous is not None:
            if previous != observation.fingerprint:
                raise RuntimeCheckpointError("CHECKPOINT_OBSERVATION_ID_COLLISION")
            continue
        by_id[observation.observation_id] = observation.fingerprint
        fingerprints.append(observation.fingerprint)
    return tuple(sorted(fingerprints))


@dataclass(frozen=True)
class RuntimeCheckpoint:
    checkpoint_id: str
    task_id: str
    task_context_fingerprint: str
    task_context_identity_fingerprint: str
    plan_fingerprint: str
    parent_authority_fingerprint: str
    scheduling_decision_fingerprint: str
    approved_node_ids: tuple[str, ...]
    observation_fingerprints: tuple[str, ...]
    captured_at: str
    schema_version: str = RUNTIME_CHECKPOINT_SCHEMA

    def validate(self) -> "RuntimeCheckpoint":
        if self.schema_version != RUNTIME_CHECKPOINT_SCHEMA:
            raise RuntimeCheckpointError("RUNTIME_CHECKPOINT_SCHEMA_VERSION_MISMATCH")
        _compact_id(self.checkpoint_id, "checkpoint_id")
        _compact_id(self.task_id, "task_id")
        for value, field_name in (
            (self.task_context_fingerprint, "task_context_fingerprint"),
            (self.task_context_identity_fingerprint, "task_context_identity_fingerprint"),
            (self.plan_fingerprint, "plan_fingerprint"),
            (self.parent_authority_fingerprint, "parent_authority_fingerprint"),
            (self.scheduling_decision_fingerprint, "scheduling_decision_fingerprint"),
        ):
            _sha256(value, field_name)
        if self.approved_node_ids != _normalized_ids(self.approved_node_ids, "approved_node_id"):
            raise RuntimeCheckpointError("APPROVED_NODE_IDS_NOT_NORMALIZED")
        if self.observation_fingerprints != _normalized_hashes(
            self.observation_fingerprints,
            "observation_fingerprint",
        ):
            raise RuntimeCheckpointError("OBSERVATION_FINGERPRINTS_NOT_NORMALIZED")
        _timestamp(self.captured_at, "captured_at")
        expected_id = "runtime-checkpoint:" + self.fingerprint.split(":", 1)[1][:24]
        if self.checkpoint_id != expected_id:
            raise RuntimeCheckpointError("RUNTIME_CHECKPOINT_IDENTITY_MISMATCH")
        return self

    def _identity_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "task_context_fingerprint": self.task_context_fingerprint,
            "task_context_identity_fingerprint": self.task_context_identity_fingerprint,
            "plan_fingerprint": self.plan_fingerprint,
            "parent_authority_fingerprint": self.parent_authority_fingerprint,
            "scheduling_decision_fingerprint": self.scheduling_decision_fingerprint,
            "approved_node_ids": list(self.approved_node_ids),
            "observation_fingerprints": list(self.observation_fingerprints),
            "captured_at": self.captured_at,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self._identity_dict())

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {"checkpoint_id": self.checkpoint_id, **self._identity_dict()}


class RuntimeCheckpointBuilder:
    @staticmethod
    def build(
        *,
        task_context: TaskContext,
        plan: ExecutionPlan,
        parent_authority: TaskCapabilityAuthority,
        observations: tuple[ExecutionObservation, ...] = (),
        approved_node_ids: Iterable[str] = (),
        captured_at: datetime | None = None,
    ) -> RuntimeCheckpoint:
        try:
            task_context.validate()
            plan.validate(parent_authority=parent_authority)
        except (TaskContextError, ExecutionPlanError, ValueError) as exc:
            raise RuntimeCheckpointError("CHECKPOINT_CANONICAL_REVALIDATION_FAILED") from exc
        if task_context.task_id != plan.task_id:
            raise RuntimeCheckpointError("CHECKPOINT_TASK_MISMATCH")
        if task_context.fingerprint != plan.task_context_fingerprint:
            raise RuntimeCheckpointError("CHECKPOINT_TASK_CONTEXT_FINGERPRINT_MISMATCH")
        if task_context.identity_fingerprint != plan.task_context_identity_fingerprint:
            raise RuntimeCheckpointError("CHECKPOINT_TASK_CONTEXT_IDENTITY_MISMATCH")
        if task_context.authority_fingerprint != parent_authority.fingerprint:
            raise RuntimeCheckpointError("CHECKPOINT_PARENT_AUTHORITY_MISMATCH")

        approvals = _normalized_ids(approved_node_ids, "approved_node_id")
        fingerprints = _observation_fingerprints(
            observations,
            plan=plan,
            parent_authority=parent_authority,
        )
        try:
            decision = RuntimeScheduler.evaluate(
                task_context=task_context,
                plan=plan,
                parent_authority=parent_authority,
                observations=observations,
                approved_node_ids=approvals,
            )
        except RuntimeSchedulerError as exc:
            raise RuntimeCheckpointError("CHECKPOINT_SCHEDULER_REVALIDATION_FAILED") from exc

        timestamp = _iso8601(captured_at or datetime.now(timezone.utc))
        identity = {
            "schema_version": RUNTIME_CHECKPOINT_SCHEMA,
            "task_id": task_context.task_id,
            "task_context_fingerprint": task_context.fingerprint,
            "task_context_identity_fingerprint": task_context.identity_fingerprint,
            "plan_fingerprint": plan.fingerprint,
            "parent_authority_fingerprint": parent_authority.fingerprint,
            "scheduling_decision_fingerprint": decision.fingerprint,
            "approved_node_ids": list(approvals),
            "observation_fingerprints": list(fingerprints),
            "captured_at": timestamp,
        }
        checkpoint = RuntimeCheckpoint(
            checkpoint_id="runtime-checkpoint:" + _digest(identity).split(":", 1)[1][:24],
            task_id=task_context.task_id,
            task_context_fingerprint=task_context.fingerprint,
            task_context_identity_fingerprint=task_context.identity_fingerprint,
            plan_fingerprint=plan.fingerprint,
            parent_authority_fingerprint=parent_authority.fingerprint,
            scheduling_decision_fingerprint=decision.fingerprint,
            approved_node_ids=approvals,
            observation_fingerprints=fingerprints,
            captured_at=timestamp,
        )
        return checkpoint.validate()


class RuntimeCheckpointCodec:
    @staticmethod
    def dumps(checkpoint: RuntimeCheckpoint) -> str:
        checkpoint.validate()
        envelope = {
            "schema_version": RUNTIME_CHECKPOINT_ENVELOPE_SCHEMA,
            "checkpoint": checkpoint.canonical_dict(),
            "checkpoint_fingerprint": checkpoint.fingerprint,
        }
        return _canonical_json(envelope)

    @staticmethod
    def loads(payload: str) -> RuntimeCheckpoint:
        if not isinstance(payload, str) or not payload:
            raise RuntimeCheckpointError("INVALID_RUNTIME_CHECKPOINT_PAYLOAD")
        try:
            envelope = json.loads(payload)
        except json.JSONDecodeError as exc:
            raise RuntimeCheckpointError("RUNTIME_CHECKPOINT_JSON_INVALID") from exc
        if not isinstance(envelope, dict):
            raise RuntimeCheckpointError("RUNTIME_CHECKPOINT_ENVELOPE_NOT_OBJECT")
        if envelope.get("schema_version") != RUNTIME_CHECKPOINT_ENVELOPE_SCHEMA:
            raise RuntimeCheckpointError("RUNTIME_CHECKPOINT_ENVELOPE_SCHEMA_VERSION_MISMATCH")
        raw = envelope.get("checkpoint")
        if not isinstance(raw, dict):
            raise RuntimeCheckpointError("RUNTIME_CHECKPOINT_RECORD_NOT_OBJECT")
        expected_keys = {
            "checkpoint_id",
            "schema_version",
            "task_id",
            "task_context_fingerprint",
            "task_context_identity_fingerprint",
            "plan_fingerprint",
            "parent_authority_fingerprint",
            "scheduling_decision_fingerprint",
            "approved_node_ids",
            "observation_fingerprints",
            "captured_at",
        }
        if set(raw) != expected_keys:
            raise RuntimeCheckpointError("RUNTIME_CHECKPOINT_RECORD_SHAPE_INVALID")
        try:
            checkpoint = RuntimeCheckpoint(
                checkpoint_id=raw["checkpoint_id"],
                task_id=raw["task_id"],
                task_context_fingerprint=raw["task_context_fingerprint"],
                task_context_identity_fingerprint=raw["task_context_identity_fingerprint"],
                plan_fingerprint=raw["plan_fingerprint"],
                parent_authority_fingerprint=raw["parent_authority_fingerprint"],
                scheduling_decision_fingerprint=raw["scheduling_decision_fingerprint"],
                approved_node_ids=tuple(raw["approved_node_ids"]),
                observation_fingerprints=tuple(raw["observation_fingerprints"]),
                captured_at=raw["captured_at"],
                schema_version=raw["schema_version"],
            ).validate()
        except (KeyError, TypeError, RuntimeCheckpointError) as exc:
            if isinstance(exc, RuntimeCheckpointError):
                raise
            raise RuntimeCheckpointError("RUNTIME_CHECKPOINT_RECORD_SHAPE_INVALID") from exc
        stored_fingerprint = envelope.get("checkpoint_fingerprint")
        if stored_fingerprint != checkpoint.fingerprint:
            raise RuntimeCheckpointError("RUNTIME_CHECKPOINT_INTEGRITY_FAILED")
        if _canonical_json(envelope) != payload:
            raise RuntimeCheckpointError("RUNTIME_CHECKPOINT_ENVELOPE_NOT_CANONICAL")
        return checkpoint


@dataclass(frozen=True)
class RuntimeRecoveryDecision:
    status: str
    scheduling_decision: SchedulingDecision
    reason_code: str
    manual_node_ids: tuple[str, ...]
    schema_version: str = RUNTIME_RECOVERY_DECISION_SCHEMA

    def canonical_dict(self) -> dict[str, Any]:
        if self.schema_version != RUNTIME_RECOVERY_DECISION_SCHEMA:
            raise RuntimeCheckpointError("RUNTIME_RECOVERY_DECISION_SCHEMA_VERSION_MISMATCH")
        if self.status not in _RECOVERY_STATUSES:
            raise RuntimeCheckpointError("INVALID_RUNTIME_RECOVERY_STATUS")
        if not isinstance(self.scheduling_decision, SchedulingDecision):
            raise RuntimeCheckpointError("INVALID_RECOVERY_SCHEDULING_DECISION")
        if not isinstance(self.reason_code, str) or not self.reason_code:
            raise RuntimeCheckpointError("INVALID_RECOVERY_REASON_CODE")
        if self.manual_node_ids != _normalized_ids(self.manual_node_ids, "manual_node_id"):
            raise RuntimeCheckpointError("MANUAL_NODE_IDS_NOT_NORMALIZED")
        return {
            "schema_version": self.schema_version,
            "status": self.status,
            "reason_code": self.reason_code,
            "manual_node_ids": list(self.manual_node_ids),
            "scheduling_decision": self.scheduling_decision.canonical_dict(),
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


class RuntimeRecovery:
    """Fail-closed recovery evaluator; never executes or replays a node."""

    @staticmethod
    def evaluate(
        *,
        checkpoint: RuntimeCheckpoint,
        task_context: TaskContext,
        plan: ExecutionPlan,
        parent_authority: TaskCapabilityAuthority,
        observations: tuple[ExecutionObservation, ...] = (),
    ) -> RuntimeRecoveryDecision:
        checkpoint.validate()
        try:
            task_context.validate()
            plan.validate(parent_authority=parent_authority)
        except (TaskContextError, ExecutionPlanError, ValueError) as exc:
            raise RuntimeCheckpointError("RECOVERY_CANONICAL_REVALIDATION_FAILED") from exc

        if checkpoint.task_id != task_context.task_id or checkpoint.task_id != plan.task_id:
            raise RuntimeCheckpointError("RECOVERY_TASK_MISMATCH")
        if checkpoint.task_context_fingerprint != task_context.fingerprint:
            raise RuntimeCheckpointError("RECOVERY_TASK_CONTEXT_FINGERPRINT_MISMATCH")
        if checkpoint.task_context_identity_fingerprint != task_context.identity_fingerprint:
            raise RuntimeCheckpointError("RECOVERY_TASK_CONTEXT_IDENTITY_MISMATCH")
        if checkpoint.plan_fingerprint != plan.fingerprint:
            raise RuntimeCheckpointError("RECOVERY_PLAN_FINGERPRINT_MISMATCH")
        if checkpoint.parent_authority_fingerprint != parent_authority.fingerprint:
            raise RuntimeCheckpointError("RECOVERY_PARENT_AUTHORITY_MISMATCH")

        fingerprints = _observation_fingerprints(
            observations,
            plan=plan,
            parent_authority=parent_authority,
        )
        if fingerprints != checkpoint.observation_fingerprints:
            raise RuntimeCheckpointError("RECOVERY_OBSERVATION_SET_MISMATCH")

        try:
            scheduling = RuntimeScheduler.evaluate(
                task_context=task_context,
                plan=plan,
                parent_authority=parent_authority,
                observations=observations,
                approved_node_ids=checkpoint.approved_node_ids,
            )
        except RuntimeSchedulerError as exc:
            raise RuntimeCheckpointError("RECOVERY_SCHEDULER_REVALIDATION_FAILED") from exc
        if scheduling.fingerprint != checkpoint.scheduling_decision_fingerprint:
            raise RuntimeCheckpointError("RECOVERY_SCHEDULING_DECISION_MISMATCH")

        manual_nodes = tuple(
            sorted(
                {
                    observation.node_id
                    for observation in observations
                    if observation.status == "PARTIAL"
                }
            )
        )
        if manual_nodes:
            status = "MANUAL_RECONCILIATION"
            reason = "PARTIAL_OBSERVATION_MUST_NOT_BE_AUTO_REPLAYED"
        elif scheduling.status == "COMPLETE":
            status = "COMPLETE"
            reason = "CHECKPOINT_ALREADY_COMPLETE"
        elif scheduling.status == "BLOCKED":
            status = "BLOCKED"
            reason = "SCHEDULER_BLOCKED"
        else:
            status = "RECOVERABLE"
            reason = "CHECKPOINT_REVALIDATED_NO_EXECUTION_PERFORMED"

        decision = RuntimeRecoveryDecision(
            status=status,
            scheduling_decision=scheduling,
            reason_code=reason,
            manual_node_ids=manual_nodes,
        )
        decision.canonical_dict()
        return decision
