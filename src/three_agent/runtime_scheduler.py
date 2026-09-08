from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .capability_authority import TaskCapabilityAuthority
from .execution_observation import (
    ExecutionObservation,
    ExecutionObservationError,
)
from .execution_plan import ExecutionPlan, ExecutionPlanError
from .task_context import TaskContext, TaskContextError

RUNTIME_SCHEDULING_DECISION_SCHEMA = "workspace-runtime-scheduling-decision/v1"
NODE_SCHEDULING_RECORD_SCHEMA = "workspace-runtime-node-scheduling-record/v1"

_DECISION_STATUSES = frozenset({"READY", "WAITING", "BLOCKED", "COMPLETE"})
_NODE_STATES = frozenset(
    {"READY", "WAITING", "BLOCKED", "SUCCEEDED", "FAILED", "CANCELLED"}
)
_TERMINAL_OBSERVATION_STATUSES = frozenset({"SUCCEEDED", "FAILED", "CANCELLED"})
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class RuntimeSchedulerError(ValueError):
    """Scheduler input or state violates a canonical WorkSpace invariant."""


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
        raise RuntimeSchedulerError("SCHEDULER_STATE_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _normalized_ids(values: Iterable[str], *, field_name: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise RuntimeSchedulerError(f"INVALID_{field_name.upper()}")
    try:
        normalized = tuple(sorted(set(values)))
    except TypeError as exc:
        raise RuntimeSchedulerError(f"INVALID_{field_name.upper()}") from exc
    if any(not isinstance(value, str) or not value for value in normalized):
        raise RuntimeSchedulerError(f"INVALID_{field_name.upper()}")
    return normalized


def _sha256(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise RuntimeSchedulerError(f"INVALID_{field_name.upper()}")
    return value


@dataclass(frozen=True)
class NodeSchedulingRecord:
    """Audit-safe scheduling state for one canonical execution node."""

    node_id: str
    node_fingerprint: str
    authority_fingerprint: str
    state: str
    reason_code: str
    approval_required: bool
    schema_version: str = NODE_SCHEDULING_RECORD_SCHEMA

    def canonical_dict(self) -> dict[str, Any]:
        if self.schema_version != NODE_SCHEDULING_RECORD_SCHEMA:
            raise RuntimeSchedulerError(
                "NODE_SCHEDULING_RECORD_SCHEMA_VERSION_MISMATCH"
            )
        if self.state not in _NODE_STATES:
            raise RuntimeSchedulerError("INVALID_NODE_SCHEDULING_STATE")
        if not isinstance(self.node_id, str) or not self.node_id:
            raise RuntimeSchedulerError("INVALID_NODE_ID")
        _sha256(self.node_fingerprint, field_name="node_fingerprint")
        _sha256(
            self.authority_fingerprint,
            field_name="node_authority_fingerprint",
        )
        if not isinstance(self.reason_code, str) or not self.reason_code:
            raise RuntimeSchedulerError("INVALID_SCHEDULING_REASON_CODE")
        if not isinstance(self.approval_required, bool):
            raise RuntimeSchedulerError("INVALID_APPROVAL_REQUIRED")
        return {
            "schema_version": self.schema_version,
            "node_id": self.node_id,
            "node_fingerprint": self.node_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
            "state": self.state,
            "reason_code": self.reason_code,
            "approval_required": self.approval_required,
        }


@dataclass(frozen=True)
class SchedulingDecision:
    """Pure scheduling decision; it never executes a tool or mutates runtime state."""

    task_id: str
    task_context_fingerprint: str
    plan_fingerprint: str
    status: str
    records: tuple[NodeSchedulingRecord, ...]
    approved_node_ids: tuple[str, ...]
    schema_version: str = RUNTIME_SCHEDULING_DECISION_SCHEMA

    @property
    def ready_node_ids(self) -> tuple[str, ...]:
        return tuple(
            record.node_id for record in self.records if record.state == "READY"
        )

    @property
    def blocked_node_ids(self) -> tuple[str, ...]:
        return tuple(
            record.node_id for record in self.records if record.state == "BLOCKED"
        )

    @property
    def waiting_node_ids(self) -> tuple[str, ...]:
        return tuple(
            record.node_id for record in self.records if record.state == "WAITING"
        )

    @property
    def terminal_node_ids(self) -> tuple[str, ...]:
        return tuple(
            record.node_id
            for record in self.records
            if record.state in _TERMINAL_OBSERVATION_STATUSES
        )

    def canonical_dict(self) -> dict[str, Any]:
        if self.schema_version != RUNTIME_SCHEDULING_DECISION_SCHEMA:
            raise RuntimeSchedulerError(
                "SCHEDULING_DECISION_SCHEMA_VERSION_MISMATCH"
            )
        if self.status not in _DECISION_STATUSES:
            raise RuntimeSchedulerError("INVALID_SCHEDULING_DECISION_STATUS")
        if not isinstance(self.records, tuple):
            raise RuntimeSchedulerError("SCHEDULING_RECORDS_MUST_BE_TUPLE")
        if self.approved_node_ids != _normalized_ids(
            self.approved_node_ids,
            field_name="approved_node_ids",
        ):
            raise RuntimeSchedulerError("APPROVED_NODE_IDS_NOT_NORMALIZED")
        _sha256(
            self.task_context_fingerprint,
            field_name="task_context_fingerprint",
        )
        _sha256(self.plan_fingerprint, field_name="plan_fingerprint")
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "task_context_fingerprint": self.task_context_fingerprint,
            "plan_fingerprint": self.plan_fingerprint,
            "status": self.status,
            "records": [record.canonical_dict() for record in self.records],
            "approved_node_ids": list(self.approved_node_ids),
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


class RuntimeScheduler:
    """Deterministic, fail-closed scheduler over canonical runtime contracts.

    The scheduler only decides admission/readiness. Execution, retries, checkpoint
    persistence, evidence storage, and remediation remain outside this class.
    """

    @staticmethod
    def evaluate(
        *,
        task_context: TaskContext,
        plan: ExecutionPlan,
        parent_authority: TaskCapabilityAuthority,
        observations: tuple[ExecutionObservation, ...] = (),
        approved_node_ids: Iterable[str] = (),
    ) -> SchedulingDecision:
        if not isinstance(task_context, TaskContext):
            raise RuntimeSchedulerError("INVALID_TASK_CONTEXT")
        if not isinstance(plan, ExecutionPlan):
            raise RuntimeSchedulerError("INVALID_EXECUTION_PLAN")
        if not isinstance(parent_authority, TaskCapabilityAuthority):
            raise RuntimeSchedulerError("INVALID_PARENT_AUTHORITY")
        if not isinstance(observations, tuple):
            raise RuntimeSchedulerError("OBSERVATIONS_MUST_BE_TUPLE")

        try:
            task_context.validate()
            plan.validate(parent_authority=parent_authority)
        except (TaskContextError, ExecutionPlanError, ValueError) as exc:
            raise RuntimeSchedulerError(
                "SCHEDULER_CANONICAL_REVALIDATION_FAILED"
            ) from exc

        if task_context.task_id != plan.task_id:
            raise RuntimeSchedulerError("SCHEDULER_TASK_MISMATCH")
        if task_context.fingerprint != plan.task_context_fingerprint:
            raise RuntimeSchedulerError(
                "SCHEDULER_TASK_CONTEXT_FINGERPRINT_MISMATCH"
            )
        if task_context.identity_fingerprint != plan.task_context_identity_fingerprint:
            raise RuntimeSchedulerError(
                "SCHEDULER_TASK_CONTEXT_IDENTITY_MISMATCH"
            )
        if task_context.authority_fingerprint != parent_authority.fingerprint:
            raise RuntimeSchedulerError("SCHEDULER_PARENT_AUTHORITY_MISMATCH")
        if plan.parent_authority_fingerprint != parent_authority.fingerprint:
            raise RuntimeSchedulerError("SCHEDULER_PLAN_AUTHORITY_MISMATCH")

        node_by_id = {node.node_id: node for node in plan.nodes}
        approvals = _normalized_ids(
            approved_node_ids,
            field_name="approved_node_ids",
        )
        unknown_approvals = tuple(
            node_id for node_id in approvals if node_id not in node_by_id
        )
        if unknown_approvals:
            raise RuntimeSchedulerError(
                "SCHEDULER_UNKNOWN_APPROVED_NODE:" + ",".join(unknown_approvals)
            )
        invalid_approvals = tuple(
            node_id
            for node_id in approvals
            if not node_by_id[node_id].approval_required
        )
        if invalid_approvals:
            raise RuntimeSchedulerError(
                "SCHEDULER_APPROVAL_FOR_NON_APPROVAL_NODE:"
                + ",".join(invalid_approvals)
            )

        unique_observations: dict[str, ExecutionObservation] = {}
        terminal_by_node: dict[str, ExecutionObservation] = {}
        partial_nodes: set[str] = set()
        for observation in observations:
            if not isinstance(observation, ExecutionObservation):
                raise RuntimeSchedulerError("INVALID_EXECUTION_OBSERVATION")
            try:
                observation.validate(
                    plan=plan,
                    parent_authority=parent_authority,
                )
            except ExecutionObservationError as exc:
                raise RuntimeSchedulerError(
                    "SCHEDULER_OBSERVATION_REVALIDATION_FAILED"
                ) from exc

            node = node_by_id[observation.node_id]
            if node.approval_required and observation.node_id not in approvals:
                raise RuntimeSchedulerError(
                    f"SCHEDULER_APPROVAL_REQUIRED_FOR_OBSERVATION:{observation.node_id}"
                )

            existing = unique_observations.get(observation.observation_id)
            if existing is not None:
                if existing.fingerprint != observation.fingerprint:
                    raise RuntimeSchedulerError(
                        "SCHEDULER_OBSERVATION_ID_COLLISION"
                    )
                continue
            unique_observations[observation.observation_id] = observation

            if observation.status == "PARTIAL":
                partial_nodes.add(observation.node_id)
                continue
            if observation.status in _TERMINAL_OBSERVATION_STATUSES:
                previous = terminal_by_node.get(observation.node_id)
                if (
                    previous is not None
                    and previous.observation_id != observation.observation_id
                ):
                    raise RuntimeSchedulerError(
                        "SCHEDULER_MULTIPLE_TERMINAL_OBSERVATIONS:"
                        + observation.node_id
                    )
                terminal_by_node[observation.node_id] = observation

        records: list[NodeSchedulingRecord] = []
        state_by_node: dict[str, str] = {}
        success_nodes = {
            node_id
            for node_id, observation in terminal_by_node.items()
            if observation.status == "SUCCEEDED"
        }

        for node in plan.nodes:
            terminal = terminal_by_node.get(node.node_id)
            if terminal is not None:
                state = terminal.status
                reason = f"OBSERVATION_{terminal.status}"
            elif node.node_id in partial_nodes:
                state = "WAITING"
                reason = "PARTIAL_OBSERVATION_REQUIRES_RECONCILIATION"
            else:
                dependency_states = tuple(
                    state_by_node.get(dependency, "WAITING")
                    for dependency in node.depends_on
                )
                if any(
                    state in {"FAILED", "CANCELLED", "BLOCKED"}
                    for state in dependency_states
                ):
                    state = "BLOCKED"
                    reason = "DEPENDENCY_NOT_SUCCESSFUL"
                elif not all(
                    dependency in success_nodes
                    for dependency in node.depends_on
                ):
                    state = "WAITING"
                    reason = "DEPENDENCY_NOT_TERMINAL_SUCCESS"
                elif node.approval_required and node.node_id not in approvals:
                    state = "BLOCKED"
                    reason = "EXPLICIT_APPROVAL_REQUIRED"
                else:
                    state = "READY"
                    reason = "NODE_ADMISSIBLE"

            state_by_node[node.node_id] = state
            records.append(
                NodeSchedulingRecord(
                    node_id=node.node_id,
                    node_fingerprint=node.fingerprint,
                    authority_fingerprint=node.authority_fingerprint,
                    state=state,
                    reason_code=reason,
                    approval_required=node.approval_required,
                )
            )

        record_tuple = tuple(records)
        if record_tuple and all(
            record.state == "SUCCEEDED" for record in record_tuple
        ):
            decision_status = "COMPLETE"
        elif any(record.state == "READY" for record in record_tuple):
            decision_status = "READY"
        elif any(record.state == "BLOCKED" for record in record_tuple):
            decision_status = "BLOCKED"
        else:
            decision_status = "WAITING"

        decision = SchedulingDecision(
            task_id=plan.task_id,
            task_context_fingerprint=task_context.fingerprint,
            plan_fingerprint=plan.fingerprint,
            status=decision_status,
            records=record_tuple,
            approved_node_ids=approvals,
        )
        decision.canonical_dict()
        return decision
