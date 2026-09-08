from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Protocol

from .capability_authority import TaskCapabilityAuthority
from .execution_budget import ExecutionBudgetExceeded
from .execution_observation import ExecutionObservation, ExecutionObservationError
from .execution_plan import ExecutionNode, ExecutionPlan, ExecutionPlanError
from .runtime_scheduler import RuntimeScheduler, RuntimeSchedulerError, SchedulingDecision
from .task_context import TaskContext

EXECUTION_SCHEDULER_SCHEMA = "workspace-execution-scheduler/v1"
DISPATCH_TICKET_SCHEMA = "workspace-dispatch-ticket/v1"
MAX_SCHEDULER_CONCURRENCY = 24


class ExecutionSchedulerError(RuntimeError):
    """A scheduler transition would violate the canonical runtime contract."""


class SchedulerBudgetGuard(Protocol):
    """Minimal adapter over the canonical persistent task execution budget."""

    def assert_active(self) -> None: ...

    def reserve(
        self,
        *,
        steps: int = 0,
        tool_calls: int = 0,
        retries: int = 0,
        escalations: int = 0,
    ) -> None: ...


class SchedulerRevocationGuard(Protocol):
    """Minimal adapter over monotonic task capability revocation."""

    def is_revoked(self, task_id: str, capability: str) -> bool: ...


def _canonical_json(payload: Any) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _node_map(plan: ExecutionPlan) -> dict[str, ExecutionNode]:
    return {node.node_id: node for node in plan.nodes}


@dataclass(frozen=True)
class DispatchTicket:
    """Trusted runtime dispatch receipt; it does not widen node authority."""

    ticket_id: str
    task_id: str
    plan_fingerprint: str
    node_id: str
    node_fingerprint: str
    authority_fingerprint: str
    dependency_observation_fingerprints: tuple[str, ...]
    dispatch_sequence: int
    execution_level: int
    schema_version: str = DISPATCH_TICKET_SCHEMA
    dispatch_authorized: bool = field(default=True, init=False)

    def _identity_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_fingerprint": self.plan_fingerprint,
            "node_id": self.node_id,
            "node_fingerprint": self.node_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
            "dependency_observation_fingerprints": list(self.dependency_observation_fingerprints),
            "dispatch_sequence": self.dispatch_sequence,
            "execution_level": self.execution_level,
            "dispatch_authorized": self.dispatch_authorized,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self._identity_dict())

    def validate(self) -> "DispatchTicket":
        if self.schema_version != DISPATCH_TICKET_SCHEMA:
            raise ExecutionSchedulerError("DISPATCH_TICKET_SCHEMA_VERSION_MISMATCH")
        if not self.dispatch_authorized:
            raise ExecutionSchedulerError("DISPATCH_TICKET_NOT_AUTHORIZED")
        if self.dispatch_sequence < 1:
            raise ExecutionSchedulerError("INVALID_DISPATCH_SEQUENCE")
        expected = "dispatch:" + _digest(self._identity_dict()).split(":", 1)[1][:24]
        if self.ticket_id != expected:
            raise ExecutionSchedulerError("DISPATCH_TICKET_IDENTITY_MISMATCH")
        return self


class ExecutionScheduler:
    """Stateful dispatch coordinator over the canonical runtime scheduler evaluator.

    ``RuntimeScheduler`` owns pure DAG readiness/approval/dependency decisions.
    This coordinator intentionally does not duplicate those decisions. It adds
    runtime state that the pure evaluator does not own: immutable dispatch
    tickets, in-flight tracking, persistent budget reservation, monotonic
    revocation checks, backpressure, cancellation, and canonical observation
    admission.
    """

    def __init__(
        self,
        *,
        task_context: TaskContext,
        plan: ExecutionPlan,
        parent_authority: TaskCapabilityAuthority,
        budget_guard: SchedulerBudgetGuard,
        revocation_guard: SchedulerRevocationGuard,
        max_concurrency: int = 4,
    ) -> None:
        if not isinstance(task_context, TaskContext):
            raise ExecutionSchedulerError("INVALID_TASK_CONTEXT")
        if not isinstance(plan, ExecutionPlan):
            raise ExecutionSchedulerError("INVALID_EXECUTION_PLAN")
        if not isinstance(parent_authority, TaskCapabilityAuthority):
            raise ExecutionSchedulerError("INVALID_PARENT_AUTHORITY")
        if (
            isinstance(max_concurrency, bool)
            or not isinstance(max_concurrency, int)
            or not 1 <= max_concurrency <= MAX_SCHEDULER_CONCURRENCY
        ):
            raise ExecutionSchedulerError("INVALID_MAX_CONCURRENCY")
        if budget_guard is None:
            raise ExecutionSchedulerError("BUDGET_GUARD_REQUIRED")
        if revocation_guard is None:
            raise ExecutionSchedulerError("REVOCATION_GUARD_REQUIRED")

        try:
            RuntimeScheduler.evaluate(
                task_context=task_context,
                plan=plan,
                parent_authority=parent_authority,
            )
        except RuntimeSchedulerError as exc:
            raise ExecutionSchedulerError(
                "SCHEDULER_CANONICAL_ADMISSION_REVALIDATION_FAILED"
            ) from exc

        self.task_context = task_context
        self.plan = plan
        self.parent_authority = parent_authority
        self.budget_guard = budget_guard
        self.revocation_guard = revocation_guard
        self.max_concurrency = max_concurrency
        self._nodes = _node_map(plan)
        self._observations: dict[str, ExecutionObservation] = {}
        self._in_flight: dict[str, DispatchTicket] = {}
        self._approved_nodes: set[str] = set()
        self._dispatch_sequence = 0
        self._cancelled = False
        self._cancellation_reason: str | None = None

    def _ordered_observations(self) -> tuple[ExecutionObservation, ...]:
        return tuple(
            self._observations[node.node_id]
            for node in self.plan.nodes
            if node.node_id in self._observations
        )

    def admission_decision(
        self,
        *,
        approved_nodes: frozenset[str] = frozenset(),
    ) -> SchedulingDecision:
        """Return the canonical pure scheduling decision for current observations."""
        if not isinstance(approved_nodes, frozenset):
            raise ExecutionSchedulerError("APPROVED_NODES_MUST_BE_FROZENSET")
        effective_approvals = tuple(sorted(self._approved_nodes | set(approved_nodes)))
        try:
            return RuntimeScheduler.evaluate(
                task_context=self.task_context,
                plan=self.plan,
                parent_authority=self.parent_authority,
                observations=self._ordered_observations(),
                approved_node_ids=effective_approvals,
            )
        except RuntimeSchedulerError as exc:
            raise ExecutionSchedulerError(
                f"SCHEDULER_DECISION_REVALIDATION_FAILED:{exc}"
            ) from exc

    def _revalidate_runtime(self, node: ExecutionNode) -> None:
        try:
            self.plan.validate(parent_authority=self.parent_authority)
            rebound = node.rebind_authority(self.parent_authority)
        except ExecutionPlanError as exc:
            raise ExecutionSchedulerError(
                f"SCHEDULER_AUTHORITY_REVALIDATION_FAILED:{node.node_id}"
            ) from exc
        if rebound.fingerprint != node.authority_fingerprint:
            raise ExecutionSchedulerError(
                f"SCHEDULER_AUTHORITY_FINGERPRINT_MISMATCH:{node.node_id}"
            )

        try:
            self.budget_guard.assert_active()
        except ExecutionBudgetExceeded as exc:
            raise ExecutionSchedulerError(
                f"SCHEDULER_BUDGET_DENIED:{exc.reason_code}"
            ) from exc
        except (ValueError, RuntimeError) as exc:
            raise ExecutionSchedulerError("SCHEDULER_BUDGET_REVALIDATION_FAILED") from exc

        for capability in node.allowed_tools:
            try:
                revoked = self.revocation_guard.is_revoked(
                    self.plan.task_id,
                    capability,
                )
            except (KeyError, ValueError, RuntimeError) as exc:
                raise ExecutionSchedulerError(
                    f"SCHEDULER_REVOCATION_CHECK_FAILED:{node.node_id}:{capability}"
                ) from exc
            if revoked:
                raise ExecutionSchedulerError(
                    f"SCHEDULER_CAPABILITY_REVOKED:{node.node_id}:{capability}"
                )

    def _dependency_observations(
        self,
        node: ExecutionNode,
    ) -> tuple[ExecutionObservation, ...]:
        """Return successful dependencies in the plan-declared fan-in order."""
        rows: list[ExecutionObservation] = []
        for dependency_id in node.depends_on:
            observation = self._observations.get(dependency_id)
            if observation is None:
                raise ExecutionSchedulerError(
                    f"SCHEDULER_DEPENDENCY_PENDING:{node.node_id}:{dependency_id}"
                )
            if observation.status != "SUCCEEDED":
                raise ExecutionSchedulerError(
                    "SCHEDULER_DEPENDENCY_NOT_SUCCEEDED:"
                    f"{node.node_id}:{dependency_id}:{observation.status}"
                )
            rows.append(observation)
        return tuple(rows)

    def blocked_reason(self, node_id: str) -> str | None:
        node = self._nodes.get(node_id)
        if node is None:
            raise ExecutionSchedulerError(f"UNKNOWN_EXECUTION_NODE:{node_id}")
        if node_id in self._observations:
            return "OBSERVED"
        if node_id in self._in_flight:
            return "IN_FLIGHT"
        if self._cancelled:
            return "SCHEDULER_CANCELLED"

        for dependency_id in node.depends_on:
            observation = self._observations.get(dependency_id)
            if observation is None:
                return f"DEPENDENCY_PENDING:{dependency_id}"
            if observation.status != "SUCCEEDED":
                return f"DEPENDENCY_{observation.status}:{dependency_id}"

        decision = self.admission_decision()
        record = next(row for row in decision.records if row.node_id == node_id)
        if record.state == "READY":
            return None
        if record.reason_code == "EXPLICIT_APPROVAL_REQUIRED":
            return "APPROVAL_REQUIRED"
        return record.reason_code

    def ready_node_ids(
        self,
        *,
        approved_nodes: frozenset[str] = frozenset(),
    ) -> tuple[str, ...]:
        if self._cancelled:
            return ()
        capacity = self.max_concurrency - len(self._in_flight)
        if capacity <= 0:
            return ()

        decision = self.admission_decision(approved_nodes=approved_nodes)
        ready = [
            record.node_id
            for record in decision.records
            if record.state == "READY"
            and record.node_id not in self._observations
            and record.node_id not in self._in_flight
        ]
        return tuple(ready[:capacity])

    def issue_dispatch(
        self,
        node_id: str,
        *,
        approval_granted: bool = False,
    ) -> DispatchTicket:
        if self._cancelled:
            raise ExecutionSchedulerError("SCHEDULER_CANCELLED")
        node = self._nodes.get(node_id)
        if node is None:
            raise ExecutionSchedulerError(f"UNKNOWN_EXECUTION_NODE:{node_id}")
        if node_id in self._observations:
            raise ExecutionSchedulerError(f"NODE_ALREADY_OBSERVED:{node_id}")
        if node_id in self._in_flight:
            raise ExecutionSchedulerError(f"NODE_ALREADY_IN_FLIGHT:{node_id}")
        if len(self._in_flight) >= self.max_concurrency:
            raise ExecutionSchedulerError("SCHEDULER_BACKPRESSURE")
        if node.approval_required and approval_granted is not True:
            raise ExecutionSchedulerError(f"NODE_APPROVAL_REQUIRED:{node_id}")

        candidate_approvals = (
            frozenset({node_id})
            if node.approval_required and approval_granted
            else frozenset()
        )
        decision = self.admission_decision(approved_nodes=candidate_approvals)
        record = next(row for row in decision.records if row.node_id == node_id)
        if record.state != "READY":
            self._dependency_observations(node)
            raise ExecutionSchedulerError(
                f"SCHEDULER_NODE_NOT_READY:{node_id}:{record.reason_code}"
            )

        dependencies = self._dependency_observations(node)
        self._revalidate_runtime(node)

        try:
            self.budget_guard.reserve(steps=1)
        except ExecutionBudgetExceeded as exc:
            raise ExecutionSchedulerError(
                f"SCHEDULER_BUDGET_DENIED:{exc.reason_code}"
            ) from exc
        except (ValueError, RuntimeError) as exc:
            raise ExecutionSchedulerError("SCHEDULER_BUDGET_RESERVATION_FAILED") from exc

        self._dispatch_sequence += 1
        provisional = DispatchTicket(
            ticket_id="dispatch:" + "0" * 24,
            task_id=self.plan.task_id,
            plan_fingerprint=self.plan.fingerprint,
            node_id=node.node_id,
            node_fingerprint=node.fingerprint,
            authority_fingerprint=node.authority_fingerprint,
            dependency_observation_fingerprints=tuple(
                observation.fingerprint for observation in dependencies
            ),
            dispatch_sequence=self._dispatch_sequence,
            execution_level=node.execution_level,
        )
        ticket_id = "dispatch:" + _digest(provisional._identity_dict()).split(":", 1)[1][:24]
        ticket = DispatchTicket(
            ticket_id=ticket_id,
            task_id=provisional.task_id,
            plan_fingerprint=provisional.plan_fingerprint,
            node_id=provisional.node_id,
            node_fingerprint=provisional.node_fingerprint,
            authority_fingerprint=provisional.authority_fingerprint,
            dependency_observation_fingerprints=provisional.dependency_observation_fingerprints,
            dispatch_sequence=provisional.dispatch_sequence,
            execution_level=provisional.execution_level,
            schema_version=provisional.schema_version,
        ).validate()

        if node.approval_required:
            self._approved_nodes.add(node_id)
        self._in_flight[node.node_id] = ticket
        return ticket

    def issue_ready(
        self,
        *,
        approved_nodes: frozenset[str] = frozenset(),
    ) -> tuple[DispatchTicket, ...]:
        node_ids = self.ready_node_ids(approved_nodes=approved_nodes)
        return tuple(
            self.issue_dispatch(
                node_id,
                approval_granted=node_id in approved_nodes,
            )
            for node_id in node_ids
        )

    def accept_observation(
        self,
        observation: ExecutionObservation,
    ) -> ExecutionObservation:
        if not isinstance(observation, ExecutionObservation):
            raise ExecutionSchedulerError("CANONICAL_EXECUTION_OBSERVATION_REQUIRED")
        ticket = self._in_flight.get(observation.node_id)
        if ticket is None:
            raise ExecutionSchedulerError(
                f"OBSERVATION_NODE_NOT_IN_FLIGHT:{observation.node_id}"
            )
        try:
            observation.validate(
                plan=self.plan,
                parent_authority=self.parent_authority,
            )
        except ExecutionObservationError as exc:
            raise ExecutionSchedulerError(
                f"SCHEDULER_OBSERVATION_REJECTED:{observation.node_id}"
            ) from exc
        if observation.node_fingerprint != ticket.node_fingerprint:
            raise ExecutionSchedulerError("OBSERVATION_TICKET_NODE_MISMATCH")
        if observation.authority_fingerprint != ticket.authority_fingerprint:
            raise ExecutionSchedulerError("OBSERVATION_TICKET_AUTHORITY_MISMATCH")

        proposed = (*self._ordered_observations(), observation)
        try:
            RuntimeScheduler.evaluate(
                task_context=self.task_context,
                plan=self.plan,
                parent_authority=self.parent_authority,
                observations=proposed,
                approved_node_ids=tuple(sorted(self._approved_nodes)),
            )
        except RuntimeSchedulerError as exc:
            raise ExecutionSchedulerError(
                f"SCHEDULER_OBSERVATION_DECISION_REJECTED:{observation.node_id}"
            ) from exc

        self._observations[observation.node_id] = observation
        del self._in_flight[observation.node_id]
        return observation

    def fan_in(self, node_id: str) -> tuple[ExecutionObservation, ...]:
        node = self._nodes.get(node_id)
        if node is None:
            raise ExecutionSchedulerError(f"UNKNOWN_EXECUTION_NODE:{node_id}")
        return self._dependency_observations(node)

    def cancel(self, *, reason_code: str = "OPERATOR_CANCELLED") -> None:
        if not isinstance(reason_code, str) or not reason_code.strip():
            raise ExecutionSchedulerError("INVALID_CANCELLATION_REASON")
        self._cancelled = True
        self._cancellation_reason = reason_code.strip()

    @property
    def cancelled(self) -> bool:
        return self._cancelled

    def snapshot(self) -> dict[str, Any]:
        """Return deterministic control state for future checkpoint binding."""
        return {
            "schema_version": EXECUTION_SCHEDULER_SCHEMA,
            "task_id": self.plan.task_id,
            "task_context_fingerprint": self.task_context.fingerprint,
            "plan_fingerprint": self.plan.fingerprint,
            "parent_authority_fingerprint": self.parent_authority.fingerprint,
            "max_concurrency": self.max_concurrency,
            "cancelled": self._cancelled,
            "cancellation_reason": self._cancellation_reason,
            "dispatch_sequence": self._dispatch_sequence,
            "approved_node_ids": sorted(self._approved_nodes),
            "in_flight": [
                self._in_flight[node.node_id].fingerprint
                for node in self.plan.nodes
                if node.node_id in self._in_flight
            ],
            "observations": [
                self._observations[node.node_id].fingerprint
                for node in self.plan.nodes
                if node.node_id in self._observations
            ],
        }
