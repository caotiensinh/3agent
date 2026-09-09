from __future__ import annotations

from typing import Any, Mapping

from .capability_authority import TaskCapabilityAuthority
from .computer_use import (
    ComputerActionRequest,
    ComputerObservation,
    ComputerUseError,
    require_fresh_observation,
)
from .execution_observation import (
    ExecutionEvidenceBinding,
    ExecutionObservation,
    ExecutionObservationBuilder,
    ObservationCost,
)
from .execution_plan import ExecutionPlan


class ComputerEvidenceError(ValueError):
    """Computer-use execution evidence is malformed or not bound to the action/runtime."""


def _require_post_observation(
    *,
    action: ComputerActionRequest,
    pre_observation: ComputerObservation,
    post_observation: ComputerObservation,
) -> None:
    try:
        require_fresh_observation(action, pre_observation)
        post_observation.validate()
    except ComputerUseError as exc:
        raise ComputerEvidenceError("COMPUTER_EVIDENCE_OBSERVATION_INVALID") from exc
    if post_observation.session_id != action.session_id:
        raise ComputerEvidenceError("COMPUTER_EVIDENCE_POST_SESSION_MISMATCH")
    if post_observation.task_id != action.task_id:
        raise ComputerEvidenceError("COMPUTER_EVIDENCE_POST_TASK_MISMATCH")
    if post_observation.surface != pre_observation.surface:
        raise ComputerEvidenceError("COMPUTER_EVIDENCE_SURFACE_CHANGED")


def build_computer_execution_observation(
    *,
    plan: ExecutionPlan,
    node_id: str,
    parent_authority: TaskCapabilityAuthority,
    action: ComputerActionRequest,
    pre_observation: ComputerObservation,
    post_observation: ComputerObservation,
    status: str,
    started_at: str,
    finished_at: str,
    executor_ref: str,
    route: str,
    result: Mapping[str, Any] | None = None,
    error_class: str | None = None,
    evidence_bindings: tuple[ExecutionEvidenceBinding, ...] = (),
    cost: ObservationCost | None = None,
) -> ExecutionObservation:
    """Project bounded computer-use results into canonical WorkSpace observation evidence.

    This adapter does not authorize execution and does not weaken plan/node evidence rules.
    It preserves the existing ExecutionObservationBuilder as the final validation gate.
    """

    if not isinstance(plan, ExecutionPlan):
        raise TypeError("plan must be ExecutionPlan")
    if not isinstance(parent_authority, TaskCapabilityAuthority):
        raise TypeError("parent_authority must be TaskCapabilityAuthority")
    action.validate()
    _require_post_observation(
        action=action,
        pre_observation=pre_observation,
        post_observation=post_observation,
    )
    if action.plan_fingerprint != plan.fingerprint:
        raise ComputerEvidenceError("COMPUTER_EVIDENCE_PLAN_FINGERPRINT_MISMATCH")
    if action.node_id != node_id:
        raise ComputerEvidenceError("COMPUTER_EVIDENCE_NODE_MISMATCH")
    if not isinstance(executor_ref, str) or not executor_ref or executor_ref != executor_ref.strip():
        raise ComputerEvidenceError("INVALID_COMPUTER_EXECUTOR_REF")
    if len(executor_ref) > 128 or "\n" in executor_ref or "\r" in executor_ref:
        raise ComputerEvidenceError("INVALID_COMPUTER_EXECUTOR_REF")
    if route not in {"api", "cli", "dom", "accessibility", "vision_pointer"}:
        raise ComputerEvidenceError("INVALID_COMPUTER_EXECUTION_ROUTE")
    if result is not None and not isinstance(result, Mapping):
        raise ComputerEvidenceError("COMPUTER_RESULT_MUST_BE_OBJECT")

    normalized_output = {
        "computer_use": {
            "action_fingerprint": action.fingerprint,
            "action_id": action.action_id,
            "operation": action.operation,
            "resource_kind": action.resource_kind,
            "resource_ref": action.resource_ref,
            "risk_class": action.risk_class,
            "requires_writer": action.requires_writer,
            "idempotency_key": action.idempotency_key,
            "executor_ref": executor_ref,
            "route": route,
            "pre_state_sha256": pre_observation.state_sha256,
            "post_state_sha256": post_observation.state_sha256,
            "pre_observation_fingerprint": pre_observation.fingerprint,
            "post_observation_fingerprint": post_observation.fingerprint,
            "pre_screenshot_sha256": pre_observation.screenshot_sha256,
            "post_screenshot_sha256": post_observation.screenshot_sha256,
            "post_active_target_ref": post_observation.active_target_ref,
            "result": None if result is None else dict(result),
        }
    }

    return ExecutionObservationBuilder.build(
        plan=plan,
        node_id=node_id,
        parent_authority=parent_authority,
        status=status,
        started_at=started_at,
        finished_at=finished_at,
        normalized_output=normalized_output,
        error_class=error_class,
        evidence_bindings=evidence_bindings,
        cost=cost,
    )
