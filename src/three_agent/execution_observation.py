from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Mapping

from .capability_authority import TaskCapabilityAuthority
from .execution_plan import ExecutionNode, ExecutionPlan, ExecutionPlanError

EXECUTION_OBSERVATION_SCHEMA = "workspace-execution-observation/v1"
EXECUTION_EVIDENCE_BINDING_SCHEMA = "workspace-execution-evidence-binding/v1"
OBSERVATION_STATUSES = frozenset({"SUCCEEDED", "FAILED", "PARTIAL", "CANCELLED"})
MAX_NORMALIZED_OUTPUT_BYTES = 64 * 1024
MAX_EVIDENCE_BINDINGS = 32

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")


class ExecutionObservationError(ValueError):
    """An execution observation is malformed or not bound to its runtime plan."""


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
        raise ExecutionObservationError("OBSERVATION_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ExecutionObservationError(f"INVALID_{field_name.upper()}")
    return value


def _single_line(value: Any, field_name: str, *, max_len: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ExecutionObservationError(f"INVALID_{field_name.upper()}")
    if len(value) > max_len or "\n" in value or "\r" in value:
        raise ExecutionObservationError(f"INVALID_{field_name.upper()}")
    return value


def _reference(value: Any, field_name: str) -> str:
    text = _single_line(value, field_name, max_len=256)
    if not _REF_RE.fullmatch(text) or "://" in text:
        raise ExecutionObservationError(f"INVALID_{field_name.upper()}")
    if any(segment == ".." for segment in text.split("/")):
        raise ExecutionObservationError(f"INVALID_{field_name.upper()}")
    return text


def _timestamp(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ExecutionObservationError(f"INVALID_{field_name.upper()}")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExecutionObservationError(f"INVALID_{field_name.upper()}") from exc
    if parsed.tzinfo is None:
        raise ExecutionObservationError(f"INVALID_{field_name.upper()}")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalized_output_json(value: Mapping[str, Any] | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ExecutionObservationError("NORMALIZED_OUTPUT_MUST_BE_OBJECT")
    canonical = _canonical_json(dict(value))
    if len(canonical.encode("utf-8")) > MAX_NORMALIZED_OUTPUT_BYTES:
        raise ExecutionObservationError("NORMALIZED_OUTPUT_BOUND_EXCEEDED")
    return canonical


def _node_for(plan: ExecutionPlan, node_id: str) -> ExecutionNode:
    for node in plan.nodes:
        if node.node_id == node_id:
            return node
    raise ExecutionObservationError(f"OBSERVATION_UNKNOWN_NODE:{node_id}")


@dataclass(frozen=True)
class ObservationCost:
    wall_time_s: float = 0.0
    model_tokens: int = 0
    tool_calls: int = 0
    cost_usd: float | None = None

    def validate(self) -> "ObservationCost":
        if (
            isinstance(self.wall_time_s, bool)
            or not isinstance(self.wall_time_s, (int, float))
            or self.wall_time_s < 0
        ):
            raise ExecutionObservationError("INVALID_OBSERVATION_WALL_TIME")
        if (
            isinstance(self.model_tokens, bool)
            or not isinstance(self.model_tokens, int)
            or self.model_tokens < 0
        ):
            raise ExecutionObservationError("INVALID_OBSERVATION_MODEL_TOKENS")
        if (
            isinstance(self.tool_calls, bool)
            or not isinstance(self.tool_calls, int)
            or self.tool_calls < 0
        ):
            raise ExecutionObservationError("INVALID_OBSERVATION_TOOL_CALLS")
        if self.cost_usd is not None and (
            isinstance(self.cost_usd, bool)
            or not isinstance(self.cost_usd, (int, float))
            or self.cost_usd < 0
        ):
            raise ExecutionObservationError("INVALID_OBSERVATION_COST_USD")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "wall_time_s": float(self.wall_time_s),
            "model_tokens": self.model_tokens,
            "tool_calls": self.tool_calls,
            "cost_usd": None if self.cost_usd is None else float(self.cost_usd),
        }

    def validate_against(self, node: ExecutionNode) -> "ObservationCost":
        self.validate()
        budget = node.resource_budget
        if self.wall_time_s > budget.wall_time_s:
            raise ExecutionObservationError("OBSERVATION_WALL_TIME_EXCEEDS_NODE_BUDGET")
        if self.model_tokens > budget.model_tokens:
            raise ExecutionObservationError("OBSERVATION_MODEL_TOKENS_EXCEED_NODE_BUDGET")
        if self.tool_calls > budget.tool_calls:
            raise ExecutionObservationError("OBSERVATION_TOOL_CALLS_EXCEED_NODE_BUDGET")
        if self.cost_usd is not None:
            if budget.cost_usd is None or self.cost_usd > budget.cost_usd:
                raise ExecutionObservationError("OBSERVATION_COST_EXCEEDS_NODE_BUDGET")
        return self


@dataclass(frozen=True)
class ExecutionEvidenceBinding:
    evidence_ref: str
    evidence_fingerprint: str
    requirement: str | None = None
    schema_version: str = EXECUTION_EVIDENCE_BINDING_SCHEMA

    def validate(self) -> "ExecutionEvidenceBinding":
        if self.schema_version != EXECUTION_EVIDENCE_BINDING_SCHEMA:
            raise ExecutionObservationError("EVIDENCE_BINDING_SCHEMA_VERSION_MISMATCH")
        _reference(self.evidence_ref, "evidence_ref")
        _sha256(self.evidence_fingerprint, "evidence_fingerprint")
        if self.requirement is not None:
            _single_line(self.requirement, "evidence_requirement", max_len=256)
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "requirement": self.requirement,
            "evidence_ref": self.evidence_ref,
            "evidence_fingerprint": self.evidence_fingerprint,
        }


def _normalize_evidence_bindings(
    bindings: tuple[ExecutionEvidenceBinding, ...],
) -> tuple[ExecutionEvidenceBinding, ...]:
    if not isinstance(bindings, tuple):
        raise ExecutionObservationError("EVIDENCE_BINDINGS_MUST_BE_TUPLE")
    if len(bindings) > MAX_EVIDENCE_BINDINGS:
        raise ExecutionObservationError("EVIDENCE_BINDING_BOUND_EXCEEDED")
    normalized: list[ExecutionEvidenceBinding] = []
    seen_rows: set[tuple[str | None, str, str]] = set()
    seen_requirements: set[str] = set()
    for binding in bindings:
        if not isinstance(binding, ExecutionEvidenceBinding):
            raise ExecutionObservationError("INVALID_EVIDENCE_BINDING")
        binding.validate()
        row = (binding.requirement, binding.evidence_ref, binding.evidence_fingerprint)
        if row in seen_rows:
            continue
        seen_rows.add(row)
        if binding.requirement is not None:
            if binding.requirement in seen_requirements:
                raise ExecutionObservationError(
                    f"DUPLICATE_EVIDENCE_REQUIREMENT:{binding.requirement}"
                )
            seen_requirements.add(binding.requirement)
        normalized.append(binding)
    return tuple(
        sorted(
            normalized,
            key=lambda item: (
                "" if item.requirement is None else item.requirement,
                item.evidence_ref,
                item.evidence_fingerprint,
            ),
        )
    )


def _validate_evidence_requirements(
    *,
    node: ExecutionNode,
    status: str,
    bindings: tuple[ExecutionEvidenceBinding, ...],
) -> None:
    declared = set(node.evidence_requirements)
    satisfied = {
        binding.requirement
        for binding in bindings
        if binding.requirement is not None
    }
    unknown = sorted(satisfied - declared)
    if unknown:
        raise ExecutionObservationError(
            "OBSERVATION_UNDECLARED_EVIDENCE_REQUIREMENT:" + ",".join(unknown)
        )
    if status == "SUCCEEDED":
        missing = sorted(declared - satisfied)
        if missing:
            raise ExecutionObservationError(
                "OBSERVATION_REQUIRED_EVIDENCE_MISSING:" + ",".join(missing)
            )


@dataclass(frozen=True)
class ExecutionObservation:
    observation_id: str
    task_id: str
    task_context_fingerprint: str
    plan_fingerprint: str
    node_id: str
    node_fingerprint: str
    authority_fingerprint: str
    status: str
    started_at: str
    finished_at: str
    normalized_output_json: str | None
    error_class: str | None
    evidence_bindings: tuple[ExecutionEvidenceBinding, ...]
    cost: ObservationCost | None = None
    schema_version: str = EXECUTION_OBSERVATION_SCHEMA

    @property
    def normalized_output(self) -> dict[str, Any] | None:
        if self.normalized_output_json is None:
            return None
        value = json.loads(self.normalized_output_json)
        if not isinstance(value, dict):
            raise ExecutionObservationError("NORMALIZED_OUTPUT_MUST_BE_OBJECT")
        return value

    @property
    def normalized_output_sha256(self) -> str | None:
        if self.normalized_output_json is None:
            return None
        return "sha256:" + hashlib.sha256(
            self.normalized_output_json.encode("utf-8")
        ).hexdigest()

    @property
    def evidence_refs(self) -> tuple[str, ...]:
        return tuple(binding.evidence_ref for binding in self.evidence_bindings)

    def _identity_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "task_context_fingerprint": self.task_context_fingerprint,
            "plan_fingerprint": self.plan_fingerprint,
            "node_id": self.node_id,
            "node_fingerprint": self.node_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "normalized_output": self.normalized_output,
            "normalized_output_sha256": self.normalized_output_sha256,
            "error_class": self.error_class,
            "evidence_bindings": [
                binding.canonical_dict() for binding in self.evidence_bindings
            ],
            "cost": None if self.cost is None else self.cost.canonical_dict(),
        }

    def validate(
        self,
        *,
        plan: ExecutionPlan | None = None,
        parent_authority: TaskCapabilityAuthority | None = None,
    ) -> "ExecutionObservation":
        if self.schema_version != EXECUTION_OBSERVATION_SCHEMA:
            raise ExecutionObservationError("OBSERVATION_SCHEMA_VERSION_MISMATCH")
        _reference(self.task_id, "task_id")
        _sha256(self.task_context_fingerprint, "task_context_fingerprint")
        _sha256(self.plan_fingerprint, "plan_fingerprint")
        _reference(self.node_id, "node_id")
        _sha256(self.node_fingerprint, "node_fingerprint")
        _sha256(self.authority_fingerprint, "authority_fingerprint")
        if self.status not in OBSERVATION_STATUSES:
            raise ExecutionObservationError("INVALID_OBSERVATION_STATUS")

        started = _timestamp(self.started_at, "started_at")
        finished = _timestamp(self.finished_at, "finished_at")
        if self.started_at != started or self.finished_at != finished:
            raise ExecutionObservationError("OBSERVATION_TIMESTAMPS_NOT_NORMALIZED")
        if datetime.fromisoformat(finished.replace("Z", "+00:00")) < datetime.fromisoformat(
            started.replace("Z", "+00:00")
        ):
            raise ExecutionObservationError("OBSERVATION_FINISHED_BEFORE_STARTED")

        if self.normalized_output_json is not None:
            try:
                value = json.loads(self.normalized_output_json)
            except json.JSONDecodeError as exc:
                raise ExecutionObservationError("INVALID_NORMALIZED_OUTPUT_JSON") from exc
            canonical = _normalized_output_json(value)
            if canonical != self.normalized_output_json:
                raise ExecutionObservationError("NORMALIZED_OUTPUT_NOT_CANONICAL")

        if self.error_class is not None:
            _reference(self.error_class, "error_class")
        if self.status == "SUCCEEDED" and self.error_class is not None:
            raise ExecutionObservationError("SUCCEEDED_OBSERVATION_CANNOT_HAVE_ERROR")
        if self.status == "FAILED" and self.error_class is None:
            raise ExecutionObservationError("FAILED_OBSERVATION_REQUIRES_ERROR_CLASS")

        normalized_bindings = _normalize_evidence_bindings(self.evidence_bindings)
        if normalized_bindings != self.evidence_bindings:
            raise ExecutionObservationError("EVIDENCE_BINDINGS_NOT_NORMALIZED")
        if self.cost is not None and not isinstance(self.cost, ObservationCost):
            raise ExecutionObservationError("INVALID_OBSERVATION_COST")
        if self.cost is not None:
            self.cost.validate()

        if plan is not None:
            if not isinstance(plan, ExecutionPlan):
                raise ExecutionObservationError("INVALID_EXECUTION_PLAN")
            try:
                if parent_authority is None:
                    plan.validate()
                else:
                    plan.validate(parent_authority=parent_authority)
            except ExecutionPlanError as exc:
                raise ExecutionObservationError("OBSERVATION_PLAN_REVALIDATION_FAILED") from exc
            node = _node_for(plan, self.node_id)
            if self.task_id != plan.task_id:
                raise ExecutionObservationError("OBSERVATION_TASK_MISMATCH")
            if self.task_context_fingerprint != plan.task_context_fingerprint:
                raise ExecutionObservationError("OBSERVATION_TASK_CONTEXT_MISMATCH")
            if self.plan_fingerprint != plan.fingerprint:
                raise ExecutionObservationError("OBSERVATION_PLAN_FINGERPRINT_MISMATCH")
            if self.node_fingerprint != node.fingerprint:
                raise ExecutionObservationError("OBSERVATION_NODE_FINGERPRINT_MISMATCH")
            if self.authority_fingerprint != node.authority_fingerprint:
                raise ExecutionObservationError("OBSERVATION_AUTHORITY_FINGERPRINT_MISMATCH")
            if parent_authority is not None:
                try:
                    rebound = node.rebind_authority(parent_authority)
                except ExecutionPlanError as exc:
                    raise ExecutionObservationError(
                        "OBSERVATION_AUTHORITY_REVALIDATION_FAILED"
                    ) from exc
                if rebound.fingerprint != self.authority_fingerprint:
                    raise ExecutionObservationError(
                        "OBSERVATION_AUTHORITY_FINGERPRINT_MISMATCH"
                    )
            _validate_evidence_requirements(
                node=node,
                status=self.status,
                bindings=self.evidence_bindings,
            )
            if self.cost is not None:
                self.cost.validate_against(node)

        expected_id = "observation:" + _digest(self._identity_dict()).split(":", 1)[1][:24]
        if self.observation_id != expected_id:
            raise ExecutionObservationError("OBSERVATION_IDENTITY_MISMATCH")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {"observation_id": self.observation_id, **self._identity_dict()}

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


class ExecutionObservationBuilder:
    """Create immutable node observations after plan/authority revalidation."""

    @staticmethod
    def build(
        *,
        plan: ExecutionPlan,
        node_id: str,
        parent_authority: TaskCapabilityAuthority,
        status: str,
        started_at: str,
        finished_at: str,
        normalized_output: Mapping[str, Any] | None = None,
        error_class: str | None = None,
        evidence_bindings: tuple[ExecutionEvidenceBinding, ...] = (),
        cost: ObservationCost | None = None,
    ) -> ExecutionObservation:
        if not isinstance(plan, ExecutionPlan):
            raise ExecutionObservationError("INVALID_EXECUTION_PLAN")
        if not isinstance(parent_authority, TaskCapabilityAuthority):
            raise ExecutionObservationError("INVALID_PARENT_AUTHORITY")
        try:
            plan.validate(parent_authority=parent_authority)
        except ExecutionPlanError as exc:
            raise ExecutionObservationError("OBSERVATION_PLAN_REVALIDATION_FAILED") from exc
        node = _node_for(plan, _reference(node_id, "node_id"))
        try:
            rebound = node.rebind_authority(parent_authority)
        except ExecutionPlanError as exc:
            raise ExecutionObservationError(
                "OBSERVATION_AUTHORITY_REVALIDATION_FAILED"
            ) from exc

        if status not in OBSERVATION_STATUSES:
            raise ExecutionObservationError("INVALID_OBSERVATION_STATUS")
        started = _timestamp(started_at, "started_at")
        finished = _timestamp(finished_at, "finished_at")
        if datetime.fromisoformat(finished.replace("Z", "+00:00")) < datetime.fromisoformat(
            started.replace("Z", "+00:00")
        ):
            raise ExecutionObservationError("OBSERVATION_FINISHED_BEFORE_STARTED")
        output_json = _normalized_output_json(normalized_output)
        normalized_bindings = _normalize_evidence_bindings(evidence_bindings)
        _validate_evidence_requirements(
            node=node,
            status=status,
            bindings=normalized_bindings,
        )
        if error_class is not None:
            error_class = _reference(error_class, "error_class")
        if status == "SUCCEEDED" and error_class is not None:
            raise ExecutionObservationError("SUCCEEDED_OBSERVATION_CANNOT_HAVE_ERROR")
        if status == "FAILED" and error_class is None:
            raise ExecutionObservationError("FAILED_OBSERVATION_REQUIRES_ERROR_CLASS")
        if cost is not None:
            if not isinstance(cost, ObservationCost):
                raise ExecutionObservationError("INVALID_OBSERVATION_COST")
            cost.validate_against(node)

        provisional = ExecutionObservation(
            observation_id="observation:" + "0" * 24,
            task_id=plan.task_id,
            task_context_fingerprint=plan.task_context_fingerprint,
            plan_fingerprint=plan.fingerprint,
            node_id=node.node_id,
            node_fingerprint=node.fingerprint,
            authority_fingerprint=rebound.fingerprint,
            status=status,
            started_at=started,
            finished_at=finished,
            normalized_output_json=output_json,
            error_class=error_class,
            evidence_bindings=normalized_bindings,
            cost=cost,
        )
        observation_id = "observation:" + _digest(provisional._identity_dict()).split(":", 1)[1][:24]
        result = ExecutionObservation(
            **{**provisional.__dict__, "observation_id": observation_id}
        )
        return result.validate(plan=plan, parent_authority=parent_authority)
