from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Mapping

from .capability_authority import CapabilityAuthorityDenied, TaskCapabilityAuthority
from .task_context import TaskContext, TaskResourceBudget
from .workflow_design import MAX_NODES, WorkflowDesignError, _graph, validate_contract

EXECUTION_NODE_SCHEMA = "workspace-execution-node/v1"
EXECUTION_PLAN_SCHEMA = "workspace-execution-plan/v1"
MAX_EVIDENCE_REQUIREMENTS = 16

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_RISK_RANK = {"R0": 0, "R1": 1, "R2": 2, "R3": 3, "R4": 4}
_WORKFLOW_RISK_CLASS = {"low": "R1", "medium": "R2", "high": "R3", "critical": "R4"}


class ExecutionPlanError(ValueError):
    """A runtime execution plan violates a canonical WorkSpace invariant."""


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
        raise ExecutionPlanError("EXECUTION_PLAN_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ExecutionPlanError(f"INVALID_{field_name.upper()}")
    return value


def _single_line(value: Any, field_name: str, *, max_len: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ExecutionPlanError(f"INVALID_{field_name.upper()}")
    if len(value) > max_len or "\n" in value or "\r" in value:
        raise ExecutionPlanError(f"INVALID_{field_name.upper()}")
    return value


def _normalize_requirements(values: tuple[str, ...]) -> tuple[str, ...]:
    if not isinstance(values, tuple):
        raise ExecutionPlanError("EVIDENCE_REQUIREMENTS_MUST_BE_TUPLE")
    normalized = tuple(
        sorted(
            {
                _single_line(value, "evidence_requirement", max_len=256)
                for value in values
            }
        )
    )
    if len(normalized) > MAX_EVIDENCE_REQUIREMENTS:
        raise ExecutionPlanError("TOO_MANY_EVIDENCE_REQUIREMENTS")
    return normalized


def _normalize_scope(value: str | tuple[str, ...]) -> str | tuple[str, ...]:
    if isinstance(value, str):
        return value
    if not isinstance(value, tuple):
        raise ExecutionPlanError("WRITE_SCOPE_MUST_BE_STRING_OR_TUPLE")
    return tuple(sorted(dict.fromkeys(value)))


def _zero_budget() -> TaskResourceBudget:
    return TaskResourceBudget(
        wall_time_s=0,
        model_tokens=0,
        tool_calls=0,
        cost_usd=None,
    )


def _budget_dimension_is_subset(
    child: int | float | None,
    parent: int | float | None,
) -> bool:
    if parent is None:
        return child is None
    if child is None:
        return False
    return child <= parent


def _require_budget_subset(child: TaskResourceBudget, parent: TaskResourceBudget) -> None:
    child.validate()
    parent.validate()
    for field_name in ("wall_time_s", "model_tokens", "tool_calls", "cost_usd"):
        if not _budget_dimension_is_subset(
            getattr(child, field_name),
            getattr(parent, field_name),
        ):
            raise ExecutionPlanError(f"EXECUTION_NODE_BUDGET_EXCEEDS_TASK_{field_name.upper()}")


def _require_aggregate_budget(
    nodes: tuple["ExecutionNode", ...],
    parent: TaskResourceBudget,
) -> None:
    for field_name in ("wall_time_s", "model_tokens", "tool_calls", "cost_usd"):
        parent_value = getattr(parent, field_name)
        child_values = [getattr(node.resource_budget, field_name) for node in nodes]
        if parent_value is None:
            if any(value is not None for value in child_values):
                raise ExecutionPlanError(
                    f"EXECUTION_PLAN_BUDGET_DIMENSION_NOT_BOUND_{field_name.upper()}"
                )
            continue
        if any(value is None for value in child_values):
            raise ExecutionPlanError(
                f"EXECUTION_PLAN_BUDGET_DIMENSION_MISSING_{field_name.upper()}"
            )
        if sum(child_values) > parent_value:
            raise ExecutionPlanError(
                f"EXECUTION_PLAN_BUDGET_EXCEEDS_TASK_{field_name.upper()}"
            )


def _child_task_id(task_id: str, node_id: str) -> str:
    candidate = f"{task_id}:{node_id}"
    if len(candidate) <= 128:
        return candidate
    digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()[:32]
    return f"node:{digest}:{node_id}"


@dataclass(frozen=True)
class ExecutionNodeBinding:
    """Trusted, deny-by-default node constraints supplied outside the workflow model."""

    allowed_sources: tuple[str, ...] = field(default_factory=tuple)
    allowed_tools: tuple[str, ...] = field(default_factory=tuple)
    write_scope: str | tuple[str, ...] = "none"
    network_scope: str = "deny"
    resource_budget: TaskResourceBudget = field(default_factory=_zero_budget)
    evidence_requirements: tuple[str, ...] = field(default_factory=tuple)
    approval_required: bool = False

    def normalized(self) -> "ExecutionNodeBinding":
        if not isinstance(self.allowed_sources, tuple):
            raise ExecutionPlanError("ALLOWED_SOURCES_MUST_BE_TUPLE")
        if not isinstance(self.allowed_tools, tuple):
            raise ExecutionPlanError("ALLOWED_TOOLS_MUST_BE_TUPLE")
        if not isinstance(self.resource_budget, TaskResourceBudget):
            raise ExecutionPlanError("INVALID_EXECUTION_NODE_BUDGET")
        self.resource_budget.validate()
        if not isinstance(self.approval_required, bool):
            raise ExecutionPlanError("APPROVAL_REQUIRED_MUST_BE_BOOLEAN")
        return ExecutionNodeBinding(
            allowed_sources=tuple(sorted(dict.fromkeys(self.allowed_sources))),
            allowed_tools=tuple(sorted(dict.fromkeys(self.allowed_tools))),
            write_scope=_normalize_scope(self.write_scope),
            network_scope=_single_line(self.network_scope, "network_scope", max_len=64),
            resource_budget=self.resource_budget,
            evidence_requirements=_normalize_requirements(self.evidence_requirements),
            approval_required=self.approval_required,
        )


@dataclass(frozen=True)
class ExecutionNode:
    node_id: str
    label: str
    kind: str
    action: str
    depends_on: tuple[str, ...]
    condition: str | None
    approval_required: bool
    execution_level: int
    authority_task_id: str
    authority_fingerprint: str
    allowed_sources: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    write_scope: str | tuple[str, ...]
    network_scope: str
    resource_budget: TaskResourceBudget
    evidence_requirements: tuple[str, ...]
    workflow_node_fingerprint: str
    schema_version: str = EXECUTION_NODE_SCHEMA

    def canonical_dict(self) -> dict[str, Any]:
        _sha256(self.authority_fingerprint, "authority_fingerprint")
        _sha256(self.workflow_node_fingerprint, "workflow_node_fingerprint")
        self.resource_budget.validate()
        if self.schema_version != EXECUTION_NODE_SCHEMA:
            raise ExecutionPlanError("EXECUTION_NODE_SCHEMA_VERSION_MISMATCH")
        if not isinstance(self.execution_level, int) or isinstance(self.execution_level, bool) or self.execution_level < 0:
            raise ExecutionPlanError("INVALID_EXECUTION_LEVEL")
        if not isinstance(self.approval_required, bool):
            raise ExecutionPlanError("APPROVAL_REQUIRED_MUST_BE_BOOLEAN")
        requirements = _normalize_requirements(self.evidence_requirements)
        if requirements != self.evidence_requirements:
            raise ExecutionPlanError("EVIDENCE_REQUIREMENTS_NOT_NORMALIZED")
        return {
            "schema_version": self.schema_version,
            "node_id": self.node_id,
            "label": self.label,
            "kind": self.kind,
            "action": self.action,
            "depends_on": list(self.depends_on),
            "condition": self.condition,
            "approval_required": self.approval_required,
            "execution_level": self.execution_level,
            "authority_task_id": self.authority_task_id,
            "authority_fingerprint": self.authority_fingerprint,
            "authority_projection": {
                "allowed_sources": list(self.allowed_sources),
                "allowed_tools": list(self.allowed_tools),
                "write_scope": (
                    list(self.write_scope)
                    if isinstance(self.write_scope, tuple)
                    else self.write_scope
                ),
                "network_scope": self.network_scope,
            },
            "resource_budget": self.resource_budget.canonical_dict(),
            "evidence_requirements": list(self.evidence_requirements),
            "workflow_node_fingerprint": self.workflow_node_fingerprint,
            "execution_authorized": False,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())

    def rebind_authority(
        self,
        parent_authority: TaskCapabilityAuthority,
    ) -> TaskCapabilityAuthority:
        if not isinstance(parent_authority, TaskCapabilityAuthority):
            raise ExecutionPlanError("INVALID_PARENT_AUTHORITY")
        try:
            rebound = parent_authority.derive_child(
                task_id=self.authority_task_id,
                allowed_sources=self.allowed_sources,
                allowed_tools=self.allowed_tools,
                write_scope=self.write_scope,
                network_scope=self.network_scope,
            )
        except (CapabilityAuthorityDenied, ValueError) as exc:
            raise ExecutionPlanError(
                f"EXECUTION_NODE_AUTHORITY_REBIND_FAILED:{self.node_id}"
            ) from exc
        if rebound.fingerprint != self.authority_fingerprint:
            raise ExecutionPlanError(
                f"EXECUTION_NODE_AUTHORITY_FINGERPRINT_MISMATCH:{self.node_id}"
            )
        return rebound


@dataclass(frozen=True)
class ExecutionPlan:
    task_id: str
    task_context_fingerprint: str
    task_context_identity_fingerprint: str
    task_risk_class: str
    parent_authority_fingerprint: str
    task_resource_budget: TaskResourceBudget
    workflow_contract_json: str
    workflow_contract_fingerprint: str
    nodes: tuple[ExecutionNode, ...]
    schema_version: str = EXECUTION_PLAN_SCHEMA
    execution_authorized: bool = field(default=False, init=False)
    execution_mode: str = field(default="plan_only", init=False)

    def _validated_workflow(self) -> dict[str, Any]:
        try:
            raw = json.loads(self.workflow_contract_json)
        except (TypeError, json.JSONDecodeError) as exc:
            raise ExecutionPlanError("INVALID_WORKFLOW_CONTRACT_JSON") from exc
        try:
            normalized = validate_contract(raw)
        except WorkflowDesignError as exc:
            raise ExecutionPlanError("INVALID_WORKFLOW_CONTRACT") from exc
        canonical = _canonical_json(normalized)
        if canonical != self.workflow_contract_json:
            raise ExecutionPlanError("WORKFLOW_CONTRACT_NOT_CANONICAL")
        if _digest(normalized) != self.workflow_contract_fingerprint:
            raise ExecutionPlanError("WORKFLOW_CONTRACT_FINGERPRINT_MISMATCH")
        return normalized

    def validate(
        self,
        *,
        parent_authority: TaskCapabilityAuthority | None = None,
    ) -> "ExecutionPlan":
        if self.schema_version != EXECUTION_PLAN_SCHEMA:
            raise ExecutionPlanError("EXECUTION_PLAN_SCHEMA_VERSION_MISMATCH")
        _sha256(self.task_context_fingerprint, "task_context_fingerprint")
        _sha256(
            self.task_context_identity_fingerprint,
            "task_context_identity_fingerprint",
        )
        _sha256(self.parent_authority_fingerprint, "parent_authority_fingerprint")
        _sha256(
            self.workflow_contract_fingerprint,
            "workflow_contract_fingerprint",
        )
        if self.task_risk_class not in _RISK_RANK:
            raise ExecutionPlanError("INVALID_TASK_RISK_CLASS")
        if not isinstance(self.task_resource_budget, TaskResourceBudget):
            raise ExecutionPlanError("INVALID_TASK_RESOURCE_BUDGET")
        self.task_resource_budget.validate()
        if not isinstance(self.nodes, tuple) or not 2 <= len(self.nodes) <= MAX_NODES:
            raise ExecutionPlanError("INVALID_EXECUTION_PLAN_NODE_COUNT")

        workflow = self._validated_workflow()
        workflow_risk = _WORKFLOW_RISK_CLASS[workflow["risk_level"]]
        if _RISK_RANK[workflow_risk] < _RISK_RANK[self.task_risk_class]:
            raise ExecutionPlanError("EXECUTION_PLAN_RISK_UNDERCLASSIFIED")

        workflow_by_id = {node["id"]: node for node in workflow["nodes"]}
        order, levels = _graph(workflow["nodes"])
        if tuple(order) != tuple(node.node_id for node in self.nodes):
            raise ExecutionPlanError("EXECUTION_PLAN_TOPOLOGY_MISMATCH")

        seen: set[str] = set()
        for node in self.nodes:
            if node.node_id in seen:
                raise ExecutionPlanError("DUPLICATE_EXECUTION_NODE_ID")
            seen.add(node.node_id)
            source = workflow_by_id.get(node.node_id)
            if source is None:
                raise ExecutionPlanError("EXECUTION_NODE_NOT_IN_WORKFLOW")
            source_fingerprint = _digest(source)
            if node.workflow_node_fingerprint != source_fingerprint:
                raise ExecutionPlanError(
                    f"EXECUTION_NODE_WORKFLOW_FINGERPRINT_MISMATCH:{node.node_id}"
                )
            if (
                node.label != source["label"]
                or node.kind != source["kind"]
                or node.action != source["action"]
                or node.depends_on != tuple(source["depends_on"])
                or node.condition != source["condition"]
                or node.execution_level != levels[node.node_id]
            ):
                raise ExecutionPlanError(
                    f"EXECUTION_NODE_WORKFLOW_PROJECTION_MISMATCH:{node.node_id}"
                )
            if source["approval_required"] and not node.approval_required:
                raise ExecutionPlanError(
                    f"EXECUTION_NODE_APPROVAL_WEAKENED:{node.node_id}"
                )
            if source["kind"] == "approval" and not node.approval_required:
                raise ExecutionPlanError(
                    f"EXECUTION_NODE_APPROVAL_WEAKENED:{node.node_id}"
                )
            node.canonical_dict()

        _require_aggregate_budget(self.nodes, self.task_resource_budget)

        if parent_authority is not None:
            if not isinstance(parent_authority, TaskCapabilityAuthority):
                raise ExecutionPlanError("INVALID_PARENT_AUTHORITY")
            if parent_authority.task_id != self.task_id:
                raise ExecutionPlanError("EXECUTION_PLAN_PARENT_TASK_MISMATCH")
            if parent_authority.fingerprint != self.parent_authority_fingerprint:
                raise ExecutionPlanError("EXECUTION_PLAN_PARENT_AUTHORITY_MISMATCH")
            for node in self.nodes:
                node.rebind_authority(parent_authority)

        if self.execution_authorized is not False or self.execution_mode != "plan_only":
            raise ExecutionPlanError("EXECUTION_PLAN_CANNOT_AUTHORIZE_EXECUTION")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        workflow = json.loads(self.workflow_contract_json)
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "task_context_fingerprint": self.task_context_fingerprint,
            "task_context_identity_fingerprint": self.task_context_identity_fingerprint,
            "task_risk_class": self.task_risk_class,
            "parent_authority_fingerprint": self.parent_authority_fingerprint,
            "task_resource_budget": self.task_resource_budget.canonical_dict(),
            "workflow_contract": workflow,
            "workflow_contract_fingerprint": self.workflow_contract_fingerprint,
            "nodes": [node.canonical_dict() for node in self.nodes],
            "execution_authorized": False,
            "execution_mode": "plan_only",
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())

    def rebind_authorities(
        self,
        parent_authority: TaskCapabilityAuthority,
    ) -> dict[str, TaskCapabilityAuthority]:
        self.validate(parent_authority=parent_authority)
        return {
            node.node_id: node.rebind_authority(parent_authority)
            for node in self.nodes
        }


class ExecutionPlanBuilder:
    """Promote a validated workflow DAG into a canonical, non-executing runtime plan."""

    @staticmethod
    def build(
        *,
        task_context: TaskContext,
        parent_authority: TaskCapabilityAuthority,
        workflow_contract: Mapping[str, Any],
        node_bindings: Mapping[str, ExecutionNodeBinding] | None = None,
    ) -> ExecutionPlan:
        if not isinstance(task_context, TaskContext):
            raise ExecutionPlanError("INVALID_TASK_CONTEXT")
        task_context.validate()
        if not isinstance(parent_authority, TaskCapabilityAuthority):
            raise ExecutionPlanError("INVALID_PARENT_AUTHORITY")
        if parent_authority.task_id != task_context.task_id:
            raise ExecutionPlanError("EXECUTION_PLAN_PARENT_TASK_MISMATCH")
        if parent_authority.fingerprint != task_context.authority_fingerprint:
            raise ExecutionPlanError("EXECUTION_PLAN_PARENT_AUTHORITY_MISMATCH")
        if not isinstance(workflow_contract, Mapping):
            raise ExecutionPlanError("INVALID_WORKFLOW_CONTRACT")

        try:
            workflow = validate_contract(dict(workflow_contract))
        except WorkflowDesignError as exc:
            raise ExecutionPlanError("INVALID_WORKFLOW_CONTRACT") from exc

        workflow_risk = _WORKFLOW_RISK_CLASS[workflow["risk_level"]]
        if _RISK_RANK[workflow_risk] < _RISK_RANK[task_context.risk_class]:
            raise ExecutionPlanError("EXECUTION_PLAN_RISK_UNDERCLASSIFIED")

        bindings = dict(node_bindings or {})
        known_ids = {node["id"] for node in workflow["nodes"]}
        unknown_bindings = sorted(set(bindings) - known_ids)
        if unknown_bindings:
            raise ExecutionPlanError(
                "EXECUTION_PLAN_UNKNOWN_NODE_BINDING:" + ",".join(unknown_bindings)
            )

        order, levels = _graph(workflow["nodes"])
        workflow_by_id = {node["id"]: node for node in workflow["nodes"]}
        execution_nodes: list[ExecutionNode] = []

        for node_id in order:
            source = workflow_by_id[node_id]
            raw_binding = bindings.get(node_id, ExecutionNodeBinding())
            if not isinstance(raw_binding, ExecutionNodeBinding):
                raise ExecutionPlanError(
                    f"INVALID_EXECUTION_NODE_BINDING:{node_id}"
                )
            binding = raw_binding.normalized()
            _require_budget_subset(
                binding.resource_budget,
                task_context.resource_budget,
            )

            authority_task_id = _child_task_id(task_context.task_id, node_id)
            try:
                child_authority = parent_authority.derive_child(
                    task_id=authority_task_id,
                    allowed_sources=binding.allowed_sources,
                    allowed_tools=binding.allowed_tools,
                    write_scope=binding.write_scope,
                    network_scope=binding.network_scope,
                )
            except (CapabilityAuthorityDenied, ValueError) as exc:
                raise ExecutionPlanError(
                    f"EXECUTION_NODE_AUTHORITY_ESCALATION:{node_id}"
                ) from exc

            approval_required = bool(
                source["approval_required"]
                or source["kind"] == "approval"
                or source["action"] == "human_approval"
                or binding.approval_required
            )
            execution_nodes.append(
                ExecutionNode(
                    node_id=node_id,
                    label=source["label"],
                    kind=source["kind"],
                    action=source["action"],
                    depends_on=tuple(source["depends_on"]),
                    condition=source["condition"],
                    approval_required=approval_required,
                    execution_level=levels[node_id],
                    authority_task_id=child_authority.task_id,
                    authority_fingerprint=child_authority.fingerprint,
                    allowed_sources=child_authority.allowed_sources,
                    allowed_tools=child_authority.allowed_tools,
                    write_scope=child_authority.write_scope,
                    network_scope=child_authority.network_scope,
                    resource_budget=binding.resource_budget,
                    evidence_requirements=binding.evidence_requirements,
                    workflow_node_fingerprint=_digest(source),
                )
            )

        plan = ExecutionPlan(
            task_id=task_context.task_id,
            task_context_fingerprint=task_context.fingerprint,
            task_context_identity_fingerprint=task_context.identity_fingerprint,
            task_risk_class=task_context.risk_class,
            parent_authority_fingerprint=parent_authority.fingerprint,
            task_resource_budget=task_context.resource_budget,
            workflow_contract_json=_canonical_json(workflow),
            workflow_contract_fingerprint=_digest(workflow),
            nodes=tuple(execution_nodes),
        )
        plan.validate(parent_authority=parent_authority)
        return plan
