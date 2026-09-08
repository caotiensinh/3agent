from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable

from .capability_authority import CapabilityAuthorityDenied, TaskCapabilityAuthority
from .task_contract import TaskContract

RUNTIME_EXECUTION_PLAN_SCHEMA = "workspace-runtime-execution-plan/v1"
RUNTIME_OBSERVATION_SCHEMA = "workspace-runtime-observation/v1"
_MAX_NODES = 64
_MAX_PARALLEL = 16
_NODE_ID_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_REASON_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_OBSERVATION_STATUSES = {"succeeded", "failed", "denied", "skipped"}
_MUTATING_EFFECTS = {"write", "network_write", "destructive"}


class RuntimeExecutionPlanError(ValueError):
    """An execution plan violates task authority, graph, or runtime safety rules."""


def _canonical_sha256(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _compact(value: Any, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _COMPACT_RE.fullmatch(text):
        raise RuntimeExecutionPlanError(f"{field_name} must be a compact identifier")
    if "://" in text:
        raise RuntimeExecutionPlanError(f"{field_name} must not contain raw URLs")
    return text


def _unique(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(value).strip() for value in values if str(value).strip()))


@dataclass(frozen=True)
class ExecutionNode:
    node_id: str
    capability: str
    resource_kind: str
    resource_ref: str
    effect: str
    depends_on: tuple[str, ...] = field(default_factory=tuple)
    idempotent: bool = True
    timeout_ms: int = 30_000
    approval_required: bool = False

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["depends_on"] = list(self.depends_on)
        return payload


@dataclass(frozen=True)
class RuntimeExecutionPlan:
    plan_id: str
    task_id: str
    authority_fingerprint: str
    risk_level: str
    evidence_required: bool
    nodes: tuple[ExecutionNode, ...]
    max_parallel: int = 4
    schema_version: str = RUNTIME_EXECUTION_PLAN_SCHEMA

    @classmethod
    def compile(
        cls,
        *,
        plan_id: str,
        task_contract: TaskContract,
        nodes: Iterable[ExecutionNode],
        max_parallel: int = 4,
    ) -> "RuntimeExecutionPlan":
        task_contract.validate()
        authority = TaskCapabilityAuthority.from_contract(task_contract)
        plan = cls(
            plan_id=str(plan_id),
            task_id=task_contract.task_id,
            authority_fingerprint=authority.fingerprint,
            risk_level=task_contract.risk_level,
            evidence_required=task_contract.evidence_required,
            nodes=tuple(nodes),
            max_parallel=max_parallel,
        )
        return plan.validate(authority)

    def _node_map(self) -> dict[str, ExecutionNode]:
        return {node.node_id: node for node in self.nodes}

    def validate(self, authority: TaskCapabilityAuthority) -> "RuntimeExecutionPlan":
        _compact(self.plan_id, "plan_id", max_len=128)
        if self.task_id != authority.task_id:
            raise RuntimeExecutionPlanError("PLAN_TASK_AUTHORITY_MISMATCH")
        if self.authority_fingerprint != authority.fingerprint:
            raise RuntimeExecutionPlanError("PLAN_AUTHORITY_FINGERPRINT_MISMATCH")
        if self.risk_level not in {"low", "medium", "high", "critical"}:
            raise RuntimeExecutionPlanError("unsupported risk_level")
        if not isinstance(self.max_parallel, int) or isinstance(self.max_parallel, bool):
            raise RuntimeExecutionPlanError("max_parallel must be an integer")
        if not 1 <= self.max_parallel <= _MAX_PARALLEL:
            raise RuntimeExecutionPlanError(f"max_parallel must be within [1,{_MAX_PARALLEL}]")
        if not 1 <= len(self.nodes) <= _MAX_NODES:
            raise RuntimeExecutionPlanError(f"plan must contain between 1 and {_MAX_NODES} nodes")

        by_id: dict[str, ExecutionNode] = {}
        for node in self.nodes:
            if not _NODE_ID_RE.fullmatch(str(node.node_id)):
                raise RuntimeExecutionPlanError(f"invalid node_id: {node.node_id}")
            if node.node_id in by_id:
                raise RuntimeExecutionPlanError(f"duplicate node_id: {node.node_id}")
            if not isinstance(node.timeout_ms, int) or isinstance(node.timeout_ms, bool) or not 100 <= node.timeout_ms <= 3_600_000:
                raise RuntimeExecutionPlanError(f"invalid timeout for node {node.node_id}")
            if not isinstance(node.idempotent, bool) or not isinstance(node.approval_required, bool):
                raise RuntimeExecutionPlanError(f"invalid flags for node {node.node_id}")
            by_id[node.node_id] = node

            try:
                decision = authority.authorize(
                    node.capability,
                    resource_kind=node.resource_kind,
                    resource_ref=node.resource_ref,
                    effect=node.effect,
                )
            except (ValueError, CapabilityAuthorityDenied) as exc:
                raise RuntimeExecutionPlanError(
                    f"NODE_AUTHORITY_INVALID:{node.node_id}:{exc}"
                ) from exc
            if not decision.allowed:
                raise RuntimeExecutionPlanError(
                    f"NODE_AUTHORITY_DENIED:{node.node_id}:{decision.reason_code}"
                )
            if (
                self.risk_level in {"high", "critical"}
                and node.effect in _MUTATING_EFFECTS
                and not node.approval_required
            ):
                raise RuntimeExecutionPlanError(
                    f"HIGH_RISK_MUTATION_REQUIRES_APPROVAL:{node.node_id}"
                )

        indegree = {node_id: 0 for node_id in by_id}
        children: dict[str, list[str]] = {node_id: [] for node_id in by_id}
        for node in self.nodes:
            normalized_dependencies = _unique(node.depends_on)
            if len(normalized_dependencies) != len(node.depends_on):
                raise RuntimeExecutionPlanError(f"duplicate dependency on node {node.node_id}")
            for parent in normalized_dependencies:
                if parent not in by_id:
                    raise RuntimeExecutionPlanError(
                        f"node {node.node_id} depends on unknown node {parent}"
                    )
                if parent == node.node_id:
                    raise RuntimeExecutionPlanError(f"node {node.node_id} cannot depend on itself")
                indegree[node.node_id] += 1
                children[parent].append(node.node_id)

        queue = sorted(node_id for node_id, degree in indegree.items() if degree == 0)
        visited: list[str] = []
        while queue:
            current = queue.pop(0)
            visited.append(current)
            for child in sorted(children[current]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
                    queue.sort()
        if len(visited) != len(self.nodes):
            raise RuntimeExecutionPlanError("execution plan contains a cycle")
        return self

    @property
    def fingerprint(self) -> str:
        return _canonical_sha256(self.to_dict())

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "plan_id": self.plan_id,
            "task_id": self.task_id,
            "authority_fingerprint": self.authority_fingerprint,
            "risk_level": self.risk_level,
            "evidence_required": self.evidence_required,
            "max_parallel": self.max_parallel,
            "nodes": [node.to_dict() for node in self.nodes],
        }

    def topological_order(self) -> tuple[str, ...]:
        by_id = self._node_map()
        indegree = {node_id: 0 for node_id in by_id}
        children: dict[str, list[str]] = {node_id: [] for node_id in by_id}
        for node in self.nodes:
            for parent in node.depends_on:
                indegree[node.node_id] += 1
                children[parent].append(node.node_id)
        queue = sorted(node_id for node_id, degree in indegree.items() if degree == 0)
        order: list[str] = []
        while queue:
            current = queue.pop(0)
            order.append(current)
            for child in sorted(children[current]):
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
                    queue.sort()
        if len(order) != len(by_id):
            raise RuntimeExecutionPlanError("execution plan contains a cycle")
        return tuple(order)

    def ready_nodes(
        self,
        *,
        completed: Iterable[str] = (),
        running: Iterable[str] = (),
        approved: Iterable[str] = (),
    ) -> tuple[ExecutionNode, ...]:
        """Return the deterministic bounded set that may start now.

        Non-mutating nodes can fan out up to ``max_parallel``. Mutations are
        serialized and never start while another node is running. Approval-gated
        nodes remain blocked until their exact node ID appears in ``approved``.
        """
        by_id = self._node_map()
        completed_set = set(completed)
        running_set = set(running)
        approved_set = set(approved)
        unknown = (completed_set | running_set | approved_set) - set(by_id)
        if unknown:
            raise RuntimeExecutionPlanError(f"unknown runtime node ids: {sorted(unknown)}")
        if completed_set & running_set:
            raise RuntimeExecutionPlanError("a node cannot be completed and running")

        candidates = [
            node
            for node in self.nodes
            if node.node_id not in completed_set
            and node.node_id not in running_set
            and set(node.depends_on).issubset(completed_set)
            and (not node.approval_required or node.node_id in approved_set)
        ]
        candidates.sort(key=lambda item: item.node_id)
        available_slots = max(0, self.max_parallel - len(running_set))
        if available_slots == 0:
            return ()

        non_mutating = [node for node in candidates if node.effect not in _MUTATING_EFFECTS]
        if non_mutating:
            return tuple(non_mutating[:available_slots])

        mutating = [node for node in candidates if node.effect in _MUTATING_EFFECTS]
        if mutating and not running_set:
            return (mutating[0],)
        return ()


@dataclass(frozen=True)
class ExecutionObservation:
    observation_id: str
    task_id: str
    plan_id: str
    plan_fingerprint: str
    node_id: str
    capability: str
    status: str
    reason_code: str
    result_sha256: str
    evidence_refs: tuple[str, ...]
    authority_fingerprint: str
    schema_version: str = RUNTIME_OBSERVATION_SCHEMA

    @classmethod
    def capture(
        cls,
        *,
        plan: RuntimeExecutionPlan,
        node_id: str,
        status: str,
        reason_code: str,
        result: Any,
        evidence_refs: Iterable[str] = (),
    ) -> "ExecutionObservation":
        by_id = plan._node_map()
        if node_id not in by_id:
            raise RuntimeExecutionPlanError("OBSERVATION_NODE_NOT_IN_PLAN")
        normalized_status = str(status).strip().lower()
        if normalized_status not in _OBSERVATION_STATUSES:
            raise RuntimeExecutionPlanError("unsupported observation status")
        normalized_reason = str(reason_code).strip().upper()
        if not _REASON_RE.fullmatch(normalized_reason):
            raise RuntimeExecutionPlanError("reason_code must be compact machine-readable text")
        refs: list[str] = []
        for raw in evidence_refs:
            ref = str(raw).strip()
            if not ref:
                continue
            if not _COMPACT_RE.fullmatch(ref) or "://" in ref:
                raise RuntimeExecutionPlanError("evidence_refs must be compact references")
            if ref not in refs:
                refs.append(ref)
            if len(refs) > 32:
                raise RuntimeExecutionPlanError("at most 32 evidence_refs are allowed")

        result_sha = _canonical_sha256(result)
        node = by_id[node_id]
        identity = {
            "task_id": plan.task_id,
            "plan_id": plan.plan_id,
            "plan_fingerprint": plan.fingerprint,
            "node_id": node.node_id,
            "capability": node.capability,
            "status": normalized_status,
            "reason_code": normalized_reason,
            "result_sha256": result_sha,
            "evidence_refs": refs,
            "authority_fingerprint": plan.authority_fingerprint,
        }
        observation_id = "obs:" + _canonical_sha256(identity).split(":", 1)[1][:32]
        return cls(
            observation_id=observation_id,
            task_id=plan.task_id,
            plan_id=plan.plan_id,
            plan_fingerprint=plan.fingerprint,
            node_id=node.node_id,
            capability=node.capability,
            status=normalized_status,
            reason_code=normalized_reason,
            result_sha256=result_sha,
            evidence_refs=tuple(refs),
            authority_fingerprint=plan.authority_fingerprint,
        )

    def metadata(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["evidence_refs"] = list(self.evidence_refs)
        return payload
