from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from typing import Any, Iterable

from .capability_authority import TaskCapabilityAuthority
from .harness_context_manifest import ContextManifest
from .harness_task_compiler import CanonicalTaskSpec, HarnessTaskCompilationError
from .task_contract import TaskContract

TASK_CONTEXT_SCHEMA = "workspace-task-context/v1"
_RISK_CLASS_BY_LEVEL = {
    "low": "R1",
    "medium": "R2",
    "high": "R3",
    "critical": "R4",
}
_RISK_CLASSES = frozenset({"R0", "R1", "R2", "R3", "R4"})
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class TaskContextError(ValueError):
    """Runtime task context binding or enrichment violates a canonical invariant."""


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
        raise TaskContextError("TASK_CONTEXT_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _hash_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _compact_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or value != value.strip() or not _ID_RE.fullmatch(value):
        raise TaskContextError(f"INVALID_{field_name.upper()}")
    return value


def _single_line(value: Any, field_name: str, *, max_len: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise TaskContextError(f"INVALID_{field_name.upper()}")
    if len(value) > max_len or "\n" in value or "\r" in value:
        raise TaskContextError(f"INVALID_{field_name.upper()}")
    return value


def _sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise TaskContextError(f"INVALID_{field_name.upper()}")
    return value


def _timestamp(value: Any, field_name: str) -> str:
    text = _single_line(value, field_name, max_len=64)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise TaskContextError(f"INVALID_{field_name.upper()}") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TaskContextError(f"{field_name.upper()}_MUST_BE_TIMEZONE_AWARE")
    return text


def _as_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(normalized)


def _iso8601(value: datetime) -> str:
    if value.tzinfo is None or value.utcoffset() is None:
        raise TaskContextError("TASK_CONTEXT_TIME_MUST_BE_TIMEZONE_AWARE")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_refs(
    values: Iterable[str],
    field_name: str,
    *,
    max_items: int = 1024,
) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = _single_line(value, field_name, max_len=2048)
        if item in seen:
            continue
        seen.add(item)
        result.append(item)
    if len(result) > max_items:
        raise TaskContextError(f"{field_name.upper()}_TOO_MANY")
    return tuple(result)


@dataclass(frozen=True)
class TaskResourceBudget:
    wall_time_s: int | None
    model_tokens: int | None
    tool_calls: int | None
    cost_usd: float | None = None

    def validate(self) -> "TaskResourceBudget":
        for field_name, value in (
            ("wall_time_s", self.wall_time_s),
            ("model_tokens", self.model_tokens),
            ("tool_calls", self.tool_calls),
        ):
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 0
            ):
                raise TaskContextError(f"INVALID_RESOURCE_BUDGET_{field_name.upper()}")

        if self.cost_usd is not None:
            if (
                not isinstance(self.cost_usd, (int, float))
                or isinstance(self.cost_usd, bool)
                or not math.isfinite(float(self.cost_usd))
                or float(self.cost_usd) < 0.0
            ):
                raise TaskContextError("INVALID_RESOURCE_BUDGET_COST_USD")
        return self

    @classmethod
    def from_contract(
        cls,
        task_contract: TaskContract,
        *,
        cost_usd: float | None = None,
    ) -> "TaskResourceBudget":
        task_contract.validate()
        budget = cls(
            wall_time_s=(task_contract.execution_budget.max_wall_time_ms + 999) // 1000,
            model_tokens=(
                task_contract.context_budget.max_input_tokens
                + task_contract.generation_budget.max_output_tokens
            ),
            tool_calls=task_contract.execution_budget.max_tool_calls,
            cost_usd=cost_usd,
        )
        return budget.validate()

    def canonical_dict(self) -> dict[str, int | float | None]:
        self.validate()
        return {
            "wall_time_s": self.wall_time_s,
            "model_tokens": self.model_tokens,
            "tool_calls": self.tool_calls,
            "cost_usd": float(self.cost_usd) if self.cost_usd is not None else None,
        }


@dataclass(frozen=True)
class TaskContext:
    """Immutable runtime binding over existing WorkSpace task/context primitives.

    This object does not grant authority. It binds server-owned execution identity
    to a validated TaskContract, CanonicalTaskSpec and authority fingerprint.
    Raw intent remains in-memory working data; canonical metadata stores only its
    digest so TaskContext is not another persistent raw-prompt store.
    """

    task_id: str
    session_id: str
    trace_id: str
    actor_id: str
    intent: str
    purpose: str
    project_id: str | None
    risk_class: str
    created_at: str
    deadline: str | None
    resource_budget: TaskResourceBudget
    inventory_scope: tuple[str, ...]
    task_contract_fingerprint: str
    canonical_task_fingerprint: str
    authority_fingerprint: str
    context_refs: tuple[str, ...] = field(default_factory=tuple)
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    context_version: int = 1
    parent_context_fingerprint: str | None = None
    schema_version: str = TASK_CONTEXT_SCHEMA

    def validate(self) -> "TaskContext":
        _compact_id(self.task_id, "task_id")
        _compact_id(self.session_id, "session_id")
        _compact_id(self.trace_id, "trace_id")
        _compact_id(self.actor_id, "actor_id")

        if not isinstance(self.intent, str) or not self.intent.strip():
            raise TaskContextError("TASK_CONTEXT_INTENT_REQUIRED")
        if len(self.intent) > 32768:
            raise TaskContextError("TASK_CONTEXT_INTENT_TOO_LARGE")
        _single_line(self.purpose, "purpose", max_len=512)
        if self.project_id is not None:
            _compact_id(self.project_id, "project_id")

        if self.risk_class not in _RISK_CLASSES:
            raise TaskContextError("INVALID_RISK_CLASS")

        created = _as_datetime(_timestamp(self.created_at, "created_at"))
        if self.deadline is not None:
            deadline = _as_datetime(_timestamp(self.deadline, "deadline"))
            if deadline <= created:
                raise TaskContextError("TASK_CONTEXT_DEADLINE_NOT_AFTER_CREATED_AT")

        if not isinstance(self.resource_budget, TaskResourceBudget):
            raise TaskContextError("INVALID_TASK_RESOURCE_BUDGET")
        self.resource_budget.validate()

        if not isinstance(self.inventory_scope, tuple):
            raise TaskContextError("INVENTORY_SCOPE_MUST_BE_TUPLE")
        if _normalize_refs(self.inventory_scope, "inventory_scope") != self.inventory_scope:
            raise TaskContextError("INVENTORY_SCOPE_MUST_BE_UNIQUE_AND_NORMALIZED")

        for value, field_name in (
            (self.task_contract_fingerprint, "task_contract_fingerprint"),
            (self.canonical_task_fingerprint, "canonical_task_fingerprint"),
            (self.authority_fingerprint, "authority_fingerprint"),
        ):
            _sha256(value, field_name)

        if not isinstance(self.context_refs, tuple):
            raise TaskContextError("CONTEXT_REFS_MUST_BE_TUPLE")
        if _normalize_refs(self.context_refs, "context_ref") != self.context_refs:
            raise TaskContextError("CONTEXT_REFS_MUST_BE_UNIQUE_AND_NORMALIZED")

        if not isinstance(self.evidence_refs, tuple):
            raise TaskContextError("EVIDENCE_REFS_MUST_BE_TUPLE")
        if _normalize_refs(self.evidence_refs, "evidence_ref") != self.evidence_refs:
            raise TaskContextError("EVIDENCE_REFS_MUST_BE_UNIQUE_AND_NORMALIZED")

        if (
            not isinstance(self.context_version, int)
            or isinstance(self.context_version, bool)
            or self.context_version < 1
        ):
            raise TaskContextError("INVALID_CONTEXT_VERSION")
        if self.context_version == 1:
            if self.parent_context_fingerprint is not None:
                raise TaskContextError("ROOT_CONTEXT_CANNOT_HAVE_PARENT")
        else:
            _sha256(self.parent_context_fingerprint, "parent_context_fingerprint")

        if self.schema_version != TASK_CONTEXT_SCHEMA:
            raise TaskContextError("TASK_CONTEXT_SCHEMA_VERSION_MISMATCH")
        return self

    @property
    def intent_sha256(self) -> str:
        if not isinstance(self.intent, str):
            raise TaskContextError("TASK_CONTEXT_INTENT_REQUIRED")
        return _hash_text(self.intent)

    def _identity_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "session_id": self.session_id,
            "trace_id": self.trace_id,
            "actor_id": self.actor_id,
            "intent_sha256": self.intent_sha256,
            "purpose": self.purpose,
            "project_id": self.project_id,
            "risk_class": self.risk_class,
            "created_at": self.created_at,
            "deadline": self.deadline,
            "resource_budget": self.resource_budget.canonical_dict(),
            "inventory_scope": list(self.inventory_scope),
            "task_contract_fingerprint": self.task_contract_fingerprint,
            "canonical_task_fingerprint": self.canonical_task_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
        }

    @property
    def identity_fingerprint(self) -> str:
        self.validate()
        return _digest(self._identity_dict())

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            **self._identity_dict(),
            "context_refs": list(self.context_refs),
            "evidence_refs": list(self.evidence_refs),
            "context_version": self.context_version,
            "parent_context_fingerprint": self.parent_context_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())

    def derive(
        self,
        *,
        context_refs: Iterable[str] = (),
        evidence_refs: Iterable[str] = (),
    ) -> "TaskContext":
        """Create versioned enrichment without changing immutable task identity."""
        self.validate()
        merged_context_refs = _normalize_refs(
            (*self.context_refs, *tuple(context_refs)),
            "context_ref",
        )
        merged_evidence_refs = _normalize_refs(
            (*self.evidence_refs, *tuple(evidence_refs)),
            "evidence_ref",
        )
        if (
            merged_context_refs == self.context_refs
            and merged_evidence_refs == self.evidence_refs
        ):
            raise TaskContextError("TASK_CONTEXT_DERIVATION_HAS_NO_NEW_REFERENCES")

        derived = replace(
            self,
            context_refs=merged_context_refs,
            evidence_refs=merged_evidence_refs,
            context_version=self.context_version + 1,
            parent_context_fingerprint=self.fingerprint,
        )
        derived.validate()
        if derived.identity_fingerprint != self.identity_fingerprint:
            raise TaskContextError("TASK_CONTEXT_IDENTITY_CHANGED_DURING_DERIVATION")
        return derived

    def bind_context_manifest(self, manifest: ContextManifest) -> "TaskContext":
        """Bind an audited context manifest after scope and authority verification."""
        self.validate()
        if not isinstance(manifest, ContextManifest):
            raise TaskContextError("INVALID_CONTEXT_MANIFEST")
        manifest.validate()
        if self.project_id is None:
            raise TaskContextError("TASK_CONTEXT_PROJECT_REQUIRED_FOR_MANIFEST")
        if manifest.project_id != self.project_id:
            raise TaskContextError("TASK_CONTEXT_MANIFEST_PROJECT_MISMATCH")
        if manifest.conversation_id != self.session_id:
            raise TaskContextError("TASK_CONTEXT_MANIFEST_SESSION_MISMATCH")
        if manifest.task_id != self.task_id:
            raise TaskContextError("TASK_CONTEXT_MANIFEST_TASK_MISMATCH")
        if manifest.authority_fingerprint != self.authority_fingerprint:
            raise TaskContextError("TASK_CONTEXT_MANIFEST_AUTHORITY_MISMATCH")

        context_ref = f"context-manifest:{manifest.context_manifest_id}:{manifest.fingerprint}"
        return self.derive(context_refs=(context_ref,))


class TaskContextBuilder:
    """Compose TaskContext from canonical WorkSpace primitives.

    Caller-supplied actor/session/trace/project values are expected to come from
    trusted runtime state. User/model text cannot alter TaskContract authority.
    """

    @staticmethod
    def build(
        *,
        task_contract: TaskContract,
        canonical_task: CanonicalTaskSpec,
        session_id: str,
        trace_id: str,
        actor_id: str,
        purpose: str,
        project_id: str | None = None,
        inventory_scope: Iterable[str] = (),
        created_at: datetime | None = None,
        deadline: datetime | None = None,
        cost_usd: float | None = None,
    ) -> TaskContext:
        task_contract.validate()
        if not isinstance(canonical_task, CanonicalTaskSpec):
            raise TaskContextError("INVALID_CANONICAL_TASK")
        try:
            canonical_task.assert_authority_binding(task_contract)
        except HarnessTaskCompilationError as exc:
            raise TaskContextError(str(exc)) from exc

        authority = TaskCapabilityAuthority.from_contract(task_contract)
        if canonical_task.task_id != task_contract.task_id:
            raise TaskContextError("TASK_CONTEXT_CANONICAL_TASK_ID_MISMATCH")
        if canonical_task.authority_fingerprint != authority.fingerprint:
            raise TaskContextError("TASK_CONTEXT_AUTHORITY_BINDING_MISMATCH")

        created = created_at or datetime.now(timezone.utc)
        context = TaskContext(
            task_id=task_contract.task_id,
            session_id=_compact_id(session_id, "session_id"),
            trace_id=_compact_id(trace_id, "trace_id"),
            actor_id=_compact_id(actor_id, "actor_id"),
            intent=canonical_task.compiled_intent,
            purpose=_single_line(purpose, "purpose", max_len=512),
            project_id=_compact_id(project_id, "project_id") if project_id is not None else None,
            risk_class=_RISK_CLASS_BY_LEVEL[task_contract.risk_level],
            created_at=_iso8601(created),
            deadline=_iso8601(deadline) if deadline is not None else None,
            resource_budget=TaskResourceBudget.from_contract(task_contract, cost_usd=cost_usd),
            inventory_scope=_normalize_refs(inventory_scope, "inventory_scope"),
            task_contract_fingerprint=_digest(task_contract.to_dict()),
            canonical_task_fingerprint=canonical_task.fingerprint,
            authority_fingerprint=authority.fingerprint,
        )
        return context.validate()
