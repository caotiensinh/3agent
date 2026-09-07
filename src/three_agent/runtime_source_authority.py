from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .capability_registry import CapabilityRegistry
from .runtime_plan_compiler import CompiledRuntimePlan
from .task_contract import TaskContract

RUNTIME_SOURCE_BINDING_SCHEMA = "workspace-runtime-source-binding/v1"
RUNTIME_SOURCE_BINDING_BUNDLE_SCHEMA = "workspace-runtime-source-binding-bundle/v1"
SOURCE_SCOPED_CAPABILITIES = frozenset(
    {"read_file", "search_repo", "search_docs", "query_db_readonly"}
)
_LOCAL_ROOT_REQUIRED = frozenset({"read_file", "search_repo"})
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")


class RuntimeSourceAuthorityDenied(RuntimeError):
    """A production source binding would exceed the task's reviewed source scope."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _compact(value: object, field: str) -> str:
    text = str(value or "").strip()
    if not text or not _COMPACT_RE.fullmatch(text) or "://" in text:
        raise RuntimeSourceAuthorityDenied(f"SOURCE_{field.upper()}_INVALID")
    return text


def _canonical_sha256(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _normalized_root(value: str | Path | None) -> Path | None:
    if value is None:
        return None
    root = Path(value).expanduser().resolve()
    if not root.is_dir():
        raise RuntimeSourceAuthorityDenied("SOURCE_LOCAL_ROOT_NOT_DIRECTORY")
    return root


def _assert_relative_target_within(root: Path, resource_ref: str) -> None:
    candidate = Path(resource_ref)
    if candidate.is_absolute():
        raise RuntimeSourceAuthorityDenied("SOURCE_RESOURCE_PATH_ABSOLUTE_DENIED")
    try:
        resolved = (root / candidate).resolve()
        common = Path(os.path.commonpath((str(root), str(resolved))))
    except (OSError, ValueError) as exc:
        raise RuntimeSourceAuthorityDenied("SOURCE_RESOURCE_PATH_INVALID") from exc
    if common != root:
        raise RuntimeSourceAuthorityDenied("SOURCE_RESOURCE_PATH_ESCAPES_ROOT")


@dataclass(frozen=True)
class ReviewedSourceBinding:
    """Runtime-owned binding between one plan node and one reviewed source.

    The planner owns neither ``source_class`` nor ``local_root``. A runtime/operator
    supplies this binding after plan compilation. Exact node resource binding plus
    root confinement prevents an allowed source class such as ``repo`` from being
    used as a label to access arbitrary local resources.
    """

    task_id: str
    plan_id: str
    plan_fingerprint: str
    compiled_plan_fingerprint: str
    node_id: str
    capability: str
    source_class: str
    resource_kind: str
    resource_ref: str
    local_root_sha256: str | None
    _local_root: str | None
    schema_version: str = RUNTIME_SOURCE_BINDING_SCHEMA

    @classmethod
    def bind(
        cls,
        *,
        compiled_plan: CompiledRuntimePlan,
        node_id: str,
        source_class: str,
        local_root: str | Path | None = None,
    ) -> "ReviewedSourceBinding":
        key = str(node_id).strip()
        by_id = {node.node_id: node for node in compiled_plan.plan.nodes}
        try:
            node = by_id[key]
        except KeyError as exc:
            raise RuntimeSourceAuthorityDenied("SOURCE_NODE_NOT_IN_PLAN") from exc
        if node.capability not in SOURCE_SCOPED_CAPABILITIES:
            raise RuntimeSourceAuthorityDenied("SOURCE_CAPABILITY_NOT_SCOPED")

        source = _compact(source_class, "class")
        root = _normalized_root(local_root)
        if node.capability in _LOCAL_ROOT_REQUIRED and root is None:
            raise RuntimeSourceAuthorityDenied("SOURCE_LOCAL_ROOT_REQUIRED")
        if node.capability == "read_file" and root is not None:
            _assert_relative_target_within(root, node.resource_ref)

        root_text = str(root) if root is not None else None
        root_sha = (
            _canonical_sha256({"local_root": root_text})
            if root_text is not None
            else None
        )
        return cls(
            task_id=compiled_plan.plan.task_id,
            plan_id=compiled_plan.plan.plan_id,
            plan_fingerprint=compiled_plan.plan.fingerprint,
            compiled_plan_fingerprint=compiled_plan.fingerprint,
            node_id=node.node_id,
            capability=node.capability,
            source_class=source,
            resource_kind=node.resource_kind,
            resource_ref=node.resource_ref,
            local_root_sha256=root_sha,
            _local_root=root_text,
        )

    @property
    def local_root(self) -> Path | None:
        return Path(self._local_root) if self._local_root is not None else None

    @property
    def fingerprint(self) -> str:
        return _canonical_sha256(self.metadata())

    def validate(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        registry: CapabilityRegistry | None = None,
    ) -> "ReviewedSourceBinding":
        active_registry = registry or CapabilityRegistry.default()
        compiled_plan.validate_current(
            task_contract=task_contract,
            registry=active_registry,
        )
        checks = (
            (
                self.schema_version == RUNTIME_SOURCE_BINDING_SCHEMA,
                "SOURCE_BINDING_SCHEMA_UNSUPPORTED",
            ),
            (self.task_id == task_contract.task_id, "SOURCE_BINDING_TASK_MISMATCH"),
            (
                self.plan_id == compiled_plan.plan.plan_id,
                "SOURCE_BINDING_PLAN_ID_MISMATCH",
            ),
            (
                self.plan_fingerprint == compiled_plan.plan.fingerprint,
                "SOURCE_BINDING_PLAN_CHANGED",
            ),
            (
                self.compiled_plan_fingerprint == compiled_plan.fingerprint,
                "SOURCE_BINDING_COMPILED_PLAN_CHANGED",
            ),
        )
        for valid, code in checks:
            if not valid:
                raise RuntimeSourceAuthorityDenied(code)

        if self.source_class not in task_contract.allowed_sources:
            raise RuntimeSourceAuthorityDenied("SOURCE_CLASS_NOT_ALLOWED")

        by_id = {node.node_id: node for node in compiled_plan.plan.nodes}
        try:
            node = by_id[self.node_id]
        except KeyError as exc:
            raise RuntimeSourceAuthorityDenied("SOURCE_NODE_NOT_IN_PLAN") from exc
        if (
            node.capability != self.capability
            or node.resource_kind != self.resource_kind
            or node.resource_ref != self.resource_ref
        ):
            raise RuntimeSourceAuthorityDenied("SOURCE_NODE_BINDING_MISMATCH")
        if self.capability not in SOURCE_SCOPED_CAPABILITIES:
            raise RuntimeSourceAuthorityDenied("SOURCE_CAPABILITY_NOT_SCOPED")

        root = self.local_root
        if self.capability in _LOCAL_ROOT_REQUIRED and root is None:
            raise RuntimeSourceAuthorityDenied("SOURCE_LOCAL_ROOT_REQUIRED")
        if root is not None:
            normalized = _normalized_root(root)
            expected_sha = _canonical_sha256({"local_root": str(normalized)})
            if expected_sha != self.local_root_sha256:
                raise RuntimeSourceAuthorityDenied("SOURCE_LOCAL_ROOT_CHANGED")
            if self.capability == "read_file":
                _assert_relative_target_within(normalized, self.resource_ref)
        return self

    def metadata(self) -> dict[str, str | None]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "plan_fingerprint": self.plan_fingerprint,
            "compiled_plan_fingerprint": self.compiled_plan_fingerprint,
            "node_id": self.node_id,
            "capability": self.capability,
            "source_class": self.source_class,
            "resource_kind": self.resource_kind,
            "resource_ref": self.resource_ref,
            "local_root_sha256": self.local_root_sha256,
        }


@dataclass(frozen=True)
class RuntimeSourceBindingBundle:
    task_id: str
    plan_id: str
    plan_fingerprint: str
    compiled_plan_fingerprint: str
    bindings: tuple[ReviewedSourceBinding, ...]
    schema_version: str = RUNTIME_SOURCE_BINDING_BUNDLE_SCHEMA

    @classmethod
    def compile(
        cls,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        bindings: Iterable[ReviewedSourceBinding],
        registry: CapabilityRegistry | None = None,
    ) -> "RuntimeSourceBindingBundle":
        bundle = cls(
            task_id=compiled_plan.plan.task_id,
            plan_id=compiled_plan.plan.plan_id,
            plan_fingerprint=compiled_plan.plan.fingerprint,
            compiled_plan_fingerprint=compiled_plan.fingerprint,
            bindings=tuple(bindings),
        )
        return bundle.validate(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
            registry=registry,
        )

    @property
    def fingerprint(self) -> str:
        return _canonical_sha256(self.metadata())

    def for_node(self, node_id: str) -> ReviewedSourceBinding:
        key = str(node_id).strip()
        for binding in self.bindings:
            if binding.node_id == key:
                return binding
        raise RuntimeSourceAuthorityDenied("SOURCE_NODE_NOT_IN_BUNDLE")

    def validate(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        registry: CapabilityRegistry | None = None,
    ) -> "RuntimeSourceBindingBundle":
        active_registry = registry or CapabilityRegistry.default()
        compiled_plan.validate_current(
            task_contract=task_contract,
            registry=active_registry,
        )
        checks = (
            (
                self.schema_version == RUNTIME_SOURCE_BINDING_BUNDLE_SCHEMA,
                "SOURCE_BINDING_BUNDLE_SCHEMA_UNSUPPORTED",
            ),
            (
                self.task_id == task_contract.task_id,
                "SOURCE_BINDING_BUNDLE_TASK_MISMATCH",
            ),
            (
                self.plan_id == compiled_plan.plan.plan_id,
                "SOURCE_BINDING_BUNDLE_PLAN_ID_MISMATCH",
            ),
            (
                self.plan_fingerprint == compiled_plan.plan.fingerprint,
                "SOURCE_BINDING_BUNDLE_PLAN_CHANGED",
            ),
            (
                self.compiled_plan_fingerprint == compiled_plan.fingerprint,
                "SOURCE_BINDING_BUNDLE_COMPILED_PLAN_CHANGED",
            ),
        )
        for valid, code in checks:
            if not valid:
                raise RuntimeSourceAuthorityDenied(code)

        expected = {
            node.node_id
            for node in compiled_plan.plan.nodes
            if node.capability in SOURCE_SCOPED_CAPABILITIES
        }
        actual = [binding.node_id for binding in self.bindings]
        if len(actual) != len(set(actual)):
            raise RuntimeSourceAuthorityDenied("SOURCE_BINDING_BUNDLE_DUPLICATE_NODE")
        if set(actual) != expected:
            raise RuntimeSourceAuthorityDenied(
                "SOURCE_BINDING_BUNDLE_NODE_COVERAGE_MISMATCH"
            )

        for binding in self.bindings:
            binding.validate(
                compiled_plan=compiled_plan,
                task_contract=task_contract,
                registry=active_registry,
            )
        return self

    def metadata(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "plan_fingerprint": self.plan_fingerprint,
            "compiled_plan_fingerprint": self.compiled_plan_fingerprint,
            "bindings": [
                binding.metadata()
                for binding in sorted(self.bindings, key=lambda item: item.node_id)
            ],
        }
