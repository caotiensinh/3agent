from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from .runtime_plan_compiler import CompiledRuntimePlan

RUNTIME_INVOCATION_SCHEMA = "workspace-runtime-invocation/v1"
RUNTIME_INVOCATION_BUNDLE_SCHEMA = "workspace-runtime-invocation-bundle/v1"
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_FORBIDDEN_KEYS = {
    "argv",
    "args",
    "command",
    "cmd",
    "shell",
    "cwd",
    "callable",
    "function",
    "endpoint",
    "url",
    "headers",
    "method",
    "sql",
    "raw_sql",
    "script",
    "code",
}


class RuntimeInvocationError(ValueError):
    """Planner-supplied invocation data is not safe for reviewed runtime adapters."""


@dataclass(frozen=True)
class _Schema:
    operation: str
    required: frozenset[str]
    optional: frozenset[str]


_SCHEMAS: dict[str, _Schema] = {
    "read_file": _Schema("read", frozenset(), frozenset({"max_bytes"})),
    "search_repo": _Schema("search", frozenset({"query"}), frozenset({"max_results"})),
    "search_docs": _Schema("search", frozenset({"query"}), frozenset({"max_results"})),
    "query_db_readonly": _Schema(
        "query",
        frozenset({"query_ref"}),
        frozenset({"parameters_ref"}),
    ),
    "calculator": _Schema("evaluate", frozenset({"expression"}), frozenset()),
    "run_linter": _Schema("run", frozenset(), frozenset({"profile"})),
    "run_tests": _Schema("run", frozenset(), frozenset({"suite"})),
    "write_staging": _Schema(
        "materialize",
        frozenset({"content_ref", "content_sha256"}),
        frozenset(),
    ),
    "apply_patch": _Schema(
        "apply",
        frozenset({"patch_ref", "patch_sha256"}),
        frozenset(),
    ),
    "web_gateway": _Schema("search", frozenset({"query"}), frozenset({"count"})),
}


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _compact(value: Any, field: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if (
        not text
        or len(text) > max_len
        or not _COMPACT_RE.fullmatch(text)
        or "://" in text
    ):
        raise RuntimeInvocationError(f"{field} must be a compact non-URL identifier")
    return text


def _bounded_text(value: Any, field: str, *, max_len: int = 2048) -> str:
    if not isinstance(value, str):
        raise RuntimeInvocationError(f"{field} must be text")
    text = value.strip()
    if not text or len(text) > max_len or "\x00" in text:
        raise RuntimeInvocationError(f"{field} is empty or exceeds its safety bound")
    return text


def _bounded_int(value: Any, field: str, *, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RuntimeInvocationError(f"{field} must be an integer within [{minimum},{maximum}]")
    return value


def _digest(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise RuntimeInvocationError(f"{field} must be a sha256 digest")
    return text


def _validate_arguments(
    capability: str,
    operation: str,
    arguments: Mapping[str, Any],
) -> tuple[tuple[str, str | int | bool], ...]:
    try:
        schema = _SCHEMAS[capability]
    except KeyError as exc:
        raise RuntimeInvocationError(
            f"TYPED_INVOCATION_CAPABILITY_UNSUPPORTED:{capability}"
        ) from exc
    if operation != schema.operation:
        raise RuntimeInvocationError(f"TYPED_INVOCATION_OPERATION_INVALID:{capability}")
    if not isinstance(arguments, Mapping):
        raise RuntimeInvocationError("TYPED_INVOCATION_ARGUMENTS_MUST_BE_MAPPING")

    normalized_keys: dict[str, str] = {}
    for raw_key in arguments:
        if not isinstance(raw_key, str):
            raise RuntimeInvocationError("TYPED_INVOCATION_ARGUMENT_KEY_TYPE_INVALID")
        key = raw_key.strip()
        if not key:
            raise RuntimeInvocationError("TYPED_INVOCATION_ARGUMENT_KEY_INVALID")
        if key in normalized_keys:
            raise RuntimeInvocationError("TYPED_INVOCATION_ARGUMENT_KEY_COLLISION")
        normalized_keys[key] = raw_key
    keys = set(normalized_keys)

    forbidden = keys & _FORBIDDEN_KEYS
    if forbidden:
        raise RuntimeInvocationError(
            "TYPED_INVOCATION_RAW_EXECUTION_FIELD_DENIED:" + ",".join(sorted(forbidden))
        )
    allowed = schema.required | schema.optional
    if not schema.required.issubset(keys):
        missing = sorted(schema.required - keys)
        raise RuntimeInvocationError(
            "TYPED_INVOCATION_REQUIRED_ARGUMENT_MISSING:" + ",".join(missing)
        )
    if not keys.issubset(allowed):
        extra = sorted(keys - allowed)
        raise RuntimeInvocationError(
            "TYPED_INVOCATION_ARGUMENT_NOT_ALLOWED:" + ",".join(extra)
        )

    normalized: dict[str, str | int | bool] = {}
    for key in sorted(keys):
        value = arguments[normalized_keys[key]]
        if key == "max_bytes":
            normalized[key] = _bounded_int(
                value,
                key,
                minimum=1,
                maximum=16 * 1024 * 1024,
            )
        elif key == "max_results":
            normalized[key] = _bounded_int(value, key, minimum=1, maximum=100)
        elif key == "count":
            normalized[key] = _bounded_int(value, key, minimum=1, maximum=20)
        elif key in {"query", "expression"}:
            normalized[key] = _bounded_text(value, key)
        elif key in {
            "query_ref",
            "parameters_ref",
            "profile",
            "suite",
            "content_ref",
            "patch_ref",
        }:
            normalized[key] = _compact(value, key)
        elif key in {"content_sha256", "patch_sha256"}:
            normalized[key] = _digest(value, key)
        else:
            raise RuntimeInvocationError(
                f"TYPED_INVOCATION_ARGUMENT_VALIDATOR_MISSING:{key}"
            )
    return tuple((key, normalized[key]) for key in sorted(normalized))


@dataclass(frozen=True)
class TypedCapabilityInvocation:
    task_id: str
    plan_id: str
    plan_fingerprint: str
    compiled_plan_fingerprint: str
    node_id: str
    capability: str
    resource_kind: str
    resource_ref: str
    effect: str
    operation: str
    arguments: tuple[tuple[str, str | int | bool], ...]
    schema_version: str = RUNTIME_INVOCATION_SCHEMA

    @classmethod
    def compile(
        cls,
        *,
        compiled_plan: CompiledRuntimePlan,
        node_id: str,
        operation: str,
        arguments: Mapping[str, Any] | None = None,
    ) -> "TypedCapabilityInvocation":
        by_id = {node.node_id: node for node in compiled_plan.plan.nodes}
        key = str(node_id).strip()
        try:
            node = by_id[key]
        except KeyError as exc:
            raise RuntimeInvocationError("TYPED_INVOCATION_NODE_NOT_IN_PLAN") from exc
        op = _compact(operation, "operation", max_len=64)
        normalized = _validate_arguments(node.capability, op, arguments or {})
        return cls(
            task_id=compiled_plan.plan.task_id,
            plan_id=compiled_plan.plan.plan_id,
            plan_fingerprint=compiled_plan.plan.fingerprint,
            compiled_plan_fingerprint=compiled_plan.fingerprint,
            node_id=node.node_id,
            capability=node.capability,
            resource_kind=node.resource_kind,
            resource_ref=node.resource_ref,
            effect=node.effect,
            operation=op,
            arguments=normalized,
        ).validate(compiled_plan)

    def argument_map(self) -> dict[str, str | int | bool]:
        return dict(self.arguments)

    @property
    def fingerprint(self) -> str:
        return _sha(self.to_dict())

    def validate(self, compiled_plan: CompiledRuntimePlan) -> "TypedCapabilityInvocation":
        plan = compiled_plan.plan
        checks = (
            (
                self.schema_version == RUNTIME_INVOCATION_SCHEMA,
                "TYPED_INVOCATION_SCHEMA_UNSUPPORTED",
            ),
            (self.task_id == plan.task_id, "TYPED_INVOCATION_TASK_MISMATCH"),
            (self.plan_id == plan.plan_id, "TYPED_INVOCATION_PLAN_ID_MISMATCH"),
            (
                self.plan_fingerprint == plan.fingerprint,
                "TYPED_INVOCATION_PLAN_CHANGED",
            ),
            (
                self.compiled_plan_fingerprint == compiled_plan.fingerprint,
                "TYPED_INVOCATION_COMPILED_PLAN_CHANGED",
            ),
        )
        for valid, code in checks:
            if not valid:
                raise RuntimeInvocationError(code)
        by_id = {node.node_id: node for node in plan.nodes}
        try:
            node = by_id[self.node_id]
        except KeyError as exc:
            raise RuntimeInvocationError("TYPED_INVOCATION_NODE_NOT_IN_PLAN") from exc
        if (
            self.capability != node.capability
            or self.resource_kind != node.resource_kind
            or self.resource_ref != node.resource_ref
            or self.effect != node.effect
        ):
            raise RuntimeInvocationError("TYPED_INVOCATION_NODE_BINDING_MISMATCH")
        normalized = _validate_arguments(
            self.capability,
            self.operation,
            self.argument_map(),
        )
        if normalized != self.arguments:
            raise RuntimeInvocationError(
                "TYPED_INVOCATION_ARGUMENT_NORMALIZATION_DRIFT"
            )
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "plan_fingerprint": self.plan_fingerprint,
            "compiled_plan_fingerprint": self.compiled_plan_fingerprint,
            "node_id": self.node_id,
            "capability": self.capability,
            "resource_kind": self.resource_kind,
            "resource_ref": self.resource_ref,
            "effect": self.effect,
            "operation": self.operation,
            "arguments": self.argument_map(),
        }


@dataclass(frozen=True)
class RuntimeInvocationBundle:
    task_id: str
    plan_id: str
    plan_fingerprint: str
    compiled_plan_fingerprint: str
    invocations: tuple[TypedCapabilityInvocation, ...]
    schema_version: str = RUNTIME_INVOCATION_BUNDLE_SCHEMA

    @classmethod
    def compile(
        cls,
        *,
        compiled_plan: CompiledRuntimePlan,
        invocations: Iterable[TypedCapabilityInvocation],
    ) -> "RuntimeInvocationBundle":
        bundle = cls(
            task_id=compiled_plan.plan.task_id,
            plan_id=compiled_plan.plan.plan_id,
            plan_fingerprint=compiled_plan.plan.fingerprint,
            compiled_plan_fingerprint=compiled_plan.fingerprint,
            invocations=tuple(invocations),
        )
        return bundle.validate(compiled_plan)

    @property
    def fingerprint(self) -> str:
        return _sha(self.to_dict())

    def for_node(self, node_id: str) -> TypedCapabilityInvocation:
        key = str(node_id).strip()
        for invocation in self.invocations:
            if invocation.node_id == key:
                return invocation
        raise RuntimeInvocationError("TYPED_INVOCATION_NODE_NOT_IN_BUNDLE")

    def validate(self, compiled_plan: CompiledRuntimePlan) -> "RuntimeInvocationBundle":
        plan = compiled_plan.plan
        checks = (
            (
                self.schema_version == RUNTIME_INVOCATION_BUNDLE_SCHEMA,
                "TYPED_INVOCATION_BUNDLE_SCHEMA_UNSUPPORTED",
            ),
            (self.task_id == plan.task_id, "TYPED_INVOCATION_BUNDLE_TASK_MISMATCH"),
            (
                self.plan_id == plan.plan_id,
                "TYPED_INVOCATION_BUNDLE_PLAN_ID_MISMATCH",
            ),
            (
                self.plan_fingerprint == plan.fingerprint,
                "TYPED_INVOCATION_BUNDLE_PLAN_CHANGED",
            ),
            (
                self.compiled_plan_fingerprint == compiled_plan.fingerprint,
                "TYPED_INVOCATION_BUNDLE_COMPILED_PLAN_CHANGED",
            ),
        )
        for valid, code in checks:
            if not valid:
                raise RuntimeInvocationError(code)
        expected = {node.node_id for node in plan.nodes}
        actual = [invocation.node_id for invocation in self.invocations]
        if len(actual) != len(set(actual)):
            raise RuntimeInvocationError("TYPED_INVOCATION_BUNDLE_DUPLICATE_NODE")
        if set(actual) != expected:
            raise RuntimeInvocationError(
                "TYPED_INVOCATION_BUNDLE_NODE_COVERAGE_MISMATCH"
            )
        for invocation in self.invocations:
            invocation.validate(compiled_plan)
        return self

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "plan_fingerprint": self.plan_fingerprint,
            "compiled_plan_fingerprint": self.compiled_plan_fingerprint,
            "invocations": [
                invocation.to_dict()
                for invocation in sorted(
                    self.invocations,
                    key=lambda item: item.node_id,
                )
            ],
        }
