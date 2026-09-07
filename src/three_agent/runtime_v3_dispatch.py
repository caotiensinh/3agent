from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Protocol

RUNTIME_V3_DISPATCH_DESCRIPTOR_SCHEMA = "workspace-runtime-v3-dispatch-descriptor/v1"
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class RuntimeV3DispatchError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _canonical_sha256(payload: object) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _compact(value: object, field: str) -> str:
    text = str(value or "").strip()
    if not text or not _COMPACT_RE.fullmatch(text) or "://" in text:
        raise RuntimeV3DispatchError(f"RUNTIME_V3_{field.upper()}_INVALID")
    return text


def _digest(value: object, field: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise RuntimeV3DispatchError(f"RUNTIME_V3_{field.upper()}_INVALID")
    return text


@dataclass(frozen=True)
class RuntimeV3DispatchDescriptor:
    """Durable, content-free description of one reviewed Runtime V3 package.

    The workflow dispatcher stores this descriptor instead of serializing planner
    inputs, source roots, SQL, patch bytes, credentials, or live Python objects.
    ``runtime_ref`` is an opaque local identifier owned by the trusted runtime
    executor. The executor must be able to reconstruct the exact package after a
    process restart and must reject semantic drift against these fingerprints.
    """

    task_id: str
    runtime_ref: str
    compiled_plan_fingerprint: str
    invocation_bundle_fingerprint: str
    authority_fingerprint: str
    source_binding_bundle_fingerprint: str | None = None
    query_bundle_fingerprint: str | None = None
    schema_version: str = RUNTIME_V3_DISPATCH_DESCRIPTOR_SCHEMA

    def validate(self) -> "RuntimeV3DispatchDescriptor":
        if self.schema_version != RUNTIME_V3_DISPATCH_DESCRIPTOR_SCHEMA:
            raise RuntimeV3DispatchError("RUNTIME_V3_DESCRIPTOR_SCHEMA_UNSUPPORTED")
        _compact(self.task_id, "task_id")
        _compact(self.runtime_ref, "runtime_ref")
        _digest(self.compiled_plan_fingerprint, "compiled_plan_fingerprint")
        _digest(self.invocation_bundle_fingerprint, "invocation_bundle_fingerprint")
        _digest(self.authority_fingerprint, "authority_fingerprint")
        _digest(
            self.source_binding_bundle_fingerprint,
            "source_binding_bundle_fingerprint",
            optional=True,
        )
        _digest(
            self.query_bundle_fingerprint,
            "query_bundle_fingerprint",
            optional=True,
        )
        return self

    @property
    def fingerprint(self) -> str:
        return _canonical_sha256(self.metadata())

    def metadata(self) -> dict[str, str | None]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "runtime_ref": self.runtime_ref,
            "compiled_plan_fingerprint": self.compiled_plan_fingerprint,
            "invocation_bundle_fingerprint": self.invocation_bundle_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
            "source_binding_bundle_fingerprint": self.source_binding_bundle_fingerprint,
            "query_bundle_fingerprint": self.query_bundle_fingerprint,
        }


class RuntimeV3DispatchExecutor(Protocol):
    """Trusted durable executor exposed to Workflow Dispatch.

    Implementations own package persistence/reconstruction. They must validate the
    descriptor again at execute time and must never treat dispatcher authorization
    as permission to widen task/runtime authority.
    """

    def describe(self, runtime_ref: str) -> RuntimeV3DispatchDescriptor: ...

    def execute(
        self,
        runtime_ref: str,
        *,
        expected_descriptor_fingerprint: str,
        approval_fingerprint: str,
        approver_ref: str,
    ) -> Any: ...


def validate_runtime_v3_executor(executor: object) -> RuntimeV3DispatchExecutor:
    if executor is None:
        raise RuntimeV3DispatchError("RUNTIME_V3_EXECUTOR_REQUIRED")
    if not callable(getattr(executor, "describe", None)):
        raise RuntimeV3DispatchError("RUNTIME_V3_EXECUTOR_DESCRIBE_REQUIRED")
    if not callable(getattr(executor, "execute", None)):
        raise RuntimeV3DispatchError("RUNTIME_V3_EXECUTOR_EXECUTE_REQUIRED")
    return executor  # type: ignore[return-value]
