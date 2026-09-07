from __future__ import annotations

import hashlib
import os
import re
import stat
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Protocol

from .capability_registry import CapabilityRegistry
from .inference_scope import current_capability_authority
from .resource_events import ResourceEventRecorder
from .runtime_capability_boundary import require_runtime_capability
from .runtime_execution_plan import ExecutionNode
from .runtime_plan_compiler import CompiledRuntimePlan
from .runtime_source_authority import (
    ReviewedSourceBinding,
    RuntimeSourceAuthorityDenied,
    RuntimeSourceBindingBundle,
)
from .task_contract import TaskContract

RUNTIME_REVIEWED_READ_SCHEMA = "workspace-runtime-reviewed-read/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_DEFAULT_MAX_BYTES = 1024 * 1024
_HARD_MAX_BYTES = 16 * 1024 * 1024


class ReviewedReadError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class FileReadEvidenceSink(Protocol):
    """Durably persist bounded file-read evidence and return compact references."""

    def persist_file_read(
        self,
        *,
        task_id: str,
        node_id: str,
        source_class: str,
        resource_ref: str,
        content: bytes,
        content_sha256: str,
    ) -> tuple[str, ...]: ...


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _safe_relative_parts(resource_ref: str) -> tuple[str, ...]:
    text = str(resource_ref or "").strip().replace("\\", "/")
    path = PurePosixPath(text)
    if not text or path.is_absolute() or not path.parts:
        raise RuntimeSourceAuthorityDenied("SOURCE_RESOURCE_PATH_INVALID")
    parts = tuple(path.parts)
    if any(part in {"", ".", ".."} for part in parts):
        raise RuntimeSourceAuthorityDenied("SOURCE_RESOURCE_PATH_ESCAPES_ROOT")
    return parts


def _secure_open_supported() -> bool:
    return (
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in getattr(os, "supports_dir_fd", set())
    )


def _read_regular_file_nofollow(
    binding: ReviewedSourceBinding,
    *,
    max_bytes: int,
) -> bytes:
    root = binding.local_root
    if root is None:
        raise RuntimeSourceAuthorityDenied("SOURCE_LOCAL_ROOT_REQUIRED")
    if not _secure_open_supported():
        raise ReviewedReadError("REVIEWED_READ_SECURE_OPEN_UNAVAILABLE")
    parts = _safe_relative_parts(binding.resource_ref)
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    file_flags = os.O_RDONLY | os.O_NOFOLLOW
    opened: list[int] = []
    file_fd: int | None = None
    try:
        root_fd = os.open(root, directory_flags)
        opened.append(root_fd)
        current_fd = root_fd
        for component in parts[:-1]:
            child_fd = os.open(component, directory_flags, dir_fd=current_fd)
            opened.append(child_fd)
            current_fd = child_fd
        file_fd = os.open(parts[-1], file_flags, dir_fd=current_fd)
        info = os.fstat(file_fd)
        if not stat.S_ISREG(info.st_mode):
            raise ReviewedReadError("REVIEWED_READ_REGULAR_FILE_REQUIRED")
        if info.st_size > max_bytes:
            raise ReviewedReadError("REVIEWED_READ_MAX_BYTES_EXCEEDED")

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(file_fd, min(64 * 1024, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise ReviewedReadError("REVIEWED_READ_MAX_BYTES_EXCEEDED")
        return b"".join(chunks)
    except RuntimeSourceAuthorityDenied:
        raise
    except ReviewedReadError:
        raise
    except OSError as exc:
        raise ReviewedReadError("REVIEWED_READ_PATH_UNSAFE_OR_UNAVAILABLE") from exc
    finally:
        if file_fd is not None:
            try:
                os.close(file_fd)
            except OSError:
                pass
        for fd in reversed(opened):
            try:
                os.close(fd)
            except OSError:
                pass


def _validate_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    refs: list[str] = []
    for value in values:
        ref = str(value).strip()
        if not ref or not _EVIDENCE_RE.fullmatch(ref) or "://" in ref:
            raise ReviewedReadError("REVIEWED_READ_EVIDENCE_REF_INVALID")
        if ref not in refs:
            refs.append(ref)
        if len(refs) > 32:
            raise ReviewedReadError("REVIEWED_READ_EVIDENCE_REF_LIMIT_EXCEEDED")
    if not refs:
        raise ReviewedReadError("REVIEWED_READ_EVIDENCE_REQUIRED")
    return tuple(refs)


@dataclass(frozen=True)
class ReviewedFileReadResult:
    content_sha256: str
    content_bytes: int
    evidence_refs: tuple[str, ...]
    source_binding_fingerprint: str
    schema_version: str = RUNTIME_REVIEWED_READ_SCHEMA

    def validate(self) -> "ReviewedFileReadResult":
        if not _SHA256_RE.fullmatch(str(self.content_sha256)):
            raise ReviewedReadError("REVIEWED_READ_CONTENT_DIGEST_INVALID")
        if (
            isinstance(self.content_bytes, bool)
            or not isinstance(self.content_bytes, int)
            or self.content_bytes < 0
            or self.content_bytes > _HARD_MAX_BYTES
        ):
            raise ReviewedReadError("REVIEWED_READ_CONTENT_SIZE_INVALID")
        _validate_refs(tuple(self.evidence_refs))
        if not _SHA256_RE.fullmatch(str(self.source_binding_fingerprint)):
            raise ReviewedReadError("REVIEWED_READ_SOURCE_FINGERPRINT_INVALID")
        return self


class ReviewedReadBoundary:
    """Fail-closed local read boundary bound to runtime-reviewed source authority.

    Source class/root never comes from planner data. The source bundle is validated
    against the immutable plan and TaskContract, live capability revocation is
    checked immediately before I/O, and POSIX openat/O_NOFOLLOW traversal prevents
    symlink components from escaping the reviewed root. Raw content is handed only
    to the injected evidence sink; scheduler observations receive hashes/refs.
    """

    def __init__(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        source_binding_bundle: RuntimeSourceBindingBundle,
        evidence_sink: FileReadEvidenceSink,
        registry: CapabilityRegistry | None = None,
        recorder: ResourceEventRecorder | None = None,
        hard_max_bytes: int = _HARD_MAX_BYTES,
    ):
        active_registry = registry or CapabilityRegistry.default()
        source_binding_bundle.validate(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
            registry=active_registry,
        )
        if evidence_sink is None or not callable(
            getattr(evidence_sink, "persist_file_read", None)
        ):
            raise ReviewedReadError("FILE_READ_EVIDENCE_SINK_REQUIRED")
        if (
            isinstance(hard_max_bytes, bool)
            or not isinstance(hard_max_bytes, int)
            or not 1 <= hard_max_bytes <= _HARD_MAX_BYTES
        ):
            raise ReviewedReadError("REVIEWED_READ_HARD_MAX_INVALID")
        self.compiled_plan = compiled_plan
        self.task_contract = task_contract
        self.source_binding_bundle = source_binding_bundle
        self.registry = active_registry
        self.evidence_sink = evidence_sink
        self.recorder = recorder
        self.hard_max_bytes = hard_max_bytes

    def read_file(
        self,
        *,
        task_id: str,
        node: ExecutionNode,
        max_bytes: int = _DEFAULT_MAX_BYTES,
    ) -> ReviewedFileReadResult:
        if node.capability != "read_file" or node.effect != "read" or node.resource_kind != "path":
            raise ReviewedReadError("REVIEWED_READ_NODE_UNSUPPORTED")
        if task_id != self.task_contract.task_id:
            raise ReviewedReadError("REVIEWED_READ_TASK_MISMATCH")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 1 <= max_bytes <= self.hard_max_bytes
        ):
            raise ReviewedReadError("REVIEWED_READ_MAX_BYTES_INVALID")

        binding = self.source_binding_bundle.for_node(node.node_id)
        binding.validate(
            compiled_plan=self.compiled_plan,
            task_contract=self.task_contract,
            registry=self.registry,
        )
        if (
            binding.capability != node.capability
            or binding.resource_kind != node.resource_kind
            or binding.resource_ref != node.resource_ref
        ):
            raise RuntimeSourceAuthorityDenied("SOURCE_NODE_BINDING_MISMATCH")

        authority = current_capability_authority()
        if authority is None:
            raise ReviewedReadError("REVIEWED_READ_NODE_AUTHORITY_REQUIRED")
        if binding.source_class not in authority.allowed_sources:
            raise RuntimeSourceAuthorityDenied("SOURCE_CLASS_NOT_ALLOWED")
        if authority.network_scope != "deny" or authority.write_scope != "none":
            raise ReviewedReadError("REVIEWED_READ_SCOPE_NOT_ISOLATED")

        # Authorization/revocation/budget charge happens before opening the file.
        require_runtime_capability(
            node.capability,
            task_id=task_id,
            resource_kind=node.resource_kind,
            resource_ref=node.resource_ref,
            effect=node.effect,
            recorder=self.recorder,
            actor_id="runtime_node",
            action="reviewed_file_read",
        )
        content = _read_regular_file_nofollow(binding, max_bytes=max_bytes)
        content_sha = _sha256(content)
        refs = self.evidence_sink.persist_file_read(
            task_id=task_id,
            node_id=node.node_id,
            source_class=binding.source_class,
            resource_ref=binding.resource_ref,
            content=content,
            content_sha256=content_sha,
        )
        result = ReviewedFileReadResult(
            content_sha256=content_sha,
            content_bytes=len(content),
            evidence_refs=_validate_refs(tuple(refs)),
            source_binding_fingerprint=binding.fingerprint,
        )
        return result.validate()
