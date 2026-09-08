from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from .resource_events import ResourceEventRecorder
from .runtime_capability_boundary import require_runtime_capability
from .runtime_execution_plan import ExecutionNode

RUNTIME_REVIEWED_STAGING_SCHEMA = "workspace-runtime-reviewed-staging/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_MAX_CONTENT_BYTES = 16 * 1024 * 1024


class ReviewedStagingError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class StagingContentSource(Protocol):
    def resolve_content(
        self,
        *,
        task_id: str,
        content_ref: str,
        max_bytes: int,
    ) -> bytes: ...


class StagingEvidenceSink(Protocol):
    def persist_staged_write(
        self,
        *,
        task_id: str,
        node_id: str,
        resource_sha256: str,
        content_ref_sha256: str,
        content_sha256: str,
        bytes_written: int,
        created: bool,
    ) -> tuple[str, ...]: ...


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _validate_digest(value: str) -> str:
    digest = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(digest):
        raise ReviewedStagingError("STAGING_CONTENT_DIGEST_INVALID")
    return digest


def _validate_content_ref(value: str) -> str:
    ref = str(value or "").strip()
    if not ref or not _REF_RE.fullmatch(ref) or "://" in ref:
        raise ReviewedStagingError("STAGING_CONTENT_REF_INVALID")
    return ref


def _validate_evidence_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    refs: list[str] = []
    for value in values:
        ref = str(value).strip()
        if not ref or not _EVIDENCE_RE.fullmatch(ref) or "://" in ref:
            raise ReviewedStagingError("STAGING_EVIDENCE_REF_INVALID")
        if ref not in refs:
            refs.append(ref)
        if len(refs) > 32:
            raise ReviewedStagingError("STAGING_EVIDENCE_REF_LIMIT_EXCEEDED")
    if not refs:
        raise ReviewedStagingError("STAGING_EVIDENCE_REQUIRED")
    return tuple(refs)


def _safe_relative_resource(resource_ref: str) -> PurePosixPath:
    raw = str(resource_ref or "").strip().replace("\\", "/")
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts:
        raise ReviewedStagingError("STAGING_PATH_INVALID")
    parts = tuple(part for part in path.parts if part not in {"", "."})
    if not parts or any(":" in part for part in parts):
        # Colons are rejected here even though compact authority identifiers allow
        # them: on Windows they can denote drive or alternate-data-stream syntax.
        raise ReviewedStagingError("STAGING_PATH_INVALID")
    return PurePosixPath(*parts)


@dataclass(frozen=True)
class ReviewedStagingResult:
    resource_sha256: str
    content_ref_sha256: str
    content_sha256: str
    bytes_written: int
    created: bool
    evidence_refs: tuple[str, ...]
    schema_version: str = RUNTIME_REVIEWED_STAGING_SCHEMA

    def validate(self) -> "ReviewedStagingResult":
        for digest in (
            self.resource_sha256,
            self.content_ref_sha256,
            self.content_sha256,
        ):
            if not _SHA256_RE.fullmatch(str(digest)):
                raise ReviewedStagingError("STAGING_RESULT_DIGEST_INVALID")
        if (
            isinstance(self.bytes_written, bool)
            or not isinstance(self.bytes_written, int)
            or not 0 <= self.bytes_written <= _MAX_CONTENT_BYTES
        ):
            raise ReviewedStagingError("STAGING_RESULT_SIZE_INVALID")
        if not isinstance(self.created, bool):
            raise ReviewedStagingError("STAGING_RESULT_CREATED_INVALID")
        _validate_evidence_refs(tuple(self.evidence_refs))
        return self


class ReviewedStagingBoundary:
    """Materialize trusted referenced bytes into one authority-bounded staging path.

    Planner input carries only a compact content reference and digest. The target
    path comes exclusively from the already-admitted execution node. The boundary
    never spawns processes or performs network I/O, rejects symlink/path escape,
    never overwrites conflicting content, and rolls back a newly created file when
    durable evidence cannot be recorded.
    """

    def __init__(
        self,
        *,
        staging_root: Path,
        content_source: StagingContentSource,
        evidence_sink: StagingEvidenceSink,
        recorder: ResourceEventRecorder | None = None,
        max_content_bytes: int = _MAX_CONTENT_BYTES,
    ):
        root = Path(staging_root)
        if root.is_symlink() or not root.exists() or not root.is_dir():
            raise ReviewedStagingError("STAGING_ROOT_INVALID")
        resolved_root = root.resolve(strict=True)
        if not callable(getattr(content_source, "resolve_content", None)):
            raise ReviewedStagingError("STAGING_CONTENT_SOURCE_INVALID")
        if not callable(getattr(evidence_sink, "persist_staged_write", None)):
            raise ReviewedStagingError("STAGING_EVIDENCE_SINK_INVALID")
        if (
            isinstance(max_content_bytes, bool)
            or not isinstance(max_content_bytes, int)
            or not 1 <= max_content_bytes <= _MAX_CONTENT_BYTES
        ):
            raise ReviewedStagingError("STAGING_CONTENT_LIMIT_INVALID")
        self.staging_root = resolved_root
        self.content_source = content_source
        self.evidence_sink = evidence_sink
        self.recorder = recorder
        self.max_content_bytes = max_content_bytes

    def _target(self, resource_ref: str) -> Path:
        relative = _safe_relative_resource(resource_ref)
        cursor = self.staging_root
        for part in relative.parts[:-1]:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ReviewedStagingError("STAGING_SYMLINK_DENIED")
        parent = self.staging_root.joinpath(*relative.parts[:-1])
        if not parent.exists() or not parent.is_dir():
            raise ReviewedStagingError("STAGING_PARENT_REQUIRED")
        if parent.is_symlink():
            raise ReviewedStagingError("STAGING_SYMLINK_DENIED")
        try:
            parent.resolve(strict=True).relative_to(self.staging_root)
        except (OSError, ValueError) as exc:
            raise ReviewedStagingError("STAGING_PATH_ESCAPE_DENIED") from exc
        target = self.staging_root.joinpath(*relative.parts)
        if target.is_symlink():
            raise ReviewedStagingError("STAGING_SYMLINK_DENIED")
        return target

    def _rollback_created(self, target: Path) -> None:
        try:
            target.unlink()
        except OSError as exc:
            raise ReviewedStagingError("STAGING_ROLLBACK_FAILED") from exc

    def materialize(
        self,
        *,
        task_id: str,
        node: ExecutionNode,
        content_ref: str,
        content_sha256: str,
    ) -> ReviewedStagingResult:
        if (
            node.capability != "write_staging"
            or node.effect != "write"
            or node.resource_kind != "path"
        ):
            raise ReviewedStagingError("STAGING_NODE_UNSUPPORTED")

        ref = _validate_content_ref(content_ref)
        expected_sha = _validate_digest(content_sha256)
        target = self._target(node.resource_ref)

        require_runtime_capability(
            node.capability,
            task_id=task_id,
            resource_kind=node.resource_kind,
            resource_ref=node.resource_ref,
            effect=node.effect,
            recorder=self.recorder,
            actor_id="runtime_node",
            action="reviewed_staging_materialize",
        )

        try:
            content = self.content_source.resolve_content(
                task_id=task_id,
                content_ref=ref,
                max_bytes=self.max_content_bytes,
            )
        except ReviewedStagingError:
            raise
        except Exception as exc:
            raise ReviewedStagingError("STAGING_CONTENT_RESOLUTION_FAILED") from exc
        if not isinstance(content, bytes):
            raise ReviewedStagingError("STAGING_CONTENT_TYPE_INVALID")
        if len(content) > self.max_content_bytes:
            raise ReviewedStagingError("STAGING_CONTENT_LIMIT_EXCEEDED")
        if _sha256_bytes(content) != expected_sha:
            raise ReviewedStagingError("STAGING_CONTENT_DIGEST_MISMATCH")

        created = False
        if target.exists():
            if not target.is_file():
                raise ReviewedStagingError("STAGING_TARGET_CONFLICT")
            try:
                if target.stat().st_size > self.max_content_bytes:
                    raise ReviewedStagingError("STAGING_TARGET_CONFLICT")
                existing = target.read_bytes()
            except ReviewedStagingError:
                raise
            except OSError as exc:
                raise ReviewedStagingError("STAGING_TARGET_READ_FAILED") from exc
            if _sha256_bytes(existing) != expected_sha:
                raise ReviewedStagingError("STAGING_TARGET_CONFLICT")
        else:
            try:
                with target.open("xb") as handle:
                    handle.write(content)
                    handle.flush()
                    os.fsync(handle.fileno())
                created = True
            except FileExistsError as exc:
                raise ReviewedStagingError("STAGING_TARGET_CONFLICT") from exc
            except OSError as exc:
                raise ReviewedStagingError("STAGING_WRITE_FAILED") from exc

        resource_sha = _sha256_text(node.resource_ref)
        ref_sha = _sha256_text(ref)
        try:
            refs = _validate_evidence_refs(
                tuple(
                    self.evidence_sink.persist_staged_write(
                        task_id=task_id,
                        node_id=node.node_id,
                        resource_sha256=resource_sha,
                        content_ref_sha256=ref_sha,
                        content_sha256=expected_sha,
                        bytes_written=len(content),
                        created=created,
                    )
                )
            )
        except Exception as exc:
            if created:
                self._rollback_created(target)
            if isinstance(exc, ReviewedStagingError):
                raise
            raise ReviewedStagingError("STAGING_EVIDENCE_WRITE_FAILED") from exc

        return ReviewedStagingResult(
            resource_sha256=resource_sha,
            content_ref_sha256=ref_sha,
            content_sha256=expected_sha,
            bytes_written=len(content),
            created=created,
            evidence_refs=refs,
        ).validate()
