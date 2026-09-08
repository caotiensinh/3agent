from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from .resource_events import ResourceEventRecorder
from .runtime_capability_boundary import require_runtime_capability
from .runtime_execution_plan import ExecutionNode

RUNTIME_REVIEWED_PATCH_SCHEMA = "workspace-runtime-reviewed-patch/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_REF_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_HUNK_RE = re.compile(
    r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?: .*)?$"
)
_MAX_PATCH_BYTES = 4 * 1024 * 1024
_MAX_TARGET_BYTES = 16 * 1024 * 1024
_MAX_HUNKS = 128


class ReviewedPatchError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class PatchContentSource(Protocol):
    def resolve_patch(
        self,
        *,
        task_id: str,
        patch_ref: str,
        max_bytes: int,
    ) -> bytes: ...


class PatchEvidenceSink(Protocol):
    def persist_patch_application(
        self,
        *,
        task_id: str,
        node_id: str,
        resource_sha256: str,
        patch_ref_sha256: str,
        patch_sha256: str,
        before_sha256: str,
        after_sha256: str,
        bytes_written: int,
        hunk_count: int,
    ) -> tuple[str, ...]: ...


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _sha256_text(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _validate_digest(value: str) -> str:
    digest = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(digest):
        raise ReviewedPatchError("PATCH_DIGEST_INVALID")
    return digest


def _validate_patch_ref(value: str) -> str:
    ref = str(value or "").strip()
    if not ref or not _REF_RE.fullmatch(ref) or "://" in ref:
        raise ReviewedPatchError("PATCH_REF_INVALID")
    return ref


def _validate_evidence_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    refs: list[str] = []
    for value in values:
        ref = str(value).strip()
        if not ref or not _EVIDENCE_RE.fullmatch(ref) or "://" in ref:
            raise ReviewedPatchError("PATCH_EVIDENCE_REF_INVALID")
        if ref not in refs:
            refs.append(ref)
        if len(refs) > 32:
            raise ReviewedPatchError("PATCH_EVIDENCE_REF_LIMIT_EXCEEDED")
    if not refs:
        raise ReviewedPatchError("PATCH_EVIDENCE_REQUIRED")
    return tuple(refs)


def _safe_relative_resource(resource_ref: str) -> PurePosixPath:
    raw = str(resource_ref or "").strip().replace("\\", "/")
    path = PurePosixPath(raw)
    if not raw or path.is_absolute() or ".." in path.parts:
        raise ReviewedPatchError("PATCH_PATH_INVALID")
    parts = tuple(part for part in path.parts if part not in {"", "."})
    if not parts or any(":" in part for part in parts):
        raise ReviewedPatchError("PATCH_PATH_INVALID")
    return PurePosixPath(*parts)


def _decode_utf8(data: bytes, reason_code: str) -> str:
    if b"\x00" in data:
        raise ReviewedPatchError(reason_code)
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReviewedPatchError(reason_code) from exc


def _target_newline(data: bytes) -> tuple[str, bool]:
    without_crlf = data.replace(b"\r\n", b"")
    if b"\r" in without_crlf:
        raise ReviewedPatchError("PATCH_TARGET_NEWLINE_UNSUPPORTED")
    newline = "\r\n" if b"\r\n" in data else "\n"
    trailing = data.endswith(b"\r\n") if newline == "\r\n" else data.endswith(b"\n")
    return newline, trailing


@dataclass(frozen=True)
class _AppliedPatch:
    content: bytes
    hunk_count: int


def _apply_unified_diff(
    *,
    original: bytes,
    patch: bytes,
    resource_ref: str,
    max_target_bytes: int,
) -> _AppliedPatch:
    original_text = _decode_utf8(original, "PATCH_TARGET_NOT_UTF8_TEXT")
    patch_text = _decode_utf8(patch, "PATCH_NOT_UTF8_TEXT")
    if "\nGIT binary patch\n" in "\n" + patch_text or "Binary files " in patch_text:
        raise ReviewedPatchError("PATCH_BINARY_DENIED")

    lines = patch_text.splitlines()
    expected_old = f"--- a/{resource_ref}"
    expected_new = f"+++ b/{resource_ref}"
    if len(lines) < 3 or lines[0] != expected_old or lines[1] != expected_new:
        raise ReviewedPatchError("PATCH_TARGET_HEADER_MISMATCH")
    if "/dev/null" in {lines[0][4:] if lines else "", lines[1][4:] if len(lines) > 1 else ""}:
        raise ReviewedPatchError("PATCH_CREATE_DELETE_DENIED")

    newline, trailing_newline = _target_newline(original)
    source_lines = original_text.splitlines()
    output: list[str] = []
    source_cursor = 0
    index = 2
    hunk_count = 0

    while index < len(lines):
        line = lines[index]
        if line.startswith("--- ") or line.startswith("+++ "):
            raise ReviewedPatchError("PATCH_MULTIFILE_DENIED")
        if line == "\\ No newline at end of file":
            raise ReviewedPatchError("PATCH_NO_NEWLINE_MARKER_UNSUPPORTED")
        match = _HUNK_RE.fullmatch(line)
        if match is None:
            raise ReviewedPatchError("PATCH_FORMAT_INVALID")
        hunk_count += 1
        if hunk_count > _MAX_HUNKS:
            raise ReviewedPatchError("PATCH_HUNK_LIMIT_EXCEEDED")

        old_start = int(match.group(1))
        old_count = int(match.group(2) or "1")
        new_start = int(match.group(3))
        new_count = int(match.group(4) or "1")
        old_index = old_start if old_count == 0 else old_start - 1
        new_index = new_start if new_count == 0 else new_start - 1
        if old_index < source_cursor or old_index > len(source_lines):
            raise ReviewedPatchError("PATCH_HUNK_POSITION_INVALID")
        output.extend(source_lines[source_cursor:old_index])
        source_cursor = old_index
        if new_index != len(output):
            raise ReviewedPatchError("PATCH_HUNK_POSITION_INVALID")

        index += 1
        old_seen = 0
        new_seen = 0
        while old_seen < old_count or new_seen < new_count:
            if index >= len(lines):
                raise ReviewedPatchError("PATCH_HUNK_TRUNCATED")
            entry = lines[index]
            if entry == "\\ No newline at end of file":
                raise ReviewedPatchError("PATCH_NO_NEWLINE_MARKER_UNSUPPORTED")
            if entry.startswith("@@ ") or entry.startswith("--- ") or entry.startswith("+++ "):
                raise ReviewedPatchError("PATCH_HUNK_COUNT_MISMATCH")
            if not entry or entry[0] not in {" ", "+", "-"}:
                raise ReviewedPatchError("PATCH_HUNK_LINE_INVALID")
            marker, payload = entry[0], entry[1:]
            if marker in {" ", "-"}:
                if old_seen >= old_count or source_cursor >= len(source_lines):
                    raise ReviewedPatchError("PATCH_HUNK_COUNT_MISMATCH")
                if source_lines[source_cursor] != payload:
                    raise ReviewedPatchError("PATCH_CONTEXT_MISMATCH")
                source_cursor += 1
                old_seen += 1
            if marker in {" ", "+"}:
                if new_seen >= new_count:
                    raise ReviewedPatchError("PATCH_HUNK_COUNT_MISMATCH")
                output.append(payload)
                new_seen += 1
            index += 1
        if old_seen != old_count or new_seen != new_count:
            raise ReviewedPatchError("PATCH_HUNK_COUNT_MISMATCH")

    if hunk_count == 0:
        raise ReviewedPatchError("PATCH_HUNK_REQUIRED")
    output.extend(source_lines[source_cursor:])
    rendered = newline.join(output)
    if trailing_newline:
        rendered += newline
    result = rendered.encode("utf-8")
    if len(result) > max_target_bytes:
        raise ReviewedPatchError("PATCH_RESULT_LIMIT_EXCEEDED")
    if result == original:
        raise ReviewedPatchError("PATCH_NO_CHANGE")
    return _AppliedPatch(result, hunk_count)


@dataclass(frozen=True)
class ReviewedPatchResult:
    resource_sha256: str
    patch_ref_sha256: str
    patch_sha256: str
    before_sha256: str
    after_sha256: str
    bytes_written: int
    hunk_count: int
    evidence_refs: tuple[str, ...]
    schema_version: str = RUNTIME_REVIEWED_PATCH_SCHEMA

    def validate(self) -> "ReviewedPatchResult":
        for digest in (
            self.resource_sha256,
            self.patch_ref_sha256,
            self.patch_sha256,
            self.before_sha256,
            self.after_sha256,
        ):
            if not _SHA256_RE.fullmatch(str(digest)):
                raise ReviewedPatchError("PATCH_RESULT_DIGEST_INVALID")
        if (
            isinstance(self.bytes_written, bool)
            or not isinstance(self.bytes_written, int)
            or not 0 <= self.bytes_written <= _MAX_TARGET_BYTES
        ):
            raise ReviewedPatchError("PATCH_RESULT_SIZE_INVALID")
        if (
            isinstance(self.hunk_count, bool)
            or not isinstance(self.hunk_count, int)
            or not 1 <= self.hunk_count <= _MAX_HUNKS
        ):
            raise ReviewedPatchError("PATCH_RESULT_HUNK_COUNT_INVALID")
        _validate_evidence_refs(tuple(self.evidence_refs))
        return self


class ReviewedPatchBoundary:
    """Apply one exact, reviewed unified diff without invoking shell or git.

    The patch is resolved from a trusted runtime-owned reference after live
    capability authorization. Patch headers must name exactly the already-admitted
    node resource. V1 intentionally denies multi-file, binary, create/delete,
    rename/fuzz behavior and requires exact hunk context. The target is atomically
    replaced and the original bytes are restored if durable evidence cannot be
    persisted.
    """

    def __init__(
        self,
        *,
        workspace_root: Path,
        patch_source: PatchContentSource,
        evidence_sink: PatchEvidenceSink,
        recorder: ResourceEventRecorder | None = None,
        max_patch_bytes: int = _MAX_PATCH_BYTES,
        max_target_bytes: int = _MAX_TARGET_BYTES,
    ):
        root = Path(workspace_root)
        if root.is_symlink() or not root.exists() or not root.is_dir():
            raise ReviewedPatchError("PATCH_WORKSPACE_ROOT_INVALID")
        if not callable(getattr(patch_source, "resolve_patch", None)):
            raise ReviewedPatchError("PATCH_SOURCE_INVALID")
        if not callable(getattr(evidence_sink, "persist_patch_application", None)):
            raise ReviewedPatchError("PATCH_EVIDENCE_SINK_INVALID")
        if (
            isinstance(max_patch_bytes, bool)
            or not isinstance(max_patch_bytes, int)
            or not 1 <= max_patch_bytes <= _MAX_PATCH_BYTES
        ):
            raise ReviewedPatchError("PATCH_SIZE_LIMIT_INVALID")
        if (
            isinstance(max_target_bytes, bool)
            or not isinstance(max_target_bytes, int)
            or not 1 <= max_target_bytes <= _MAX_TARGET_BYTES
        ):
            raise ReviewedPatchError("PATCH_TARGET_LIMIT_INVALID")
        self.workspace_root = root.resolve(strict=True)
        self.patch_source = patch_source
        self.evidence_sink = evidence_sink
        self.recorder = recorder
        self.max_patch_bytes = max_patch_bytes
        self.max_target_bytes = max_target_bytes

    def _target(self, resource_ref: str) -> Path:
        relative = _safe_relative_resource(resource_ref)
        cursor = self.workspace_root
        for part in relative.parts[:-1]:
            cursor = cursor / part
            if cursor.is_symlink():
                raise ReviewedPatchError("PATCH_SYMLINK_DENIED")
        target = self.workspace_root.joinpath(*relative.parts)
        if target.is_symlink():
            raise ReviewedPatchError("PATCH_SYMLINK_DENIED")
        if not target.exists() or not target.is_file():
            raise ReviewedPatchError("PATCH_TARGET_FILE_REQUIRED")
        try:
            target.resolve(strict=True).relative_to(self.workspace_root)
        except (OSError, ValueError) as exc:
            raise ReviewedPatchError("PATCH_PATH_ESCAPE_DENIED") from exc
        return target

    @staticmethod
    def _read_target(target: Path, max_bytes: int) -> bytes:
        try:
            size = target.stat().st_size
            if size > max_bytes:
                raise ReviewedPatchError("PATCH_TARGET_LIMIT_EXCEEDED")
            data = target.read_bytes()
        except ReviewedPatchError:
            raise
        except OSError as exc:
            raise ReviewedPatchError("PATCH_TARGET_READ_FAILED") from exc
        if len(data) > max_bytes:
            raise ReviewedPatchError("PATCH_TARGET_LIMIT_EXCEEDED")
        return data

    @staticmethod
    def _atomic_replace(target: Path, data: bytes, mode: int) -> None:
        fd = -1
        temp_path: Path | None = None
        try:
            fd, raw_path = tempfile.mkstemp(
                prefix=f".{target.name}.workspace-patch-",
                dir=str(target.parent),
            )
            temp_path = Path(raw_path)
            with os.fdopen(fd, "wb") as handle:
                fd = -1
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temp_path, stat.S_IMODE(mode))
            os.replace(temp_path, target)
            temp_path = None
        except OSError as exc:
            raise ReviewedPatchError("PATCH_ATOMIC_REPLACE_FAILED") from exc
        finally:
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    pass
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def _rollback(self, target: Path, original: bytes, mode: int) -> None:
        try:
            self._atomic_replace(target, original, mode)
        except ReviewedPatchError as exc:
            raise ReviewedPatchError("PATCH_ROLLBACK_FAILED") from exc

    def apply(
        self,
        *,
        task_id: str,
        node: ExecutionNode,
        patch_ref: str,
        patch_sha256: str,
    ) -> ReviewedPatchResult:
        if (
            node.capability != "apply_patch"
            or node.effect != "write"
            or node.resource_kind != "path"
        ):
            raise ReviewedPatchError("PATCH_NODE_UNSUPPORTED")
        if node.idempotent:
            raise ReviewedPatchError("PATCH_NODE_MUST_BE_NON_IDEMPOTENT")

        resource = _safe_relative_resource(node.resource_ref).as_posix()
        ref = _validate_patch_ref(patch_ref)
        expected_patch_sha = _validate_digest(patch_sha256)

        require_runtime_capability(
            node.capability,
            task_id=task_id,
            resource_kind=node.resource_kind,
            resource_ref=node.resource_ref,
            effect=node.effect,
            recorder=self.recorder,
            actor_id="runtime_node",
            action="reviewed_patch_apply",
        )

        try:
            patch = self.patch_source.resolve_patch(
                task_id=task_id,
                patch_ref=ref,
                max_bytes=self.max_patch_bytes,
            )
        except ReviewedPatchError:
            raise
        except Exception as exc:
            raise ReviewedPatchError("PATCH_RESOLUTION_FAILED") from exc
        if not isinstance(patch, bytes):
            raise ReviewedPatchError("PATCH_CONTENT_TYPE_INVALID")
        if len(patch) > self.max_patch_bytes:
            raise ReviewedPatchError("PATCH_SIZE_LIMIT_EXCEEDED")
        if _sha256_bytes(patch) != expected_patch_sha:
            raise ReviewedPatchError("PATCH_DIGEST_MISMATCH")

        target = self._target(resource)
        original = self._read_target(target, self.max_target_bytes)
        try:
            mode = target.stat().st_mode
        except OSError as exc:
            raise ReviewedPatchError("PATCH_TARGET_STAT_FAILED") from exc
        applied = _apply_unified_diff(
            original=original,
            patch=patch,
            resource_ref=resource,
            max_target_bytes=self.max_target_bytes,
        )
        before_sha = _sha256_bytes(original)
        after_sha = _sha256_bytes(applied.content)

        if target.is_symlink():
            raise ReviewedPatchError("PATCH_SYMLINK_DENIED")
        current = self._read_target(target, self.max_target_bytes)
        if _sha256_bytes(current) != before_sha:
            raise ReviewedPatchError("PATCH_TARGET_CHANGED")
        self._atomic_replace(target, applied.content, mode)

        resource_sha = _sha256_text(resource)
        ref_sha = _sha256_text(ref)
        try:
            refs = _validate_evidence_refs(
                tuple(
                    self.evidence_sink.persist_patch_application(
                        task_id=task_id,
                        node_id=node.node_id,
                        resource_sha256=resource_sha,
                        patch_ref_sha256=ref_sha,
                        patch_sha256=expected_patch_sha,
                        before_sha256=before_sha,
                        after_sha256=after_sha,
                        bytes_written=len(applied.content),
                        hunk_count=applied.hunk_count,
                    )
                )
            )
        except Exception as exc:
            self._rollback(target, original, mode)
            if isinstance(exc, ReviewedPatchError):
                raise
            raise ReviewedPatchError("PATCH_EVIDENCE_WRITE_FAILED") from exc

        return ReviewedPatchResult(
            resource_sha256=resource_sha,
            patch_ref_sha256=ref_sha,
            patch_sha256=expected_patch_sha,
            before_sha256=before_sha,
            after_sha256=after_sha,
            bytes_written=len(applied.content),
            hunk_count=applied.hunk_count,
            evidence_refs=refs,
        ).validate()
