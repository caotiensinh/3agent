from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from dataclasses import dataclass
from typing import Protocol

from .capability_registry import CapabilityRegistry
from .inference_scope import current_capability_authority
from .resource_events import ResourceEventRecorder
from .runtime_capability_boundary import require_runtime_capability
from .runtime_execution_plan import ExecutionNode
from .runtime_plan_compiler import CompiledRuntimePlan
from .runtime_source_authority import (
    RuntimeSourceAuthorityDenied,
    RuntimeSourceBindingBundle,
)
from .task_contract import TaskContract

RUNTIME_REVIEWED_REPO_SEARCH_SCHEMA = "workspace-runtime-reviewed-repo-search/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_DEFAULT_MAX_RESULTS = 20
_DEFAULT_MAX_FILES = 2_000
_DEFAULT_MAX_BYTES = 16 * 1024 * 1024
_HARD_MAX_RESULTS = 100
_HARD_MAX_FILES = 10_000
_HARD_MAX_BYTES = 64 * 1024 * 1024
_MAX_FILE_BYTES = 1024 * 1024
_MAX_EXCERPT_CHARS = 240
_MAX_DEPTH = 32
_SKIPPED_DIRECTORIES = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
    }
)


class ReviewedRepoSearchError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class RepoSearchEvidenceSink(Protocol):
    """Persist bounded repo-search evidence and return compact evidence refs."""

    def persist_repo_search(
        self,
        *,
        task_id: str,
        node_id: str,
        source_class: str,
        resource_ref: str,
        query_sha256: str,
        result: bytes,
        result_sha256: str,
    ) -> tuple[str, ...]: ...


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _secure_open_supported() -> bool:
    return (
        hasattr(os, "O_NOFOLLOW")
        and hasattr(os, "O_DIRECTORY")
        and os.open in getattr(os, "supports_dir_fd", set())
        and os.stat in getattr(os, "supports_dir_fd", set())
    )


def _validate_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    refs: list[str] = []
    for value in values:
        ref = str(value).strip()
        if not ref or not _EVIDENCE_RE.fullmatch(ref) or "://" in ref:
            raise ReviewedRepoSearchError("REPO_SEARCH_EVIDENCE_REF_INVALID")
        if ref not in refs:
            refs.append(ref)
        if len(refs) > 32:
            raise ReviewedRepoSearchError("REPO_SEARCH_EVIDENCE_REF_LIMIT_EXCEEDED")
    if not refs:
        raise ReviewedRepoSearchError("REPO_SEARCH_EVIDENCE_REQUIRED")
    return tuple(refs)


def _clean_excerpt(line: str) -> str:
    text = " ".join(str(line).strip().split())
    return text[:_MAX_EXCERPT_CHARS]


@dataclass(frozen=True)
class ReviewedRepoSearchResult:
    query_sha256: str
    result_sha256: str
    result_bytes: int
    match_count: int
    files_scanned: int
    bytes_scanned: int
    evidence_refs: tuple[str, ...]
    source_binding_fingerprint: str
    schema_version: str = RUNTIME_REVIEWED_REPO_SEARCH_SCHEMA

    def validate(self) -> "ReviewedRepoSearchResult":
        for digest in (
            self.query_sha256,
            self.result_sha256,
            self.source_binding_fingerprint,
        ):
            if not _SHA256_RE.fullmatch(str(digest)):
                raise ReviewedRepoSearchError("REPO_SEARCH_DIGEST_INVALID")
        for value, maximum in (
            (self.result_bytes, _HARD_MAX_BYTES),
            (self.match_count, _HARD_MAX_RESULTS),
            (self.files_scanned, _HARD_MAX_FILES),
            (self.bytes_scanned, _HARD_MAX_BYTES),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
                raise ReviewedRepoSearchError("REPO_SEARCH_RESULT_METADATA_INVALID")
        _validate_refs(tuple(self.evidence_refs))
        return self


class ReviewedRepoSearchBoundary:
    """Fail-closed repository search bound to runtime-reviewed source authority.

    Traversal uses directory file descriptors and never follows symlinks. Only
    regular files are read, scanning is bounded by file/byte/result limits, and
    live capability revocation plus tool-call accounting is checked immediately
    before any repository I/O. Raw excerpts go only to the injected evidence sink.
    """

    def __init__(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        source_binding_bundle: RuntimeSourceBindingBundle,
        evidence_sink: RepoSearchEvidenceSink,
        registry: CapabilityRegistry | None = None,
        recorder: ResourceEventRecorder | None = None,
        hard_max_files: int = _HARD_MAX_FILES,
        hard_max_bytes: int = _HARD_MAX_BYTES,
    ):
        active_registry = registry or CapabilityRegistry.default()
        source_binding_bundle.validate(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
            registry=active_registry,
        )
        if evidence_sink is None or not callable(
            getattr(evidence_sink, "persist_repo_search", None)
        ):
            raise ReviewedRepoSearchError("REPO_SEARCH_EVIDENCE_SINK_REQUIRED")
        if (
            isinstance(hard_max_files, bool)
            or not isinstance(hard_max_files, int)
            or not 1 <= hard_max_files <= _HARD_MAX_FILES
        ):
            raise ReviewedRepoSearchError("REPO_SEARCH_HARD_MAX_FILES_INVALID")
        if (
            isinstance(hard_max_bytes, bool)
            or not isinstance(hard_max_bytes, int)
            or not 1 <= hard_max_bytes <= _HARD_MAX_BYTES
        ):
            raise ReviewedRepoSearchError("REPO_SEARCH_HARD_MAX_BYTES_INVALID")
        self.compiled_plan = compiled_plan
        self.task_contract = task_contract
        self.source_binding_bundle = source_binding_bundle
        self.registry = active_registry
        self.evidence_sink = evidence_sink
        self.recorder = recorder
        self.hard_max_files = hard_max_files
        self.hard_max_bytes = hard_max_bytes

    @staticmethod
    def _check_deadline(deadline: float) -> None:
        if time.monotonic() > deadline:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")

    def search_repo(
        self,
        *,
        task_id: str,
        node: ExecutionNode,
        query: str,
        max_results: int = _DEFAULT_MAX_RESULTS,
        max_files: int = _DEFAULT_MAX_FILES,
        max_bytes: int = _DEFAULT_MAX_BYTES,
        timeout_seconds: float,
    ) -> ReviewedRepoSearchResult:
        if node.capability != "search_repo" or node.effect != "read" or node.resource_kind != "repo":
            raise ReviewedRepoSearchError("REPO_SEARCH_NODE_UNSUPPORTED")
        if task_id != self.task_contract.task_id:
            raise ReviewedRepoSearchError("REPO_SEARCH_TASK_MISMATCH")
        if not isinstance(query, str) or not query.strip() or len(query) > 2048 or "\x00" in query:
            raise ReviewedRepoSearchError("REPO_SEARCH_QUERY_INVALID")
        if (
            isinstance(max_results, bool)
            or not isinstance(max_results, int)
            or not 1 <= max_results <= _HARD_MAX_RESULTS
        ):
            raise ReviewedRepoSearchError("REPO_SEARCH_MAX_RESULTS_INVALID")
        if (
            isinstance(max_files, bool)
            or not isinstance(max_files, int)
            or not 1 <= max_files <= self.hard_max_files
        ):
            raise ReviewedRepoSearchError("REPO_SEARCH_MAX_FILES_INVALID")
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 1 <= max_bytes <= self.hard_max_bytes
        ):
            raise ReviewedRepoSearchError("REPO_SEARCH_MAX_BYTES_INVALID")
        if timeout_seconds <= 0:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")
        if not _secure_open_supported():
            raise ReviewedRepoSearchError("REPO_SEARCH_SECURE_OPEN_UNAVAILABLE")

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
        root = binding.local_root
        if root is None:
            raise RuntimeSourceAuthorityDenied("SOURCE_LOCAL_ROOT_REQUIRED")

        authority = current_capability_authority()
        if authority is None:
            raise ReviewedRepoSearchError("REPO_SEARCH_NODE_AUTHORITY_REQUIRED")
        if binding.source_class not in authority.allowed_sources:
            raise RuntimeSourceAuthorityDenied("SOURCE_CLASS_NOT_ALLOWED")
        if authority.network_scope != "deny" or authority.write_scope != "none":
            raise ReviewedRepoSearchError("REPO_SEARCH_SCOPE_NOT_ISOLATED")

        require_runtime_capability(
            node.capability,
            task_id=task_id,
            resource_kind=node.resource_kind,
            resource_ref=node.resource_ref,
            effect=node.effect,
            recorder=self.recorder,
            actor_id="runtime_node",
            action="reviewed_repo_search",
        )

        deadline = time.monotonic() + float(timeout_seconds)
        query_text = query.strip()
        query_fold = query_text.casefold()
        query_sha = _sha256(query_text.encode("utf-8"))
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        file_flags = os.O_RDONLY | os.O_NOFOLLOW
        matches: list[dict[str, object]] = []
        files_scanned = 0
        bytes_scanned = 0
        root_fd: int | None = None

        def walk(directory_fd: int, relative_parts: tuple[str, ...], depth: int) -> None:
            nonlocal files_scanned, bytes_scanned
            self._check_deadline(deadline)
            if depth > _MAX_DEPTH or len(matches) >= max_results:
                return
            try:
                names = sorted(os.listdir(directory_fd))
            except OSError as exc:
                raise ReviewedRepoSearchError("REPO_SEARCH_DIRECTORY_UNAVAILABLE") from exc
            for name in names:
                self._check_deadline(deadline)
                if len(matches) >= max_results:
                    return
                if not name or name in {".", ".."}:
                    continue
                try:
                    info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                except OSError:
                    continue
                if stat.S_ISLNK(info.st_mode):
                    continue
                if stat.S_ISDIR(info.st_mode):
                    if name in _SKIPPED_DIRECTORIES:
                        continue
                    child_fd: int | None = None
                    try:
                        child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                        walk(child_fd, relative_parts + (name,), depth + 1)
                    except OSError:
                        continue
                    finally:
                        if child_fd is not None:
                            try:
                                os.close(child_fd)
                            except OSError:
                                pass
                    continue
                if not stat.S_ISREG(info.st_mode):
                    continue
                if files_scanned >= max_files or bytes_scanned >= max_bytes:
                    return
                if info.st_size < 0 or info.st_size > _MAX_FILE_BYTES:
                    continue
                remaining = max_bytes - bytes_scanned
                if info.st_size > remaining:
                    return
                file_fd: int | None = None
                try:
                    file_fd = os.open(name, file_flags, dir_fd=directory_fd)
                    opened_info = os.fstat(file_fd)
                    if not stat.S_ISREG(opened_info.st_mode) or opened_info.st_size > _MAX_FILE_BYTES:
                        continue
                    chunks: list[bytes] = []
                    total = 0
                    while True:
                        self._check_deadline(deadline)
                        chunk = os.read(file_fd, min(64 * 1024, _MAX_FILE_BYTES + 1 - total))
                        if not chunk:
                            break
                        chunks.append(chunk)
                        total += len(chunk)
                        if total > _MAX_FILE_BYTES or bytes_scanned + total > max_bytes:
                            raise ReviewedRepoSearchError("REPO_SEARCH_MAX_BYTES_EXCEEDED")
                    content = b"".join(chunks)
                except ReviewedRepoSearchError:
                    raise
                except OSError:
                    continue
                finally:
                    if file_fd is not None:
                        try:
                            os.close(file_fd)
                        except OSError:
                            pass
                files_scanned += 1
                bytes_scanned += len(content)
                if b"\x00" in content[:4096]:
                    continue
                text = content.decode("utf-8", errors="replace")
                relative_path = "/".join(relative_parts + (name,))
                for line_number, line in enumerate(text.splitlines(), start=1):
                    if query_fold in line.casefold():
                        matches.append(
                            {
                                "path": relative_path,
                                "line": line_number,
                                "excerpt": _clean_excerpt(line),
                            }
                        )
                        if len(matches) >= max_results:
                            return

        try:
            root_fd = os.open(root, directory_flags)
            walk(root_fd, (), 0)
        except ReviewedRepoSearchError:
            raise
        except OSError as exc:
            raise ReviewedRepoSearchError("REPO_SEARCH_ROOT_UNSAFE_OR_UNAVAILABLE") from exc
        finally:
            if root_fd is not None:
                try:
                    os.close(root_fd)
                except OSError:
                    pass

        payload = {
            "schema_version": RUNTIME_REVIEWED_REPO_SEARCH_SCHEMA,
            "query_sha256": query_sha,
            "matches": matches,
            "match_count": len(matches),
            "files_scanned": files_scanned,
            "bytes_scanned": bytes_scanned,
        }
        result_bytes = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        result_sha = _sha256(result_bytes)
        refs = self.evidence_sink.persist_repo_search(
            task_id=task_id,
            node_id=node.node_id,
            source_class=binding.source_class,
            resource_ref=binding.resource_ref,
            query_sha256=query_sha,
            result=result_bytes,
            result_sha256=result_sha,
        )
        return ReviewedRepoSearchResult(
            query_sha256=query_sha,
            result_sha256=result_sha,
            result_bytes=len(result_bytes),
            match_count=len(matches),
            files_scanned=files_scanned,
            bytes_scanned=bytes_scanned,
            evidence_refs=_validate_refs(tuple(refs)),
            source_binding_fingerprint=binding.fingerprint,
        ).validate()
