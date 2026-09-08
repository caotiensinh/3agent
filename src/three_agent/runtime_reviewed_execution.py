from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol

from .inference_scope import current_capability_authority
from .resource_events import ResourceEventRecorder
from .runtime_capability_boundary import require_runtime_capability
from .runtime_execution_plan import ExecutionNode

RUNTIME_REVIEWED_EXECUTION_SCHEMA = "workspace-runtime-reviewed-execution/v1"
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/@+\-=]{0,255}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")


class ReviewedExecutionError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _compact(value: object, field: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _COMPACT_RE.fullmatch(text) or "://" in text:
        raise ReviewedExecutionError(f"REVIEWED_{field.upper()}_INVALID")
    return text


def _safe_relative_path(value: object, field: str) -> str:
    text = str(value or ".").strip().replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts:
        raise ReviewedExecutionError(f"REVIEWED_{field.upper()}_INVALID")
    normalized = path.as_posix().strip("/")
    return normalized if normalized and normalized != "." else "."


def _sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class ReviewedCommandProfile:
    profile_id: str
    capability: str
    argv: tuple[str, ...]
    relative_cwd: str = "."
    max_timeout_ms: int = 300_000

    def validate(self) -> "ReviewedCommandProfile":
        profile = _compact(self.profile_id, "profile_id", max_len=64)
        if self.capability not in {"run_tests", "run_linter"}:
            raise ReviewedExecutionError("REVIEWED_PROFILE_CAPABILITY_UNSUPPORTED")
        if not self.argv or len(self.argv) > 32:
            raise ReviewedExecutionError("REVIEWED_PROFILE_ARGV_INVALID")
        normalized_argv: list[str] = []
        for item in self.argv:
            if not isinstance(item, str) or not item or len(item) > 256 or "\x00" in item:
                raise ReviewedExecutionError("REVIEWED_PROFILE_ARGV_INVALID")
            normalized_argv.append(item)
        executable = Path(normalized_argv[0]).name.casefold()
        if self.capability == "run_tests":
            allowed = executable in {"pytest", "pytest.exe"}
            if executable in {"python", "python3", "python.exe"}:
                allowed = len(normalized_argv) >= 3 and normalized_argv[1:3] == ["-m", "pytest"]
            if not allowed:
                raise ReviewedExecutionError("REVIEWED_TEST_PROFILE_EXECUTABLE_DENIED")
        else:
            allowed = executable in {"ruff", "ruff.exe"}
            if executable in {"python", "python3", "python.exe"}:
                allowed = len(normalized_argv) >= 3 and normalized_argv[1:3] == ["-m", "ruff"]
            if not allowed:
                raise ReviewedExecutionError("REVIEWED_LINTER_PROFILE_EXECUTABLE_DENIED")
        if any(item in {"-c", "--command"} for item in normalized_argv[1:]):
            raise ReviewedExecutionError("REVIEWED_PROFILE_INLINE_CODE_DENIED")
        _safe_relative_path(self.relative_cwd, "relative_cwd")
        if (
            isinstance(self.max_timeout_ms, bool)
            or not isinstance(self.max_timeout_ms, int)
            or not 100 <= self.max_timeout_ms <= 3_600_000
        ):
            raise ReviewedExecutionError("REVIEWED_PROFILE_TIMEOUT_INVALID")
        if profile != self.profile_id:
            raise ReviewedExecutionError("REVIEWED_PROFILE_ID_NORMALIZATION_DRIFT")
        return self


@dataclass(frozen=True)
class SandboxConstraints:
    task_id: str
    node_id: str
    network_scope: str
    write_scope: tuple[str, ...]
    workspace_root: str

    def metadata(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "node_id": self.node_id,
            "network_scope": self.network_scope,
            "write_scope": list(self.write_scope),
            "workspace_root": self.workspace_root,
        }


@dataclass(frozen=True)
class SandboxCommandResult:
    returncode: int
    stdout_sha256: str
    stderr_sha256: str
    evidence_refs: tuple[str, ...]

    @classmethod
    def from_output_hashes(
        cls,
        *,
        returncode: int,
        stdout: bytes,
        stderr: bytes,
        evidence_refs: tuple[str, ...],
    ) -> "SandboxCommandResult":
        return cls(
            returncode=returncode,
            stdout_sha256=_sha256(stdout),
            stderr_sha256=_sha256(stderr),
            evidence_refs=evidence_refs,
        ).validate()

    def validate(self) -> "SandboxCommandResult":
        if isinstance(self.returncode, bool) or not isinstance(self.returncode, int):
            raise ReviewedExecutionError("SANDBOX_RESULT_RETURNCODE_INVALID")
        if not _SHA256_RE.fullmatch(str(self.stdout_sha256)):
            raise ReviewedExecutionError("SANDBOX_RESULT_STDOUT_DIGEST_INVALID")
        if not _SHA256_RE.fullmatch(str(self.stderr_sha256)):
            raise ReviewedExecutionError("SANDBOX_RESULT_STDERR_DIGEST_INVALID")
        if not self.evidence_refs or len(self.evidence_refs) > 32:
            raise ReviewedExecutionError("SANDBOX_RESULT_EVIDENCE_REQUIRED")
        for ref in self.evidence_refs:
            if not _EVIDENCE_RE.fullmatch(str(ref)) or "://" in str(ref):
                raise ReviewedExecutionError("SANDBOX_RESULT_EVIDENCE_REF_INVALID")
        return self


class SandboxRunner(Protocol):
    """Trusted isolation backend; host subprocess fallback is intentionally absent."""

    def run(
        self,
        *,
        argv: tuple[str, ...],
        cwd: Path,
        timeout_seconds: float,
        constraints: SandboxConstraints,
    ) -> SandboxCommandResult: ...


class ReviewedExecutionBoundary:
    """Fixed-profile execution boundary above a trusted sandbox runner.

    Planner data may select only a reviewed profile ID. argv/cwd never come from
    the planner. The injected runner is responsible for actually enforcing the
    supplied network/write constraints at the OS/container boundary.
    """

    def __init__(
        self,
        *,
        workspace_root: Path,
        profiles: tuple[ReviewedCommandProfile, ...],
        runner: SandboxRunner,
        recorder: ResourceEventRecorder | None = None,
    ):
        self.workspace_root = Path(workspace_root).resolve()
        if not self.workspace_root.is_absolute():
            raise ReviewedExecutionError("REVIEWED_WORKSPACE_ROOT_INVALID")
        if not profiles:
            raise ReviewedExecutionError("REVIEWED_PROFILE_SET_EMPTY")
        by_key: dict[tuple[str, str], ReviewedCommandProfile] = {}
        for profile in profiles:
            profile.validate()
            key = (profile.capability, profile.profile_id)
            if key in by_key:
                raise ReviewedExecutionError("REVIEWED_PROFILE_DUPLICATE")
            by_key[key] = profile
        if runner is None or not callable(getattr(runner, "run", None)):
            raise ReviewedExecutionError("TRUSTED_SANDBOX_RUNNER_REQUIRED")
        self._profiles = by_key
        self.runner = runner
        self.recorder = recorder

    def _cwd(self, relative_cwd: str) -> Path:
        relative = _safe_relative_path(relative_cwd, "relative_cwd")
        target = (self.workspace_root / relative).resolve()
        try:
            common = os.path.commonpath((str(self.workspace_root), str(target)))
        except ValueError as exc:
            raise ReviewedExecutionError("REVIEWED_PROFILE_CWD_ESCAPE") from exc
        if common != str(self.workspace_root):
            raise ReviewedExecutionError("REVIEWED_PROFILE_CWD_ESCAPE")
        return target

    @staticmethod
    def _write_scope_tuple(scope: str | tuple[str, ...]) -> tuple[str, ...]:
        if scope == "none":
            return ()
        return tuple(scope) if isinstance(scope, tuple) else (str(scope),)

    def invoke(
        self,
        *,
        task_id: str,
        node: ExecutionNode,
        profile_id: str,
        timeout_seconds: float,
    ) -> SandboxCommandResult:
        key = (node.capability, str(profile_id).strip())
        try:
            profile = self._profiles[key]
        except KeyError as exc:
            raise ReviewedExecutionError("REVIEWED_PROFILE_NOT_FOUND") from exc
        if node.effect != "execute" or node.capability not in {"run_tests", "run_linter"}:
            raise ReviewedExecutionError("REVIEWED_EXECUTION_NODE_UNSUPPORTED")
        if timeout_seconds <= 0:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")

        require_runtime_capability(
            node.capability,
            task_id=task_id,
            resource_kind=node.resource_kind,
            resource_ref=node.resource_ref,
            effect=node.effect,
            recorder=self.recorder,
            actor_id="runtime_node",
            action="reviewed_execution",
        )
        authority = current_capability_authority()
        if authority is None:
            raise ReviewedExecutionError("REVIEWED_NODE_AUTHORITY_REQUIRED")
        # run_tests/run_linter nodes are capability-isolated and must not obtain
        # network or write authority merely because the parent task has it.
        if authority.network_scope != "deny" or authority.write_scope != "none":
            raise ReviewedExecutionError("REVIEWED_EXECUTION_SCOPE_NOT_ISOLATED")

        constraints = SandboxConstraints(
            task_id=str(task_id),
            node_id=node.node_id,
            network_scope=authority.network_scope,
            write_scope=self._write_scope_tuple(authority.write_scope),
            workspace_root=str(self.workspace_root),
        )
        timeout = min(float(timeout_seconds), profile.max_timeout_ms / 1000.0)
        if timeout <= 0:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")
        result = self.runner.run(
            argv=profile.argv,
            cwd=self._cwd(profile.relative_cwd),
            timeout_seconds=timeout,
            constraints=constraints,
        )
        if not isinstance(result, SandboxCommandResult):
            raise ReviewedExecutionError("SANDBOX_RESULT_TYPE_INVALID")
        return result.validate()
