from __future__ import annotations

import json
import os
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterator

from .config import AppConfig
from .evidence_packing import (
    DEFAULT_SYNTHESIS_CONTEXT_BUDGET_CHARS,
    LEGACY_PACKING_MODE,
    EvidencePackingPolicy,
    resolve_evidence_packing_policy,
)


BENCHMARK_ISOLATION_SCHEMA = "workspace-benchmark-isolation/v1"
_VARIANT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_ENV_KEYS = (
    "WORKSPACE_INFERENCE_TELEMETRY",
    "WORKSPACE_RESOURCE_TELEMETRY",
    "WORKSPACE_EVIDENCE_PACKING_MODE",
    "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS",
)
_ENV_LOCK = threading.Lock()


@dataclass(frozen=True)
class BenchmarkVariantSpec:
    label: str
    evidence_packing_mode: str = LEGACY_PACKING_MODE
    synthesis_context_budget_chars: int = DEFAULT_SYNTHESIS_CONTEXT_BUDGET_CHARS

    def validate(self) -> "BenchmarkVariantSpec":
        label = str(self.label or "").strip()
        if not _VARIANT_RE.fullmatch(label):
            raise ValueError(
                "benchmark variant label must be 1-80 characters using letters, digits, '.', '_' or '-'"
            )
        policy = resolve_evidence_packing_policy(
            {
                "WORKSPACE_EVIDENCE_PACKING_MODE": str(self.evidence_packing_mode),
                "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS": str(
                    self.synthesis_context_budget_chars
                ),
            }
        )
        return BenchmarkVariantSpec(
            label=label,
            evidence_packing_mode=policy.mode,
            synthesis_context_budget_chars=policy.budget_chars,
        )

    def policy(self) -> EvidencePackingPolicy:
        validated = self.validate()
        return EvidencePackingPolicy(
            mode=validated.evidence_packing_mode,
            budget_chars=validated.synthesis_context_budget_chars,
        )


@dataclass(frozen=True)
class BenchmarkIsolationPaths:
    sandbox_root: Path
    database_path: Path
    artifact_root: Path
    inference_telemetry: Path
    resource_telemetry: Path
    internet_audit_log: Path
    execution_audit_log: Path
    manifest_path: Path

    def to_dict(self) -> dict[str, str]:
        return {
            "sandbox_root": str(self.sandbox_root),
            "database_path": str(self.database_path),
            "artifact_root": str(self.artifact_root),
            "inference_telemetry": str(self.inference_telemetry),
            "resource_telemetry": str(self.resource_telemetry),
            "internet_audit_log": str(self.internet_audit_log),
            "execution_audit_log": str(self.execution_audit_log),
            "manifest_path": str(self.manifest_path),
        }


@dataclass(frozen=True)
class PreparedBenchmarkVariant:
    spec: BenchmarkVariantSpec
    paths: BenchmarkIsolationPaths
    config: AppConfig

    def manifest(self) -> dict:
        policy = self.spec.policy()
        return {
            "schema_version": BENCHMARK_ISOLATION_SCHEMA,
            "variant_label": self.spec.label,
            "evidence_packing": policy.to_fingerprint_dict(),
            "storage": {
                "database_isolated": True,
                "artifacts_isolated": True,
                "inference_telemetry_isolated": True,
                "resource_telemetry_isolated": True,
                "internet_audit_isolated": True,
                "execution_audit_isolated": True,
            },
            "raw_prompt_logged": False,
            "raw_evidence_logged": False,
        }


class BenchmarkIsolation:
    """Create one clean filesystem/telemetry boundary per benchmark variant.

    The class never deletes an existing sandbox. Reusing a non-empty variant root
    fails closed so benchmark evidence from separate runs cannot be accidentally
    accumulated. Runtime optimization knobs are process-global environment values,
    therefore activation is serialized and restored after each variant.
    """

    def __init__(self, base_config: AppConfig, root: Path):
        self.base_config = base_config
        self.root = Path(root).expanduser()

    def paths_for(self, spec: BenchmarkVariantSpec) -> BenchmarkIsolationPaths:
        validated = spec.validate()
        sandbox = self.root / validated.label
        artifact_root = sandbox / "data"
        activity = artifact_root / "activity"
        return BenchmarkIsolationPaths(
            sandbox_root=sandbox,
            database_path=sandbox / "state" / "tasks.db",
            artifact_root=artifact_root,
            inference_telemetry=activity / "inference.jsonl",
            resource_telemetry=activity / "resource_events.jsonl",
            internet_audit_log=activity / "internet.jsonl",
            execution_audit_log=activity / "execution.jsonl",
            manifest_path=sandbox / "isolation.json",
        )

    @staticmethod
    def _assert_empty(paths: BenchmarkIsolationPaths) -> None:
        sandbox = paths.sandbox_root
        if not sandbox.exists():
            return
        if not sandbox.is_dir():
            raise FileExistsError(
                f"benchmark sandbox path exists and is not a directory: {sandbox}"
            )
        try:
            next(sandbox.iterdir())
        except StopIteration:
            return
        raise FileExistsError(
            "benchmark sandbox already contains data; use a new variant/root instead of mixing runs: "
            f"{sandbox}"
        )

    def prepare(self, spec: BenchmarkVariantSpec) -> PreparedBenchmarkVariant:
        validated = spec.validate()
        paths = self.paths_for(validated)
        self._assert_empty(paths)

        paths.database_path.parent.mkdir(parents=True, exist_ok=True)
        paths.artifact_root.mkdir(parents=True, exist_ok=True)
        paths.inference_telemetry.parent.mkdir(parents=True, exist_ok=True)

        isolated = replace(
            self.base_config,
            database_path=paths.database_path,
            artifact_root=paths.artifact_root,
            internet_gateway=replace(
                self.base_config.internet_gateway,
                audit_log=paths.internet_audit_log,
            ),
            execution_gateway=replace(
                self.base_config.execution_gateway,
                audit_log=paths.execution_audit_log,
            ),
        )
        prepared = PreparedBenchmarkVariant(validated, paths, isolated)
        paths.manifest_path.write_text(
            json.dumps(prepared.manifest(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        return prepared

    @contextmanager
    def activate(
        self,
        spec: BenchmarkVariantSpec,
    ) -> Iterator[PreparedBenchmarkVariant]:
        if not _ENV_LOCK.acquire(blocking=False):
            raise RuntimeError(
                "benchmark variant activation is process-global and cannot run concurrently"
            )
        previous = {key: os.environ.get(key) for key in _ENV_KEYS}
        try:
            prepared = self.prepare(spec)
            os.environ["WORKSPACE_INFERENCE_TELEMETRY"] = str(
                prepared.paths.inference_telemetry
            )
            os.environ["WORKSPACE_RESOURCE_TELEMETRY"] = str(
                prepared.paths.resource_telemetry
            )
            os.environ["WORKSPACE_EVIDENCE_PACKING_MODE"] = (
                prepared.spec.evidence_packing_mode
            )
            os.environ["WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS"] = str(
                prepared.spec.synthesis_context_budget_chars
            )
            yield prepared
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
            _ENV_LOCK.release()


def assert_isolated_variants(
    first: PreparedBenchmarkVariant,
    second: PreparedBenchmarkVariant,
) -> None:
    """Fail if two prepared variants could write to any shared benchmark sink."""

    first_paths = first.paths
    second_paths = second.paths
    pairs = {
        "sandbox_root": (first_paths.sandbox_root, second_paths.sandbox_root),
        "database_path": (first_paths.database_path, second_paths.database_path),
        "artifact_root": (first_paths.artifact_root, second_paths.artifact_root),
        "inference_telemetry": (
            first_paths.inference_telemetry,
            second_paths.inference_telemetry,
        ),
        "resource_telemetry": (
            first_paths.resource_telemetry,
            second_paths.resource_telemetry,
        ),
        "internet_audit_log": (
            first_paths.internet_audit_log,
            second_paths.internet_audit_log,
        ),
        "execution_audit_log": (
            first_paths.execution_audit_log,
            second_paths.execution_audit_log,
        ),
    }
    collisions = [
        name
        for name, (left, right) in pairs.items()
        if left.resolve() == right.resolve()
    ]
    if collisions:
        raise ValueError(
            "benchmark variants share storage/telemetry sinks: "
            + ", ".join(sorted(collisions))
        )
