"""Bounded explicit scheduler for WorkSpace Adaptive Learning Phase 4G.

The scheduler discovers bounded local DONE tasks, resolves exact manifest and
evidence through an injected trusted catalog, reuses Phase 4A admission and
Phase 4B reflection, and stops at stage-only persistence.

It deliberately has no daemon loop, promotion/checkpoint/retrieval mutation,
network client, shell, Git, deployment, remediation, or credential authority.
"""
from __future__ import annotations

import hashlib
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Mapping

from .adaptive_learning_admission import (
    DeterministicLearningAdmission,
    LearningAdmissionError,
    VerifiedLearningSourceEnvelope,
)
from .adaptive_learning_reflection import ReflectionCoordinator, ReflectionError
from .adaptive_learning_reflection_contract import ReflectionDomainBinding
from .models import Task, TaskStatus
from .resource_budget import ResourceAdmissionError
from .store import TaskStore

SCHEDULER_RESULT_SCHEMA = "workspace-adaptive-learning-scheduler-result/v1"
_MAX_TASKS = 64
_MAX_REFLECTIONS = 16
_MAX_SECONDS = 300.0
_REASON = re.compile(r"^[A-Z0-9][A-Z0-9_:,-]{0,159}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


class ReflectionSchedulerError(ValueError):
    """A Phase 4G scheduler contract or trusted-source rule failed."""


def _bytes_sha256(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _bounded_int(value: int, *, name: str, maximum: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= maximum:
        raise ReflectionSchedulerError(f"SCHEDULER_{name.upper()}_INVALID")
    return value


def _bounded_seconds(value: float) -> float:
    if isinstance(value, bool):
        raise ReflectionSchedulerError("SCHEDULER_MAX_SECONDS_INVALID")
    try:
        seconds = float(value)
    except (TypeError, ValueError) as exc:
        raise ReflectionSchedulerError("SCHEDULER_MAX_SECONDS_INVALID") from exc
    if not 0.1 <= seconds <= _MAX_SECONDS:
        raise ReflectionSchedulerError("SCHEDULER_MAX_SECONDS_INVALID")
    return seconds


def _reason_code(value: object, fallback: str = "SCHEDULER_SOURCE_FAILED") -> str:
    text = str(value or "").strip().upper()
    return text if _REASON.fullmatch(text) else fallback


@dataclass(frozen=True)
class TrustedReflectionSource:
    """Finite operator/policy-owned source descriptor.

    File-system identity is checked lazily during an enabled tick so constructing
    a disabled scheduler performs no learning filesystem work. Evidence bytes and
    local manifest paths are hidden from repr and never enter scheduler results.
    """

    task_id: str
    manifest_path: Path = field(repr=False)
    domain: str
    authority_type: str
    authority_id: str
    evidence_payloads: Mapping[str, bytes] = field(repr=False)
    requested_sensitivity: str | None = None

    def validate_descriptor(self) -> "TrustedReflectionSource":
        task_id = str(self.task_id or "").strip()
        if not task_id or len(task_id) > 128:
            raise ReflectionSchedulerError("SCHEDULER_SOURCE_TASK_ID_INVALID")
        if not Path(self.manifest_path).is_absolute():
            raise ReflectionSchedulerError("SCHEDULER_MANIFEST_PATH_NOT_ABSOLUTE")
        if not isinstance(self.evidence_payloads, Mapping):
            raise ReflectionSchedulerError("SCHEDULER_EVIDENCE_MAPPING_INVALID")
        if not str(self.domain or "").strip():
            raise ReflectionSchedulerError("SCHEDULER_DOMAIN_MAPPING_REQUIRED")
        if not str(self.authority_type or "").strip() or not str(self.authority_id or "").strip():
            raise ReflectionSchedulerError("SCHEDULER_DOMAIN_AUTHORITY_REQUIRED")
        return self

    def validate_manifest_identity(self) -> Path:
        self.validate_descriptor()
        path = Path(self.manifest_path)
        try:
            info = path.lstat()
        except OSError as exc:
            raise ReflectionSchedulerError("SCHEDULER_MANIFEST_UNAVAILABLE") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ReflectionSchedulerError("SCHEDULER_MANIFEST_IDENTITY_INVALID")
        return path

    def validate_evidence(
        self, envelope: VerifiedLearningSourceEnvelope
    ) -> dict[str, bytes]:
        self.validate_descriptor()
        envelope.to_payload()
        if envelope.task_id != self.task_id:
            raise ReflectionSchedulerError("SCHEDULER_SOURCE_TASK_MISMATCH")
        expected = tuple(envelope.evidence_hashes)
        normalized: dict[str, bytes] = {}
        for raw_key, raw_value in self.evidence_payloads.items():
            key = str(raw_key or "").strip().lower()
            if not _SHA.fullmatch(key):
                raise ReflectionSchedulerError("SCHEDULER_EVIDENCE_REF_INVALID")
            if not isinstance(raw_value, (bytes, bytearray)):
                raise ReflectionSchedulerError("SCHEDULER_EVIDENCE_BYTES_REQUIRED")
            if key in normalized:
                raise ReflectionSchedulerError("SCHEDULER_EVIDENCE_SET_MISMATCH")
            payload = bytes(raw_value)
            if _bytes_sha256(payload) != key:
                raise ReflectionSchedulerError("SCHEDULER_EVIDENCE_DIGEST_MISMATCH")
            normalized[key] = payload
        if set(normalized) != set(expected) or len(normalized) != len(expected):
            raise ReflectionSchedulerError("SCHEDULER_EVIDENCE_SET_MISMATCH")
        return normalized

    def binding_for(
        self, envelope: VerifiedLearningSourceEnvelope
    ) -> ReflectionDomainBinding:
        return ReflectionDomainBinding.create(
            envelope,
            domain=self.domain,
            authority_type=self.authority_type,
            authority_id=self.authority_id,
        )


class TrustedReflectionSourceCatalog:
    """Finite exact mapping; never scans directories or invents filenames."""

    def __init__(self, entries: list[TrustedReflectionSource] | tuple[TrustedReflectionSource, ...]):
        by_task: dict[str, TrustedReflectionSource] = {}
        for entry in tuple(entries):
            entry.validate_descriptor()
            task_id = str(entry.task_id).strip()
            if task_id in by_task:
                raise ReflectionSchedulerError("SCHEDULER_SOURCE_DUPLICATE_TASK")
            by_task[task_id] = entry
        self.__entries = by_task

    def get(self, task_id: str) -> TrustedReflectionSource | None:
        return self.__entries.get(str(task_id or "").strip())


@dataclass(frozen=True)
class ReflectionSchedulerSourceResult:
    task_id: str
    status: str
    reason_code: str
    admission_id: str | None = None
    candidate_id: str | None = None

    def to_payload(self) -> dict[str, object]:
        return {
            "task_id": self.task_id,
            "status": self.status,
            "reason_code": self.reason_code,
            "admission_id": self.admission_id,
            "candidate_id": self.candidate_id,
        }


@dataclass(frozen=True)
class ReflectionSchedulerResult:
    enabled: bool
    considered_count: int
    admitted_count: int
    reflection_attempt_count: int
    reflected_count: int
    staged_count: int
    no_learning_value_count: int
    skipped_count: int
    failed_count: int
    sources: tuple[ReflectionSchedulerSourceResult, ...]
    schema_version: str = SCHEDULER_RESULT_SCHEMA

    def to_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "enabled": self.enabled,
            "considered_count": self.considered_count,
            "admitted_count": self.admitted_count,
            "reflection_attempt_count": self.reflection_attempt_count,
            "reflected_count": self.reflected_count,
            "staged_count": self.staged_count,
            "no_learning_value_count": self.no_learning_value_count,
            "skipped_count": self.skipped_count,
            "failed_count": self.failed_count,
            "sources": [item.to_payload() for item in self.sources],
        }


class BoundedReflectionScheduler:
    """One explicit bounded tick over previously completed local workflows."""

    def __init__(
        self,
        task_store: TaskStore,
        admission: DeterministicLearningAdmission,
        coordinator: ReflectionCoordinator,
        catalog: TrustedReflectionSourceCatalog,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._task_store = task_store
        self._admission = admission
        self._coordinator = coordinator
        self._catalog = catalog
        self._clock = clock

    @staticmethod
    def _ordered_done(tasks: list[Task]) -> list[Task]:
        return sorted(
            (task for task in tasks if task.status is TaskStatus.DONE),
            key=lambda task: (task.created_at, task.updated_at, task.task_id),
            reverse=True,
        )

    @staticmethod
    def _source_result(
        task_id: str,
        status: str,
        reason_code: str,
        *,
        admission_id: str | None = None,
        candidate_id: str | None = None,
    ) -> ReflectionSchedulerSourceResult:
        return ReflectionSchedulerSourceResult(
            task_id=str(task_id),
            status=status,
            reason_code=_reason_code(reason_code),
            admission_id=admission_id,
            candidate_id=candidate_id,
        )

    def run_once(
        self,
        *,
        enabled: bool = False,
        max_tasks: int = 8,
        max_reflections: int = 4,
        max_seconds: float = 60.0,
    ) -> ReflectionSchedulerResult:
        """Run one explicit tick and stop; disabled mode touches no learning source."""
        task_limit = _bounded_int(max_tasks, name="max_tasks", maximum=_MAX_TASKS)
        reflection_limit = _bounded_int(
            max_reflections, name="max_reflections", maximum=_MAX_REFLECTIONS
        )
        seconds = _bounded_seconds(max_seconds)
        if not isinstance(enabled, bool):
            raise ReflectionSchedulerError("SCHEDULER_ENABLED_INVALID")
        if not enabled:
            return ReflectionSchedulerResult(
                False, 0, 0, 0, 0, 0, 0, 0, 0, ()
            )

        selected = self._ordered_done(self._task_store.list_tasks())[:task_limit]
        deadline = self._clock() + seconds
        considered = admitted = attempts = reflected = staged = no_value = 0
        skipped = failed = 0
        results: list[ReflectionSchedulerSourceResult] = []

        for task in selected:
            if self._clock() >= deadline:
                break
            considered += 1
            entry = self._catalog.get(task.task_id)
            if entry is None:
                skipped += 1
                results.append(self._source_result(
                    task.task_id, "skipped", "SCHEDULER_SOURCE_CATALOG_MISSING"
                ))
                continue

            envelope: VerifiedLearningSourceEnvelope | None = None
            try:
                envelope = self._admission.admit(
                    task.task_id,
                    entry.validate_manifest_identity(),
                    requested_sensitivity=entry.requested_sensitivity,
                )
                admitted += 1
                evidence = entry.validate_evidence(envelope)
                binding = entry.binding_for(envelope)

                receipt = self._coordinator.receipt_store.read(
                    envelope.admission_id, binding.domain
                )
                if receipt is not None:
                    skipped += 1
                    reason = (
                        "REFLECTION_ALREADY_COMPLETED"
                        if receipt.status == "completed"
                        else "REFLECTION_CLAIM_RECOVERY_REQUIRED"
                    )
                    results.append(self._source_result(
                        task.task_id, "skipped", reason,
                        admission_id=envelope.admission_id,
                    ))
                    continue

                if attempts >= reflection_limit:
                    skipped += 1
                    results.append(self._source_result(
                        task.task_id,
                        "skipped",
                        "SCHEDULER_REFLECTION_LIMIT_REACHED",
                        admission_id=envelope.admission_id,
                    ))
                    continue

                attempts += 1
                outcome = self._coordinator.reflect_and_stage(envelope, binding, evidence)
                reflected += 1
                if outcome.result == "STAGED":
                    staged += 1
                    results.append(self._source_result(
                        task.task_id, "completed", "REFLECTION_STAGED",
                        admission_id=envelope.admission_id,
                        candidate_id=outcome.candidate_id,
                    ))
                elif outcome.result == "NO_LEARNING_VALUE":
                    no_value += 1
                    results.append(self._source_result(
                        task.task_id, "completed", "NO_LEARNING_VALUE",
                        admission_id=envelope.admission_id,
                    ))
                else:
                    failed += 1
                    results.append(self._source_result(
                        task.task_id, "failed", "SCHEDULER_REFLECTION_RESULT_INVALID",
                        admission_id=envelope.admission_id,
                    ))
            except ResourceAdmissionError:
                raise
            except LearningAdmissionError as exc:
                skipped += 1
                results.append(self._source_result(task.task_id, "skipped", exc.reason_code))
            except ReflectionError as exc:
                code = _reason_code(exc.reason_code)
                if code in {"REFLECTION_ALREADY_COMPLETED", "REFLECTION_CLAIM_RECOVERY_REQUIRED"}:
                    skipped += 1
                    status = "skipped"
                else:
                    failed += 1
                    status = "failed"
                results.append(self._source_result(
                    task.task_id, status, code,
                    admission_id=None if envelope is None else envelope.admission_id,
                ))
            except ReflectionSchedulerError as exc:
                failed += 1
                results.append(self._source_result(
                    task.task_id, "failed", str(exc),
                    admission_id=None if envelope is None else envelope.admission_id,
                ))
            except Exception:
                # Never copy arbitrary exception text: a lower layer may include
                # source content or a local path.
                failed += 1
                results.append(self._source_result(
                    task.task_id, "failed", "SCHEDULER_SOURCE_FAILED",
                    admission_id=None if envelope is None else envelope.admission_id,
                ))

        return ReflectionSchedulerResult(
            enabled=True,
            considered_count=considered,
            admitted_count=admitted,
            reflection_attempt_count=attempts,
            reflected_count=reflected,
            staged_count=staged,
            no_learning_value_count=no_value,
            skipped_count=skipped,
            failed_count=failed,
            sources=tuple(results),
        )
