"""Bounded operator-enabled scheduler for WorkSpace Phase 4G reflection.

This module discovers only explicitly domain-bound DONE tasks, resolves only
artifacts already registered in TaskStore and contained by ArtifactManager.root,
then reuses Phase 4A admission and Phase 4B reflection/stage-only persistence.

It deliberately provides only a bounded run_once() primitive. It has no daemon
loop, promotion authority, remediation capability, Git/deployment authority, or
network client of its own.
"""
from __future__ import annotations

import hashlib
import re
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping

from .adaptive_learning_admission import (
    DeterministicLearningAdmission,
    LearningAdmissionError,
    VerifiedLearningSourceEnvelope,
)
from .adaptive_learning_reflection import ReflectionCoordinator, ReflectionError
from .adaptive_learning_reflection_contract import (
    AUTHORITY_TYPES,
    DOMAINS,
    ReflectionContractError,
    ReflectionDomainBinding,
)
from .artifacts import ArtifactManager
from .models import TaskStatus
from .store import TaskStore

SCHEDULER_RUN_SCHEMA = "workspace-learning-scheduler-run/v1"
_MAX_CONFIGURED_TASKS = 128
_MAX_ITEMS = 32
_MAX_SCAN_ITEMS = 128
_MAX_WALL_TIME_SECONDS = 3600
_MAX_EVIDENCE_RECORDS_PER_TASK = 32
_MAX_EVIDENCE_ITEM_BYTES = 32 * 1024
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")


class LearningSchedulerError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


@dataclass(frozen=True)
class ScheduledTaskDomain:
    task_id: str
    domain: str

    def validate(self) -> "ScheduledTaskDomain":
        task_id = str(self.task_id or "").strip()
        domain = str(self.domain or "").strip().lower()
        if not _ID.fullmatch(task_id):
            raise LearningSchedulerError("SCHEDULER_TASK_ID_INVALID")
        if domain not in DOMAINS:
            raise LearningSchedulerError("SCHEDULER_DOMAIN_INVALID")
        if task_id != self.task_id or domain != self.domain:
            raise LearningSchedulerError("SCHEDULER_DOMAIN_BINDING_NOT_CANONICAL")
        return self


@dataclass(frozen=True)
class AdaptiveLearningSchedulerConfig:
    enabled: bool = False
    max_items: int = 4
    max_scan_items: int = 16
    max_wall_time_seconds: int = 300
    authority_type: str = "policy"
    authority_id: str = "policy:adaptive-learning-scheduler-v1"
    task_domains: tuple[ScheduledTaskDomain, ...] = ()

    def validate(self) -> "AdaptiveLearningSchedulerConfig":
        if not isinstance(self.enabled, bool):
            raise LearningSchedulerError("SCHEDULER_ENABLED_INVALID")
        for value, maximum, reason in (
            (self.max_items, _MAX_ITEMS, "SCHEDULER_MAX_ITEMS_INVALID"),
            (self.max_scan_items, _MAX_SCAN_ITEMS, "SCHEDULER_MAX_SCAN_ITEMS_INVALID"),
            (
                self.max_wall_time_seconds,
                _MAX_WALL_TIME_SECONDS,
                "SCHEDULER_MAX_WALL_TIME_INVALID",
            ),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 1 <= value <= maximum
            ):
                raise LearningSchedulerError(reason)
        if self.max_scan_items < self.max_items:
            raise LearningSchedulerError("SCHEDULER_SCAN_LIMIT_BELOW_ITEM_LIMIT")
        authority_type = str(self.authority_type or "").strip().lower()
        authority_id = str(self.authority_id or "").strip()
        if authority_type not in AUTHORITY_TYPES:
            raise LearningSchedulerError("SCHEDULER_AUTHORITY_TYPE_INVALID")
        if authority_type != self.authority_type:
            raise LearningSchedulerError("SCHEDULER_AUTHORITY_TYPE_NOT_CANONICAL")
        if not _ID.fullmatch(authority_id) or authority_id != self.authority_id:
            raise LearningSchedulerError("SCHEDULER_AUTHORITY_ID_INVALID")
        if (
            not isinstance(self.task_domains, tuple)
            or len(self.task_domains) > _MAX_CONFIGURED_TASKS
        ):
            raise LearningSchedulerError("SCHEDULER_TASK_DOMAINS_INVALID")
        seen: set[str] = set()
        for entry in self.task_domains:
            if not isinstance(entry, ScheduledTaskDomain):
                raise LearningSchedulerError("SCHEDULER_TASK_DOMAINS_INVALID")
            entry.validate()
            if entry.task_id in seen:
                raise LearningSchedulerError("SCHEDULER_TASK_DOMAIN_DUPLICATE")
            seen.add(entry.task_id)
        return self

    def domain_map(self) -> dict[str, str]:
        self.validate()
        return {entry.task_id: entry.domain for entry in self.task_domains}


@dataclass(frozen=True)
class LearningSourceHandle:
    task_id: str
    manifest_record_path: str


@dataclass(frozen=True)
class SchedulerItemOutcome:
    task_id: str
    result: str
    reason_code: str | None
    domain: str | None = None
    admission_id: str | None = None
    candidate_id: str | None = None
    candidate_sha256: str | None = None

    def to_payload(self) -> dict[str, str | None]:
        return {
            "task_id": self.task_id,
            "result": self.result,
            "reason_code": self.reason_code,
            "domain": self.domain,
            "admission_id": self.admission_id,
            "candidate_id": self.candidate_id,
            "candidate_sha256": self.candidate_sha256,
        }


@dataclass(frozen=True)
class SchedulerRunReceipt:
    enabled: bool
    attempted: int
    staged: int
    no_learning_value: int
    skipped: int
    recovery_required: int
    failed: int
    elapsed_ms: int
    stop_reason: str
    outcomes: tuple[SchedulerItemOutcome, ...]
    schema_version: str = SCHEDULER_RUN_SCHEMA

    def to_payload(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "enabled": self.enabled,
            "attempted": self.attempted,
            "staged": self.staged,
            "no_learning_value": self.no_learning_value,
            "skipped": self.skipped,
            "recovery_required": self.recovery_required,
            "failed": self.failed,
            "elapsed_ms": self.elapsed_ms,
            "stop_reason": self.stop_reason,
            "outcomes": [item.to_payload() for item in self.outcomes],
        }


class LocalLearningSourceProvider:
    """Resolve only TaskStore-registered artifacts under one trusted artifact root."""

    def __init__(self, store: TaskStore, artifacts: ArtifactManager):
        self.store = store
        self.artifacts = artifacts

    @property
    def root(self) -> Path:
        return self.artifacts.root.resolve()

    def discover_done(
        self,
        configured_task_ids: tuple[str, ...],
        *,
        limit: int,
    ) -> tuple[LearningSourceHandle, ...]:
        if not configured_task_ids:
            return ()
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= _MAX_SCAN_ITEMS
        ):
            raise LearningSchedulerError("SCHEDULER_DISCOVERY_LIMIT_INVALID")
        if len(configured_task_ids) > _MAX_CONFIGURED_TASKS:
            raise LearningSchedulerError("SCHEDULER_DISCOVERY_TASK_SET_TOO_LARGE")
        placeholders = ",".join("?" for _ in configured_task_ids)
        sql = f"""
            SELECT t.task_id,
                   (
                       SELECT a.path
                       FROM artifacts a
                       WHERE a.task_id = t.task_id
                         AND a.artifact_type = 'workflow_manifest_json'
                       ORDER BY a.id DESC
                       LIMIT 1
                   ) AS manifest_path
            FROM tasks t
            WHERE t.status = ?
              AND t.task_id IN ({placeholders})
            ORDER BY t.updated_at DESC, t.task_id
            LIMIT ?
        """
        params = (TaskStatus.DONE.value, *configured_task_ids, limit)
        with self.store.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return tuple(
            LearningSourceHandle(
                task_id=str(row["task_id"]),
                manifest_record_path=str(row["manifest_path"] or ""),
            )
            for row in rows
        )

    def _trusted_registered_path(self, raw_path: str, *, reason_prefix: str) -> Path:
        text = str(raw_path or "").strip()
        if not text or len(text) > 4096:
            raise LearningSchedulerError(f"{reason_prefix}_PATH_INVALID")
        path = Path(text)
        if path.is_symlink():
            raise LearningSchedulerError(f"{reason_prefix}_SYMLINK_FORBIDDEN")
        try:
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise LearningSchedulerError(f"{reason_prefix}_UNREADABLE") from exc
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise LearningSchedulerError(f"{reason_prefix}_OUTSIDE_ARTIFACT_ROOT") from exc
        if not resolved.is_file():
            raise LearningSchedulerError(f"{reason_prefix}_NOT_REGULAR_FILE")
        return resolved

    def manifest_path(self, handle: LearningSourceHandle) -> Path:
        if not isinstance(handle, LearningSourceHandle):
            raise LearningSchedulerError("SCHEDULER_SOURCE_HANDLE_INVALID")
        if not handle.manifest_record_path:
            raise LearningSchedulerError("SCHEDULER_MANIFEST_NOT_REGISTERED")
        return self._trusted_registered_path(
            handle.manifest_record_path,
            reason_prefix="SCHEDULER_MANIFEST",
        )

    def _evidence_records(self, task_id: str) -> tuple[str, ...]:
        with self.store.connect() as conn:
            rows = conn.execute(
                """
                SELECT path
                FROM artifacts
                WHERE task_id = ?
                  AND artifact_type = 'research_handoff_json'
                ORDER BY id DESC
                LIMIT ?
                """,
                (task_id, _MAX_EVIDENCE_RECORDS_PER_TASK),
            ).fetchall()
        return tuple(str(row["path"] or "") for row in rows)

    def load_evidence(
        self,
        task_id: str,
        evidence_hashes: tuple[str, ...],
    ) -> Mapping[str, bytes]:
        if (
            not isinstance(evidence_hashes, tuple)
            or not evidence_hashes
            or len(evidence_hashes) > _MAX_EVIDENCE_RECORDS_PER_TASK
            or len(set(evidence_hashes)) != len(evidence_hashes)
        ):
            raise LearningSchedulerError("SCHEDULER_EVIDENCE_HASHES_INVALID")
        expected: set[str] = set()
        for value in evidence_hashes:
            digest = str(value or "").strip().lower()
            if digest != value or not _SHA.fullmatch(digest):
                raise LearningSchedulerError("SCHEDULER_EVIDENCE_HASHES_INVALID")
            expected.add(digest)

        resolved: dict[str, bytes] = {}
        for raw_path in self._evidence_records(task_id):
            try:
                path = self._trusted_registered_path(
                    raw_path,
                    reason_prefix="SCHEDULER_EVIDENCE",
                )
            except LearningSchedulerError:
                continue
            try:
                size = path.stat().st_size
                if not 1 <= size <= _MAX_EVIDENCE_ITEM_BYTES:
                    continue
                raw = path.read_bytes()
            except OSError:
                continue
            digest = "sha256:" + hashlib.sha256(raw).hexdigest()
            if digest in expected and digest not in resolved:
                resolved[digest] = raw
                if len(resolved) == len(expected):
                    break
        if set(resolved) != expected:
            raise LearningSchedulerError("SCHEDULER_EVIDENCE_NOT_RESOLVED")
        return {digest: resolved[digest] for digest in evidence_hashes}


class AdaptiveLearningScheduler:
    """One bounded scheduler tick. Construction does not start background work."""

    def __init__(
        self,
        config: AdaptiveLearningSchedulerConfig,
        admission: DeterministicLearningAdmission,
        reflection: ReflectionCoordinator,
        source_provider: LocalLearningSourceProvider,
        *,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.config = config.validate()
        self.admission = admission
        self.reflection = reflection
        self.source_provider = source_provider
        self.clock = clock

    @classmethod
    def from_local_runtime(
        cls,
        *,
        config: AdaptiveLearningSchedulerConfig,
        store: TaskStore,
        artifacts: ArtifactManager,
        reflection: ReflectionCoordinator,
        clock: Callable[[], float] = time.monotonic,
    ) -> "AdaptiveLearningScheduler":
        return cls(
            config,
            DeterministicLearningAdmission(store),
            reflection,
            LocalLearningSourceProvider(store, artifacts),
            clock=clock,
        )

    @staticmethod
    def _safe_reason(exc: Exception) -> str:
        if isinstance(
            exc,
            (
                LearningSchedulerError,
                LearningAdmissionError,
                ReflectionError,
                ReflectionContractError,
            ),
        ):
            return exc.reason_code.split(":", 1)[0]
        return "SCHEDULER_SOURCE_PROCESSING_FAILED"

    def _preflight_receipt(
        self,
        envelope: VerifiedLearningSourceEnvelope,
        domain: str,
    ) -> SchedulerItemOutcome | None:
        existing = self.reflection.receipt_store.read(envelope.admission_id, domain)
        if existing is None:
            return None
        if existing.status == "completed":
            return SchedulerItemOutcome(
                task_id=envelope.task_id,
                result="SKIPPED",
                reason_code="REFLECTION_ALREADY_COMPLETED",
                domain=domain,
                admission_id=envelope.admission_id,
                candidate_sha256=existing.candidate_sha256,
            )
        return SchedulerItemOutcome(
            task_id=envelope.task_id,
            result="RECOVERY_REQUIRED",
            reason_code="REFLECTION_CLAIM_RECOVERY_REQUIRED",
            domain=domain,
            admission_id=envelope.admission_id,
        )

    def _process(
        self,
        handle: LearningSourceHandle,
        domain: str,
    ) -> SchedulerItemOutcome:
        envelope: VerifiedLearningSourceEnvelope | None = None
        try:
            manifest_path = self.source_provider.manifest_path(handle)
            envelope = self.admission.admit(handle.task_id, manifest_path)
            if envelope.sensitivity == "secret":
                return SchedulerItemOutcome(
                    task_id=handle.task_id,
                    result="REJECTED",
                    reason_code="REFLECTION_SECRET_NOT_SUPPORTED",
                    domain=domain,
                    admission_id=envelope.admission_id,
                )
            binding = ReflectionDomainBinding.create(
                envelope,
                domain=domain,
                authority_type=self.config.authority_type,
                authority_id=self.config.authority_id,
            )
            preflight = self._preflight_receipt(envelope, domain)
            if preflight is not None:
                return preflight
            evidence = self.source_provider.load_evidence(
                handle.task_id,
                envelope.evidence_hashes,
            )
            outcome = self.reflection.reflect_and_stage(
                envelope,
                binding,
                evidence,
            )
            return SchedulerItemOutcome(
                task_id=handle.task_id,
                result=outcome.result,
                reason_code=None,
                domain=domain,
                admission_id=envelope.admission_id,
                candidate_id=outcome.candidate_id,
                candidate_sha256=outcome.candidate_sha256,
            )
        except LearningAdmissionError as exc:
            return SchedulerItemOutcome(
                task_id=handle.task_id,
                result="REJECTED",
                reason_code=self._safe_reason(exc),
                domain=domain,
                admission_id=(envelope.admission_id if envelope else None),
            )
        except ReflectionError as exc:
            reason = self._safe_reason(exc)
            if reason == "REFLECTION_ALREADY_COMPLETED":
                result = "SKIPPED"
            elif reason == "REFLECTION_CLAIM_RECOVERY_REQUIRED":
                result = "RECOVERY_REQUIRED"
            else:
                result = "FAILED"
            return SchedulerItemOutcome(
                task_id=handle.task_id,
                result=result,
                reason_code=reason,
                domain=domain,
                admission_id=(envelope.admission_id if envelope else None),
            )
        except (LearningSchedulerError, ReflectionContractError) as exc:
            return SchedulerItemOutcome(
                task_id=handle.task_id,
                result="REJECTED",
                reason_code=self._safe_reason(exc),
                domain=domain,
                admission_id=(envelope.admission_id if envelope else None),
            )
        except Exception as exc:
            return SchedulerItemOutcome(
                task_id=handle.task_id,
                result="FAILED",
                reason_code=self._safe_reason(exc),
                domain=domain,
                admission_id=(envelope.admission_id if envelope else None),
            )

    def run_once(self) -> SchedulerRunReceipt:
        started = self.clock()
        if not self.config.enabled:
            return SchedulerRunReceipt(
                enabled=False,
                attempted=0,
                staged=0,
                no_learning_value=0,
                skipped=0,
                recovery_required=0,
                failed=0,
                elapsed_ms=0,
                stop_reason="DISABLED",
                outcomes=(),
            )

        domain_map = self.config.domain_map()
        handles = self.source_provider.discover_done(
            tuple(domain_map),
            limit=self.config.max_scan_items,
        )
        deadline = started + self.config.max_wall_time_seconds
        outcomes: list[SchedulerItemOutcome] = []
        stop_reason = "COMPLETE"

        for handle in handles:
            if len(outcomes) >= self.config.max_items:
                stop_reason = "MAX_ITEMS"
                break
            if self.clock() >= deadline:
                stop_reason = "WALL_TIME"
                break
            domain = domain_map.get(handle.task_id)
            if domain is None:
                continue
            outcomes.append(self._process(handle, domain))

        elapsed_ms = max(0, int((self.clock() - started) * 1000))
        return SchedulerRunReceipt(
            enabled=True,
            attempted=len(outcomes),
            staged=sum(item.result == "STAGED" for item in outcomes),
            no_learning_value=sum(
                item.result == "NO_LEARNING_VALUE" for item in outcomes
            ),
            skipped=sum(item.result == "SKIPPED" for item in outcomes),
            recovery_required=sum(
                item.result == "RECOVERY_REQUIRED" for item in outcomes
            ),
            failed=sum(
                item.result in {"FAILED", "REJECTED"} for item in outcomes
            ),
            elapsed_ms=elapsed_ms,
            stop_reason=stop_reason,
            outcomes=tuple(outcomes),
        )
