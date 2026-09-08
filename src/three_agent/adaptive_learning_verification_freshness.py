"""Deterministic last-verified projection for exact reused adaptive knowledge.

This module closes the timestamp half of Skill lifecycle M-05 only. It reuses the
canonical Phase 4H effectiveness snapshot as the source of authoritative outcome
counts, then derives the latest verified timestamp from existing TaskStore task and
ValidatorLedger metadata. It creates no new telemetry, persistence, learning store,
contradiction store, promotion path, or mutation authority.

A verified timestamp means that an exact knowledge version was present in a task
whose current authoritative outcome is DONE + validator-verified. Confounded and
isolated observations remain separate. The projection is observational and does
not claim causal benefit from the reused knowledge.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from .adaptive_learning_contract import DOMAINS
from .adaptive_learning_effectiveness import (
    INTERPRETATION,
    REUSE_ACTIVITY_ACTION,
    REUSE_ACTIVITY_AGENT,
    DeterministicLearningEffectivenessAnalyzer,
    LearningEffectivenessError,
    LearningReuseReceipt,
)
from .models import TaskStatus
from .store import TaskStore
from .validator_ledger import ValidatorLedger

VERIFICATION_FRESHNESS_SCHEMA = "workspace-learning-verification-freshness/v1"
VERIFICATION_FRESHNESS_SNAPSHOT_SCHEMA = "workspace-learning-verification-freshness-snapshot/v1"
VERIFICATION_FRESHNESS_AUTHORITY = "observational_metadata_only_no_learning_or_runtime_mutation"

_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class LearningVerificationFreshnessError(ValueError):
    """Freshness metadata cannot be projected safely from canonical state."""


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _utc(value: Any, field: str) -> tuple[str, datetime]:
    text = str(value or "").strip()
    if not text:
        raise LearningVerificationFreshnessError(f"VERIFICATION_FRESHNESS_{field.upper()}_INVALID")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError as exc:
        raise LearningVerificationFreshnessError(
            f"VERIFICATION_FRESHNESS_{field.upper()}_INVALID"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise LearningVerificationFreshnessError(
            f"VERIFICATION_FRESHNESS_{field.upper()}_TIMEZONE_REQUIRED"
        )
    normalized = parsed.astimezone(timezone.utc)
    return normalized.isoformat().replace("+00:00", "Z"), normalized


def _identifier(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not _ID.fullmatch(text):
        raise LearningVerificationFreshnessError(
            f"VERIFICATION_FRESHNESS_{field.upper()}_INVALID"
        )
    return text


def _sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise LearningVerificationFreshnessError(
            f"VERIFICATION_FRESHNESS_{field.upper()}_INVALID"
        )
    return text


@dataclass(frozen=True)
class KnowledgeVerificationFreshnessProjection:
    item_id: str
    knowledge_sha256: str
    domain: str
    verified_task_observations: int
    isolated_verified_task_observations: int
    last_verified_at: str | None
    last_isolated_verified_at: str | None
    source_effectiveness_snapshot_sha256: str
    interpretation: str = INTERPRETATION
    authority: str = VERIFICATION_FRESHNESS_AUTHORITY
    schema_version: str = VERIFICATION_FRESHNESS_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority": self.authority,
            "interpretation": self.interpretation,
            "item_id": self.item_id,
            "knowledge_sha256": self.knowledge_sha256,
            "domain": self.domain,
            "verified_task_observations": self.verified_task_observations,
            "isolated_verified_task_observations": self.isolated_verified_task_observations,
            "last_verified_at": self.last_verified_at,
            "last_isolated_verified_at": self.last_isolated_verified_at,
            "source_effectiveness_snapshot_sha256": self.source_effectiveness_snapshot_sha256,
        }

    def validate(self) -> "KnowledgeVerificationFreshnessProjection":
        if self.schema_version != VERIFICATION_FRESHNESS_SCHEMA:
            raise LearningVerificationFreshnessError("VERIFICATION_FRESHNESS_SCHEMA_INVALID")
        if self.authority != VERIFICATION_FRESHNESS_AUTHORITY or self.interpretation != INTERPRETATION:
            raise LearningVerificationFreshnessError("VERIFICATION_FRESHNESS_HEADER_INVALID")
        _identifier(self.item_id, "item_id")
        _sha(self.knowledge_sha256, "knowledge_sha256")
        _sha(self.source_effectiveness_snapshot_sha256, "source_effectiveness_snapshot_sha256")
        if self.domain not in DOMAINS:
            raise LearningVerificationFreshnessError("VERIFICATION_FRESHNESS_DOMAIN_INVALID")
        for value in (
            self.verified_task_observations,
            self.isolated_verified_task_observations,
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise LearningVerificationFreshnessError("VERIFICATION_FRESHNESS_COUNT_INVALID")
        if self.isolated_verified_task_observations > self.verified_task_observations:
            raise LearningVerificationFreshnessError(
                "VERIFICATION_FRESHNESS_ISOLATED_COUNT_EXCEEDS_TOTAL"
            )
        if self.verified_task_observations == 0:
            if self.last_verified_at is not None or self.last_isolated_verified_at is not None:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_EMPTY_TIMESTAMP_INVALID"
                )
        else:
            if self.last_verified_at is None:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_LAST_VERIFIED_REQUIRED"
                )
            canonical, _ = _utc(self.last_verified_at, "last_verified_at")
            if canonical != self.last_verified_at:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_TIMESTAMP_NOT_CANONICAL"
                )
        if self.isolated_verified_task_observations == 0:
            if self.last_isolated_verified_at is not None:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_EMPTY_ISOLATED_TIMESTAMP_INVALID"
                )
        else:
            if self.last_isolated_verified_at is None:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_LAST_ISOLATED_REQUIRED"
                )
            isolated, isolated_dt = _utc(
                self.last_isolated_verified_at,
                "last_isolated_verified_at",
            )
            if isolated != self.last_isolated_verified_at:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_TIMESTAMP_NOT_CANONICAL"
                )
            if self.last_verified_at is None:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_LAST_VERIFIED_REQUIRED"
                )
            _, total_dt = _utc(self.last_verified_at, "last_verified_at")
            if isolated_dt > total_dt:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_ISOLATED_AFTER_TOTAL"
                )
        return self

    @property
    def projection_sha256(self) -> str:
        self.validate()
        return _digest(self._base_payload())

    def to_payload(self) -> dict[str, Any]:
        return {**self._base_payload(), "projection_sha256": self.projection_sha256}


@dataclass(frozen=True)
class LearningVerificationFreshnessSnapshot:
    source_effectiveness_snapshot_sha256: str
    projections: tuple[KnowledgeVerificationFreshnessProjection, ...]
    authority: str = VERIFICATION_FRESHNESS_AUTHORITY
    schema_version: str = VERIFICATION_FRESHNESS_SNAPSHOT_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority": self.authority,
            "source_effectiveness_snapshot_sha256": self.source_effectiveness_snapshot_sha256,
            "projection_count": len(self.projections),
            "projections": [projection.to_payload() for projection in self.projections],
        }

    def validate(self) -> "LearningVerificationFreshnessSnapshot":
        if self.schema_version != VERIFICATION_FRESHNESS_SNAPSHOT_SCHEMA:
            raise LearningVerificationFreshnessError(
                "VERIFICATION_FRESHNESS_SNAPSHOT_SCHEMA_INVALID"
            )
        if self.authority != VERIFICATION_FRESHNESS_AUTHORITY:
            raise LearningVerificationFreshnessError(
                "VERIFICATION_FRESHNESS_SNAPSHOT_AUTHORITY_INVALID"
            )
        _sha(self.source_effectiveness_snapshot_sha256, "source_effectiveness_snapshot_sha256")
        ordered = tuple(
            sorted(
                self.projections,
                key=lambda item: (item.item_id, item.knowledge_sha256, item.domain),
            )
        )
        if ordered != self.projections:
            raise LearningVerificationFreshnessError(
                "VERIFICATION_FRESHNESS_PROJECTIONS_NOT_ORDERED"
            )
        identities: set[tuple[str, str, str]] = set()
        for projection in self.projections:
            projection.validate()
            if projection.source_effectiveness_snapshot_sha256 != self.source_effectiveness_snapshot_sha256:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_SOURCE_BINDING_MISMATCH"
                )
            identity = (projection.item_id, projection.knowledge_sha256, projection.domain)
            if identity in identities:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_DUPLICATE_PROJECTION"
                )
            identities.add(identity)
        return self

    @property
    def snapshot_sha256(self) -> str:
        self.validate()
        return _digest(self._base_payload())

    def to_payload(self) -> dict[str, Any]:
        return {**self._base_payload(), "snapshot_sha256": self.snapshot_sha256}


@dataclass(frozen=True)
class _ReuseObservation:
    receipt: LearningReuseReceipt
    observed_at: datetime


class DeterministicLearningVerificationFreshnessProjector:
    """Project last verified timestamps from canonical Phase 4H + validator state."""

    __slots__ = ("store", "ledger")

    def __init__(self, store: TaskStore) -> None:
        self.store = store
        self.ledger = ValidatorLedger(store)

    def _reuse_observations(self) -> dict[str, list[_ReuseObservation]]:
        with self.store.connect() as conn:
            rows = conn.execute(
                """
                SELECT id, timestamp, task_id, details
                FROM activities
                WHERE agent_id = ? AND action = ?
                ORDER BY id
                """,
                (REUSE_ACTIVITY_AGENT, REUSE_ACTIVITY_ACTION),
            ).fetchall()
        by_task: dict[str, list[_ReuseObservation]] = {}
        by_receipt: dict[str, tuple[LearningReuseReceipt, datetime]] = {}
        for row in rows:
            try:
                receipt = LearningReuseReceipt.from_json(str(row["details"]))
            except LearningEffectivenessError as exc:
                raise LearningVerificationFreshnessError(
                    f"VERIFICATION_FRESHNESS_REUSE_RECEIPT_INVALID:activity_id={int(row['id'])}"
                ) from exc
            if str(row["task_id"] or "") != receipt.task_id:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_REUSE_TASK_LEDGER_MISMATCH"
                )
            _, observed_at = _utc(row["timestamp"], "reuse_observed_at")
            existing = by_receipt.get(receipt.receipt_id)
            if existing is None:
                by_receipt[receipt.receipt_id] = (receipt, observed_at)
            else:
                existing_receipt, earliest = existing
                if existing_receipt != receipt:
                    raise LearningVerificationFreshnessError(
                        "VERIFICATION_FRESHNESS_REUSE_RECEIPT_ID_COLLISION"
                    )
                if observed_at < earliest:
                    by_receipt[receipt.receipt_id] = (receipt, observed_at)
        for receipt, observed_at in by_receipt.values():
            by_task.setdefault(receipt.task_id, []).append(
                _ReuseObservation(receipt=receipt, observed_at=observed_at)
            )
        for task_id in by_task:
            by_task[task_id].sort(key=lambda item: (item.observed_at, item.receipt.receipt_id))
        return by_task

    def _verified_at(self, task_id: str) -> datetime | None:
        task = self.store.get_task(task_id)
        if task.status != TaskStatus.DONE:
            return None
        verification = self.ledger.evaluate(task_id)
        if not verification.verified:
            return None
        rows = self.store.validator_results_for_task(task_id)
        latest: dict[str, Any] = {}
        required = set(verification.required_validators)
        for row in rows:
            name = str(row["validator"])
            if name in required:
                latest[name] = row
        if set(latest) != required:
            raise LearningVerificationFreshnessError(
                "VERIFICATION_FRESHNESS_REQUIRED_VALIDATOR_RESULT_MISSING"
            )
        timestamps: list[datetime] = []
        for name in verification.required_validators:
            row = latest[name]
            if str(row["status"]).strip().lower() != "passed":
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_VERIFIED_STATE_MISMATCH"
                )
            _, stamp = _utc(row["timestamp"], "validator_timestamp")
            timestamps.append(stamp)
        _, task_updated = _utc(task.updated_at, "task_updated_at")
        timestamps.append(task_updated)
        return max(timestamps)

    def snapshot(self) -> LearningVerificationFreshnessSnapshot:
        try:
            effectiveness = DeterministicLearningEffectivenessAnalyzer(self.store).snapshot()
        except LearningEffectivenessError as exc:
            raise LearningVerificationFreshnessError(
                "VERIFICATION_FRESHNESS_EFFECTIVENESS_BLOCKED:" + str(exc)
            ) from exc
        by_task = self._reuse_observations()
        buckets: dict[tuple[str, str, str], dict[str, Any]] = {}

        for task_id in sorted(by_task):
            observations = by_task[task_id]
            refs: dict[tuple[str, str, str], datetime] = {}
            domains_by_item: dict[tuple[str, str], set[str]] = {}
            for observation in observations:
                receipt = observation.receipt
                for item in receipt.items:
                    identity = (item.item_id, item.knowledge_sha256)
                    domains_by_item.setdefault(identity, set()).add(receipt.domain)
                    key = (item.item_id, item.knowledge_sha256, receipt.domain)
                    earliest = refs.get(key)
                    if earliest is None or observation.observed_at < earliest:
                        refs[key] = observation.observed_at
            for domains in domains_by_item.values():
                if len(domains) != 1:
                    raise LearningVerificationFreshnessError(
                        "VERIFICATION_FRESHNESS_REUSE_DOMAIN_CONFLICT"
                    )

            verified_at = self._verified_at(task_id)
            if verified_at is None:
                continue
            confounded = len({(item_id, knowledge_sha) for item_id, knowledge_sha, _ in refs}) > 1
            for key in sorted(refs):
                if verified_at < refs[key]:
                    raise LearningVerificationFreshnessError(
                        "VERIFICATION_FRESHNESS_VERIFICATION_PRECEDES_REUSE"
                    )
                bucket = buckets.setdefault(
                    key,
                    {
                        "verified": 0,
                        "isolated_verified": 0,
                        "last_verified": None,
                        "last_isolated_verified": None,
                    },
                )
                bucket["verified"] += 1
                if bucket["last_verified"] is None or verified_at > bucket["last_verified"]:
                    bucket["last_verified"] = verified_at
                if not confounded:
                    bucket["isolated_verified"] += 1
                    if (
                        bucket["last_isolated_verified"] is None
                        or verified_at > bucket["last_isolated_verified"]
                    ):
                        bucket["last_isolated_verified"] = verified_at

        projections: list[KnowledgeVerificationFreshnessProjection] = []
        source_sha = effectiveness.snapshot_sha256
        for signal in effectiveness.signals:
            key = (signal.item_id, signal.knowledge_sha256, signal.domain)
            bucket = buckets.get(
                key,
                {
                    "verified": 0,
                    "isolated_verified": 0,
                    "last_verified": None,
                    "last_isolated_verified": None,
                },
            )
            if int(bucket["verified"]) != signal.verified_success_after_reuse:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_TOTAL_COUNT_MISMATCH"
                )
            if int(bucket["isolated_verified"]) != signal.isolated_verified_success:
                raise LearningVerificationFreshnessError(
                    "VERIFICATION_FRESHNESS_ISOLATED_COUNT_MISMATCH"
                )
            last_verified = (
                None
                if bucket["last_verified"] is None
                else bucket["last_verified"].astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            )
            last_isolated = (
                None
                if bucket["last_isolated_verified"] is None
                else bucket["last_isolated_verified"].astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
            )
            projections.append(
                KnowledgeVerificationFreshnessProjection(
                    item_id=signal.item_id,
                    knowledge_sha256=signal.knowledge_sha256,
                    domain=signal.domain,
                    verified_task_observations=signal.verified_success_after_reuse,
                    isolated_verified_task_observations=signal.isolated_verified_success,
                    last_verified_at=last_verified,
                    last_isolated_verified_at=last_isolated,
                    source_effectiveness_snapshot_sha256=source_sha,
                ).validate()
            )

        return LearningVerificationFreshnessSnapshot(
            source_effectiveness_snapshot_sha256=source_sha,
            projections=tuple(
                sorted(
                    projections,
                    key=lambda item: (item.item_id, item.knowledge_sha256, item.domain),
                )
            ),
        ).validate()
