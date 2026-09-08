"""Deterministic recommendation-only review policy for stale active skills.

This module is a narrow maintenance adapter over canonical WorkSpace learning
state. It does not create another learning store, registry, effectiveness model,
or mutation path. The policy reads the authenticated adaptive-learning ledger and
canonical exact-version reuse receipts, then recommends human review when an
active skill has not been reused for an operator-owned interval.

Staleness is deliberately different from failure. A frequently reused skill with
bad outcomes is handled by Phase 4H/4I effectiveness curation; this policy only
covers active skills whose exact version has gone unused for too long.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from .adaptive_learning_checkpoint import LearningCheckpointAuthority
from .adaptive_learning_effectiveness import (
    REUSE_ACTIVITY_ACTION,
    REUSE_ACTIVITY_AGENT,
    LearningEffectivenessError,
    LearningReuseReceipt,
)
from .adaptive_learning_store import ACTIVE_LEVELS, AdaptiveLearningStore
from .store import TaskStore

STALE_SKILL_REVIEW_SCHEMA = "workspace-stale-skill-review/v1"
STALE_SKILL_REVIEW_RECEIPT_SCHEMA = "workspace-stale-skill-review-receipt/v1"
STALE_SKILL_REVIEW_AUTHORITY = "recommendation_only_no_learning_or_runtime_mutation"

STATUS_DISABLED = "DISABLED"
STATUS_NO_STALE_SKILLS = "NO_STALE_SKILLS"
STATUS_REVIEWS_READY = "REVIEWS_READY"
STATUS_ACTIVE_SKILL_LIMIT_EXCEEDED = "ACTIVE_SKILL_LIMIT_EXCEEDED"
STATUS_REUSE_RECEIPT_LIMIT_EXCEEDED = "REUSE_RECEIPT_LIMIT_EXCEEDED"

RECOMMENDATION_TYPE = "stale_skill_review"

_MAX_ACTIVE_SKILLS = 128
_MAX_REUSE_RECEIPTS = 10_000
_MAX_STALE_DAYS = 3650
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REASON = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_REVIEW_ID = re.compile(r"^stale-review:[0-9a-f]{64}$")
_ACTIVE_EVENTS = frozenset({"activate", "enterprise", "rollback"})


class StaleSkillReviewError(ValueError):
    """Current stale-review inputs cannot be trusted or bounded safely."""


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _identifier(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not _ID.fullmatch(text):
        raise StaleSkillReviewError(f"STALE_SKILL_{field.upper()}_INVALID")
    return text


def _sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise StaleSkillReviewError(f"STALE_SKILL_{field.upper()}_INVALID")
    return text


def _utc(value: Any, field: str) -> tuple[str, datetime]:
    text = str(value or "").strip()
    if not text:
        raise StaleSkillReviewError(f"STALE_SKILL_{field.upper()}_INVALID")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    except ValueError as exc:
        raise StaleSkillReviewError(f"STALE_SKILL_{field.upper()}_INVALID") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timezone.utc.utcoffset(parsed):
        raise StaleSkillReviewError(f"STALE_SKILL_{field.upper()}_NOT_UTC")
    normalized = parsed.astimezone(timezone.utc)
    canonical = normalized.isoformat().replace("+00:00", "Z")
    return canonical, normalized


@dataclass(frozen=True)
class StaleSkillReviewConfig:
    """Operator-owned bounds for one deterministic stale-skill scan."""

    enabled: bool = False
    stale_after_days: int = 90
    max_active_skills: int = 64
    max_reuse_receipts: int = 2048

    def validate(self) -> "StaleSkillReviewConfig":
        if not isinstance(self.enabled, bool):
            raise StaleSkillReviewError("STALE_SKILL_ENABLED_INVALID")
        if (
            not isinstance(self.stale_after_days, int)
            or isinstance(self.stale_after_days, bool)
            or not 1 <= self.stale_after_days <= _MAX_STALE_DAYS
        ):
            raise StaleSkillReviewError("STALE_SKILL_DAYS_INVALID")
        if (
            not isinstance(self.max_active_skills, int)
            or isinstance(self.max_active_skills, bool)
            or not 1 <= self.max_active_skills <= _MAX_ACTIVE_SKILLS
        ):
            raise StaleSkillReviewError("STALE_SKILL_ACTIVE_LIMIT_INVALID")
        if (
            not isinstance(self.max_reuse_receipts, int)
            or isinstance(self.max_reuse_receipts, bool)
            or not 1 <= self.max_reuse_receipts <= _MAX_REUSE_RECEIPTS
        ):
            raise StaleSkillReviewError("STALE_SKILL_REUSE_LIMIT_INVALID")
        return self


@dataclass(frozen=True)
class StaleSkillReviewRecommendation:
    review_id: str
    item_id: str
    knowledge_sha256: str
    candidate_sha256: str
    active_level: str
    domain: str
    activated_at: str
    last_reuse_at: str | None
    freshness_anchor_at: str
    as_of: str
    stale_after_days: int
    age_seconds: int
    human_review_required: bool
    domain_review_required: bool
    reason_codes: tuple[str, ...]
    recommendation_type: str = RECOMMENDATION_TYPE
    authority: str = STALE_SKILL_REVIEW_AUTHORITY
    schema_version: str = STALE_SKILL_REVIEW_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("review_id", None)
        payload["reason_codes"] = list(self.reason_codes)
        return payload

    @classmethod
    def create(
        cls,
        *,
        item_id: str,
        knowledge_sha256: str,
        candidate_sha256: str,
        active_level: str,
        domain: str,
        activated_at: str,
        last_reuse_at: str | None,
        freshness_anchor_at: str,
        as_of: str,
        stale_after_days: int,
        age_seconds: int,
    ) -> "StaleSkillReviewRecommendation":
        domain_review = domain in {"network", "security"}
        reasons = [
            "STALE_SKILL_REVIEW_REQUIRED",
            "NO_REUSE_SINCE_ACTIVATION" if last_reuse_at is None else "REUSE_AGE_THRESHOLD_EXCEEDED",
            f"ACTIVE_LEVEL_{active_level.upper()}",
            "HUMAN_REVIEW_REQUIRED",
        ]
        if domain_review:
            reasons.append("DOMAIN_REVIEW_REQUIRED")
        draft = cls(
            review_id="stale-review:" + "0" * 64,
            item_id=item_id,
            knowledge_sha256=knowledge_sha256,
            candidate_sha256=candidate_sha256,
            active_level=active_level,
            domain=domain,
            activated_at=activated_at,
            last_reuse_at=last_reuse_at,
            freshness_anchor_at=freshness_anchor_at,
            as_of=as_of,
            stale_after_days=stale_after_days,
            age_seconds=age_seconds,
            human_review_required=True,
            domain_review_required=domain_review,
            reason_codes=tuple(reasons),
        )
        review_id = "stale-review:" + hashlib.sha256(
            _canonical(draft._base_payload()).encode("utf-8")
        ).hexdigest()
        return cls(review_id=review_id, **{k: v for k, v in asdict(draft).items() if k != "review_id"}).validate()

    def validate(self) -> "StaleSkillReviewRecommendation":
        if self.schema_version != STALE_SKILL_REVIEW_SCHEMA:
            raise StaleSkillReviewError("STALE_SKILL_REVIEW_SCHEMA_INVALID")
        if self.authority != STALE_SKILL_REVIEW_AUTHORITY or self.recommendation_type != RECOMMENDATION_TYPE:
            raise StaleSkillReviewError("STALE_SKILL_REVIEW_AUTHORITY_INVALID")
        _identifier(self.item_id, "item_id")
        _sha(self.knowledge_sha256, "knowledge_sha256")
        _sha(self.candidate_sha256, "candidate_sha256")
        if self.active_level not in ACTIVE_LEVELS:
            raise StaleSkillReviewError("STALE_SKILL_ACTIVE_LEVEL_INVALID")
        if not _ID.fullmatch(self.domain):
            raise StaleSkillReviewError("STALE_SKILL_DOMAIN_INVALID")
        activated, activated_dt = _utc(self.activated_at, "activated_at")
        anchor, anchor_dt = _utc(self.freshness_anchor_at, "freshness_anchor_at")
        as_of, as_of_dt = _utc(self.as_of, "as_of")
        if activated != self.activated_at or anchor != self.freshness_anchor_at or as_of != self.as_of:
            raise StaleSkillReviewError("STALE_SKILL_TIMESTAMP_NOT_CANONICAL")
        if self.last_reuse_at is not None:
            last_reuse, last_reuse_dt = _utc(self.last_reuse_at, "last_reuse_at")
            if last_reuse != self.last_reuse_at:
                raise StaleSkillReviewError("STALE_SKILL_TIMESTAMP_NOT_CANONICAL")
            if last_reuse_dt < activated_dt:
                raise StaleSkillReviewError("STALE_SKILL_REUSE_PRECEDES_ACTIVATION")
            if anchor_dt != last_reuse_dt:
                raise StaleSkillReviewError("STALE_SKILL_FRESHNESS_ANCHOR_INVALID")
        elif anchor_dt != activated_dt:
            raise StaleSkillReviewError("STALE_SKILL_FRESHNESS_ANCHOR_INVALID")
        if as_of_dt < anchor_dt:
            raise StaleSkillReviewError("STALE_SKILL_AS_OF_PRECEDES_FRESHNESS")
        if (
            not isinstance(self.stale_after_days, int)
            or isinstance(self.stale_after_days, bool)
            or not 1 <= self.stale_after_days <= _MAX_STALE_DAYS
        ):
            raise StaleSkillReviewError("STALE_SKILL_DAYS_INVALID")
        if not isinstance(self.age_seconds, int) or isinstance(self.age_seconds, bool) or self.age_seconds < 0:
            raise StaleSkillReviewError("STALE_SKILL_AGE_INVALID")
        actual_age = int((as_of_dt - anchor_dt).total_seconds())
        if actual_age != self.age_seconds or actual_age < self.stale_after_days * 86400:
            raise StaleSkillReviewError("STALE_SKILL_AGE_THRESHOLD_INVALID")
        if not self.human_review_required:
            raise StaleSkillReviewError("STALE_SKILL_HUMAN_REVIEW_REQUIRED")
        if self.domain_review_required != (self.domain in {"network", "security"}):
            raise StaleSkillReviewError("STALE_SKILL_DOMAIN_REVIEW_INVALID")
        if not self.reason_codes or len(self.reason_codes) > 8 or len(set(self.reason_codes)) != len(self.reason_codes):
            raise StaleSkillReviewError("STALE_SKILL_REASON_CODES_INVALID")
        for code in self.reason_codes:
            if not _REASON.fullmatch(code):
                raise StaleSkillReviewError("STALE_SKILL_REASON_CODE_INVALID")
        expected = "stale-review:" + hashlib.sha256(
            _canonical(self._base_payload()).encode("utf-8")
        ).hexdigest()
        if not _REVIEW_ID.fullmatch(self.review_id) or self.review_id != expected:
            raise StaleSkillReviewError("STALE_SKILL_REVIEW_ID_INVALID")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {"review_id": self.review_id, **self._base_payload()}


@dataclass(frozen=True)
class StaleSkillReviewReceipt:
    enabled: bool
    status: str
    as_of: str | None
    stale_after_days: int
    scanned_active_skills: int
    scanned_reuse_receipts: int
    emitted_reviews: int
    source_fingerprint: str | None
    checkpoint_sequence: int | None
    checkpoint_sha256: str | None
    state_sha256: str | None
    reviews: tuple[StaleSkillReviewRecommendation, ...]
    authority: str = STALE_SKILL_REVIEW_AUTHORITY
    schema_version: str = STALE_SKILL_REVIEW_RECEIPT_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority": self.authority,
            "enabled": self.enabled,
            "status": self.status,
            "as_of": self.as_of,
            "stale_after_days": self.stale_after_days,
            "scanned_active_skills": self.scanned_active_skills,
            "scanned_reuse_receipts": self.scanned_reuse_receipts,
            "emitted_reviews": self.emitted_reviews,
            "source_fingerprint": self.source_fingerprint,
            "checkpoint_sequence": self.checkpoint_sequence,
            "checkpoint_sha256": self.checkpoint_sha256,
            "state_sha256": self.state_sha256,
            "reviews": [review.to_payload() for review in self.reviews],
        }

    @property
    def receipt_sha256(self) -> str:
        self.validate()
        return _digest(self._base_payload())

    def validate(self) -> "StaleSkillReviewReceipt":
        if self.schema_version != STALE_SKILL_REVIEW_RECEIPT_SCHEMA or self.authority != STALE_SKILL_REVIEW_AUTHORITY:
            raise StaleSkillReviewError("STALE_SKILL_RECEIPT_HEADER_INVALID")
        if self.status not in {
            STATUS_DISABLED,
            STATUS_NO_STALE_SKILLS,
            STATUS_REVIEWS_READY,
            STATUS_ACTIVE_SKILL_LIMIT_EXCEEDED,
            STATUS_REUSE_RECEIPT_LIMIT_EXCEEDED,
        }:
            raise StaleSkillReviewError("STALE_SKILL_RECEIPT_STATUS_INVALID")
        for value, field in (
            (self.stale_after_days, "stale_after_days"),
            (self.scanned_active_skills, "scanned_active_skills"),
            (self.scanned_reuse_receipts, "scanned_reuse_receipts"),
            (self.emitted_reviews, "emitted_reviews"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise StaleSkillReviewError(f"STALE_SKILL_RECEIPT_{field.upper()}_INVALID")
        if self.emitted_reviews != len(self.reviews):
            raise StaleSkillReviewError("STALE_SKILL_RECEIPT_REVIEW_COUNT_MISMATCH")
        for review in self.reviews:
            review.validate()

        if self.status == STATUS_DISABLED:
            if self.enabled or self.as_of is not None or self.reviews or self.scanned_active_skills or self.scanned_reuse_receipts:
                raise StaleSkillReviewError("STALE_SKILL_DISABLED_RECEIPT_INVALID")
            if any(value is not None for value in (
                self.source_fingerprint,
                self.checkpoint_sequence,
                self.checkpoint_sha256,
                self.state_sha256,
            )):
                raise StaleSkillReviewError("STALE_SKILL_DISABLED_RECEIPT_INVALID")
            return self

        if not self.enabled or self.as_of is None:
            raise StaleSkillReviewError("STALE_SKILL_ENABLED_RECEIPT_INVALID")
        as_of, _ = _utc(self.as_of, "as_of")
        if as_of != self.as_of:
            raise StaleSkillReviewError("STALE_SKILL_TIMESTAMP_NOT_CANONICAL")
        if self.source_fingerprint is None or not _SHA.fullmatch(self.source_fingerprint):
            raise StaleSkillReviewError("STALE_SKILL_SOURCE_FINGERPRINT_INVALID")
        if not isinstance(self.checkpoint_sequence, int) or self.checkpoint_sequence < 1:
            raise StaleSkillReviewError("STALE_SKILL_CHECKPOINT_INVALID")
        if self.checkpoint_sha256 is None or not _SHA.fullmatch(self.checkpoint_sha256):
            raise StaleSkillReviewError("STALE_SKILL_CHECKPOINT_INVALID")
        if self.state_sha256 is None or not _SHA.fullmatch(self.state_sha256):
            raise StaleSkillReviewError("STALE_SKILL_STATE_INVALID")
        if self.status in {STATUS_ACTIVE_SKILL_LIMIT_EXCEEDED, STATUS_REUSE_RECEIPT_LIMIT_EXCEEDED}:
            if self.reviews:
                raise StaleSkillReviewError("STALE_SKILL_LIMIT_RECEIPT_INVALID")
            return self
        if self.status == STATUS_NO_STALE_SKILLS and self.reviews:
            raise StaleSkillReviewError("STALE_SKILL_NO_REVIEW_RECEIPT_INVALID")
        if self.status == STATUS_REVIEWS_READY and not self.reviews:
            raise StaleSkillReviewError("STALE_SKILL_READY_RECEIPT_INVALID")
        return self

    def to_payload(self) -> dict[str, Any]:
        return {**self._base_payload(), "receipt_sha256": self.receipt_sha256}


class DeterministicStaleSkillReviewAdvisor:
    """Bounded exact-version stale-skill review with zero mutation authority."""

    __slots__ = ("config", "task_store", "learning_store", "authority")

    def __init__(
        self,
        config: StaleSkillReviewConfig,
        task_store: TaskStore,
        learning_store: AdaptiveLearningStore,
        authority: LearningCheckpointAuthority,
    ) -> None:
        self.config = config.validate()
        self.task_store = task_store
        self.learning_store = learning_store
        self.authority = authority

    def _disabled(self) -> StaleSkillReviewReceipt:
        return StaleSkillReviewReceipt(
            enabled=False,
            status=STATUS_DISABLED,
            as_of=None,
            stale_after_days=self.config.stale_after_days,
            scanned_active_skills=0,
            scanned_reuse_receipts=0,
            emitted_reviews=0,
            source_fingerprint=None,
            checkpoint_sequence=None,
            checkpoint_sha256=None,
            state_sha256=None,
            reviews=(),
        ).validate()

    @staticmethod
    def _checkpoint_unchanged(before: Any, after: Any) -> None:
        if (
            before.sequence != after.sequence
            or before.checkpoint_sha256 != after.checkpoint_sha256
            or before.state_sha256 != after.state_sha256
        ):
            raise StaleSkillReviewError("STALE_SKILL_CHECKPOINT_CHANGED")

    def _reuse_count(self) -> int:
        with self.task_store.connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) AS n FROM activities WHERE agent_id=? AND action=?",
                (REUSE_ACTIVITY_AGENT, REUSE_ACTIVITY_ACTION),
            ).fetchone()
        return int(row["n"])

    def _last_reuse_by_version(self) -> tuple[int, dict[tuple[str, str], str]]:
        with self.task_store.connect() as conn:
            rows = conn.execute(
                """
                SELECT id,timestamp,task_id,details
                FROM activities
                WHERE agent_id=? AND action=?
                ORDER BY id
                """,
                (REUSE_ACTIVITY_AGENT, REUSE_ACTIVITY_ACTION),
            ).fetchall()
        latest: dict[tuple[str, str], tuple[datetime, str]] = {}
        for row in rows:
            try:
                receipt = LearningReuseReceipt.from_json(str(row["details"]))
            except LearningEffectivenessError as exc:
                raise StaleSkillReviewError(
                    f"STALE_SKILL_REUSE_RECEIPT_INVALID:activity_id={int(row['id'])}"
                ) from exc
            if str(row["task_id"] or "") != receipt.task_id:
                raise StaleSkillReviewError("STALE_SKILL_REUSE_TASK_MISMATCH")
            observed_at, observed_dt = _utc(row["timestamp"], "reuse_timestamp")
            for item in receipt.items:
                key = (item.item_id, item.knowledge_sha256)
                current = latest.get(key)
                if current is None or observed_dt > current[0]:
                    latest[key] = (observed_dt, observed_at)
        return len(rows), {key: value[1] for key, value in latest.items()}

    def _active_skills(self, ledger: list[dict[str, Any]]) -> list[dict[str, Any]]:
        skills: list[dict[str, Any]] = []
        for item_id in sorted({str(row.get("item_id") or "") for row in ledger if row.get("item_id")}):
            active = self.learning_store.active(item_id)
            if active is None:
                continue
            candidate = active.get("candidate")
            if not isinstance(candidate, dict) or str(candidate.get("kind") or "") != "skill":
                continue
            skills.append(active)
        return skills

    @staticmethod
    def _activation_for(
        ledger: list[dict[str, Any]],
        *,
        item_id: str,
        knowledge_sha256: str,
    ) -> str:
        for event in reversed(ledger):
            if (
                str(event.get("item_id") or "") == item_id
                and str(event.get("event_type") or "") in _ACTIVE_EVENTS
                and str(event.get("after_sha256") or "") == knowledge_sha256
            ):
                timestamp, _ = _utc(event.get("timestamp"), "activation_timestamp")
                return timestamp
        raise StaleSkillReviewError("STALE_SKILL_ACTIVATION_EVENT_MISSING")

    def _limit_receipt(
        self,
        *,
        status: str,
        as_of: str,
        before: Any,
        active_count: int,
        reuse_count: int,
        source_fingerprint: str,
    ) -> StaleSkillReviewReceipt:
        after = self.authority.verify(self.learning_store)
        self._checkpoint_unchanged(before, after)
        return StaleSkillReviewReceipt(
            enabled=True,
            status=status,
            as_of=as_of,
            stale_after_days=self.config.stale_after_days,
            scanned_active_skills=active_count,
            scanned_reuse_receipts=reuse_count,
            emitted_reviews=0,
            source_fingerprint=source_fingerprint,
            checkpoint_sequence=before.sequence,
            checkpoint_sha256=before.checkpoint_sha256,
            state_sha256=before.state_sha256,
            reviews=(),
        ).validate()

    def run_once(self, *, as_of: str | None = None) -> StaleSkillReviewReceipt:
        if not self.config.enabled:
            return self._disabled()
        if as_of is None:
            raise StaleSkillReviewError("STALE_SKILL_AS_OF_REQUIRED")
        canonical_as_of, as_of_dt = _utc(as_of, "as_of")

        before = self.authority.verify(self.learning_store)
        ledger_verification = self.learning_store.verify_ledger()
        if not bool(ledger_verification.get("passed")):
            raise StaleSkillReviewError("STALE_SKILL_LEDGER_INTEGRITY_FAILED")
        ledger = self.learning_store.ledger()
        active_skills = self._active_skills(ledger)
        active_count = len(active_skills)
        if active_count > self.config.max_active_skills:
            source = _digest(
                {
                    "status": STATUS_ACTIVE_SKILL_LIMIT_EXCEEDED,
                    "active_skill_count": active_count,
                    "ledger_head_sha256": ledger_verification.get("head_sha256"),
                    "as_of": canonical_as_of,
                }
            )
            return self._limit_receipt(
                status=STATUS_ACTIVE_SKILL_LIMIT_EXCEEDED,
                as_of=canonical_as_of,
                before=before,
                active_count=active_count,
                reuse_count=0,
                source_fingerprint=source,
            )

        reuse_count = self._reuse_count()
        if reuse_count > self.config.max_reuse_receipts:
            source = _digest(
                {
                    "status": STATUS_REUSE_RECEIPT_LIMIT_EXCEEDED,
                    "active_skill_count": active_count,
                    "reuse_receipt_count": reuse_count,
                    "ledger_head_sha256": ledger_verification.get("head_sha256"),
                    "as_of": canonical_as_of,
                }
            )
            return self._limit_receipt(
                status=STATUS_REUSE_RECEIPT_LIMIT_EXCEEDED,
                as_of=canonical_as_of,
                before=before,
                active_count=active_count,
                reuse_count=reuse_count,
                source_fingerprint=source,
            )

        parsed_reuse_count, last_reuse = self._last_reuse_by_version()
        if parsed_reuse_count != reuse_count:
            raise StaleSkillReviewError("STALE_SKILL_REUSE_COUNT_CHANGED")

        threshold_seconds = self.config.stale_after_days * 86400
        source_rows: list[dict[str, Any]] = []
        reviews: list[StaleSkillReviewRecommendation] = []
        for active in sorted(active_skills, key=lambda row: (str(row["item_id"]), str(row["knowledge_sha256"]))):
            item_id = _identifier(active.get("item_id"), "item_id")
            knowledge_sha = _sha(active.get("knowledge_sha256"), "knowledge_sha256")
            candidate_sha = _sha(active.get("candidate_sha256"), "candidate_sha256")
            level = str(active.get("level") or "").strip()
            if level not in ACTIVE_LEVELS:
                raise StaleSkillReviewError("STALE_SKILL_ACTIVE_LEVEL_INVALID")
            candidate = active.get("candidate")
            if not isinstance(candidate, dict):
                raise StaleSkillReviewError("STALE_SKILL_CANDIDATE_INVALID")
            domain = _identifier(candidate.get("domain"), "domain")
            activated_at = self._activation_for(
                ledger,
                item_id=item_id,
                knowledge_sha256=knowledge_sha,
            )
            _, activated_dt = _utc(activated_at, "activated_at")
            last_reuse_at = last_reuse.get((item_id, knowledge_sha))
            if last_reuse_at is None:
                anchor_at, anchor_dt = activated_at, activated_dt
            else:
                anchor_at, anchor_dt = _utc(last_reuse_at, "last_reuse_at")
                if anchor_dt < activated_dt:
                    raise StaleSkillReviewError("STALE_SKILL_REUSE_PRECEDES_ACTIVATION")
            if as_of_dt < anchor_dt:
                raise StaleSkillReviewError("STALE_SKILL_AS_OF_PRECEDES_FRESHNESS")
            age_seconds = int((as_of_dt - anchor_dt).total_seconds())
            source_rows.append(
                {
                    "item_id": item_id,
                    "knowledge_sha256": knowledge_sha,
                    "candidate_sha256": candidate_sha,
                    "active_level": level,
                    "domain": domain,
                    "activated_at": activated_at,
                    "last_reuse_at": last_reuse_at,
                    "freshness_anchor_at": anchor_at,
                    "age_seconds": age_seconds,
                }
            )
            if age_seconds >= threshold_seconds:
                reviews.append(
                    StaleSkillReviewRecommendation.create(
                        item_id=item_id,
                        knowledge_sha256=knowledge_sha,
                        candidate_sha256=candidate_sha,
                        active_level=level,
                        domain=domain,
                        activated_at=activated_at,
                        last_reuse_at=last_reuse_at,
                        freshness_anchor_at=anchor_at,
                        as_of=canonical_as_of,
                        stale_after_days=self.config.stale_after_days,
                        age_seconds=age_seconds,
                    )
                )

        source_fingerprint = _digest(
            {
                "schema_version": STALE_SKILL_REVIEW_RECEIPT_SCHEMA,
                "as_of": canonical_as_of,
                "stale_after_days": self.config.stale_after_days,
                "ledger_head_sha256": ledger_verification.get("head_sha256"),
                "reuse_receipt_count": reuse_count,
                "active_skills": source_rows,
            }
        )
        after = self.authority.verify(self.learning_store)
        self._checkpoint_unchanged(before, after)
        status = STATUS_REVIEWS_READY if reviews else STATUS_NO_STALE_SKILLS
        return StaleSkillReviewReceipt(
            enabled=True,
            status=status,
            as_of=canonical_as_of,
            stale_after_days=self.config.stale_after_days,
            scanned_active_skills=active_count,
            scanned_reuse_receipts=reuse_count,
            emitted_reviews=len(reviews),
            source_fingerprint=source_fingerprint,
            checkpoint_sequence=before.sequence,
            checkpoint_sha256=before.checkpoint_sha256,
            state_sha256=before.state_sha256,
            reviews=tuple(sorted(reviews, key=lambda item: (item.item_id, item.knowledge_sha256))),
        ).validate()
