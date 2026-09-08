"""Recommendation-only quarantine projection over canonical maintenance receipts.

M-07 closes the remaining skill-maintenance recommendation gap without creating a
quarantine store or a mutation path. Only canonical domain revision/retirement
review recommendations can project to a proposed ``quarantined`` disposition, and
the projection is rebound to the current authenticated learning checkpoint and
exact active knowledge version before it is emitted.

A quarantine recommendation is advisory. This module cannot archive, disable,
rollback, promote, supersede, materialize, invoke tools/models, access credentials,
or mutate runtime/learning state.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, replace
from typing import Any

from .adaptive_learning_checkpoint import LearningCheckpointAuthority
from .adaptive_learning_maintenance import (
    STATUS_RECOMMENDATIONS_READY,
    TYPE_DOMAIN_REVISION_OR_RETIREMENT_REVIEW,
    AdaptiveLearningMaintenanceReceipt,
    AdaptiveMaintenanceRecommendation,
)
from .adaptive_learning_store import ACTIVE_LEVELS, AdaptiveLearningStore

QUARANTINE_RECOMMENDATION_SCHEMA = "workspace-learning-quarantine-recommendation/v1"
QUARANTINE_RECOMMENDATION_SET_SCHEMA = "workspace-learning-quarantine-recommendation-set/v1"
QUARANTINE_AUTHORITY = "recommendation_only_no_learning_or_runtime_mutation"
RECOMMENDED_DISPOSITION = "quarantined"
STATUS_NO_RECOMMENDATIONS = "NO_QUARANTINE_RECOMMENDATIONS"
STATUS_RECOMMENDATIONS_READY = "QUARANTINE_RECOMMENDATIONS_READY"

_MAX_RECOMMENDATIONS = 128
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REASON = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_RECOMMENDATION_ID = re.compile(r"^quarantine-review:[0-9a-f]{64}$")


class AdaptiveLearningQuarantineError(ValueError):
    """Quarantine recommendation inputs cannot be trusted safely."""


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _require_id(value: Any, *, field: str) -> str:
    text = str(value or "").strip()
    if not _ID.fullmatch(text):
        raise AdaptiveLearningQuarantineError(f"QUARANTINE_{field.upper()}_INVALID")
    return text


def _require_sha(value: Any, *, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise AdaptiveLearningQuarantineError(f"QUARANTINE_{field.upper()}_INVALID")
    return text


@dataclass(frozen=True)
class QuarantineReviewRecommendation:
    recommendation_id: str
    source_maintenance_receipt_sha256: str
    source_proposal_id: str
    item_id: str
    knowledge_sha256: str
    candidate_sha256: str
    active_level: str
    domain: str
    advisory_signal: str
    curation_action: str
    recommended_disposition: str
    human_review_required: bool
    domain_review_required: bool
    reason_codes: tuple[str, ...]
    authority: str = QUARANTINE_AUTHORITY
    schema_version: str = QUARANTINE_RECOMMENDATION_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("recommendation_id", None)
        payload["reason_codes"] = list(self.reason_codes)
        return payload

    @classmethod
    def create(
        cls,
        *,
        source_receipt_sha256: str,
        source: AdaptiveMaintenanceRecommendation,
    ) -> "QuarantineReviewRecommendation":
        source.validate()
        if source.recommendation_type != TYPE_DOMAIN_REVISION_OR_RETIREMENT_REVIEW:
            raise AdaptiveLearningQuarantineError("QUARANTINE_SOURCE_NOT_DOMAIN_REVIEW")
        if not source.human_review_required or not source.domain_review_required:
            raise AdaptiveLearningQuarantineError("QUARANTINE_REVIEW_REQUIREMENT_MISSING")
        if source.domain not in {"network", "security"}:
            raise AdaptiveLearningQuarantineError("QUARANTINE_DOMAIN_NOT_SENSITIVE")

        reasons = (
            "DOMAIN_REVISION_OR_RETIREMENT_REVIEW",
            "QUARANTINE_RECOMMENDED",
            "HUMAN_REVIEW_REQUIRED",
            "DOMAIN_REVIEW_REQUIRED",
            "OPERATOR_DECISION_REQUIRED",
        )
        draft = cls(
            recommendation_id="quarantine-review:" + "0" * 64,
            source_maintenance_receipt_sha256=source_receipt_sha256,
            source_proposal_id=source.proposal_id,
            item_id=source.item_id,
            knowledge_sha256=source.knowledge_sha256,
            candidate_sha256=source.candidate_sha256,
            active_level=source.active_level,
            domain=source.domain,
            advisory_signal=source.advisory_signal,
            curation_action=source.curation_action,
            recommended_disposition=RECOMMENDED_DISPOSITION,
            human_review_required=True,
            domain_review_required=True,
            reason_codes=reasons,
        )
        recommendation_id = "quarantine-review:" + hashlib.sha256(
            _canonical(draft._base_payload()).encode("utf-8")
        ).hexdigest()
        return replace(draft, recommendation_id=recommendation_id).validate()

    def validate(self) -> "QuarantineReviewRecommendation":
        if self.schema_version != QUARANTINE_RECOMMENDATION_SCHEMA:
            raise AdaptiveLearningQuarantineError("QUARANTINE_SCHEMA_INVALID")
        if self.authority != QUARANTINE_AUTHORITY:
            raise AdaptiveLearningQuarantineError("QUARANTINE_AUTHORITY_INVALID")
        if self.recommended_disposition != RECOMMENDED_DISPOSITION:
            raise AdaptiveLearningQuarantineError("QUARANTINE_DISPOSITION_INVALID")
        _require_sha(self.source_maintenance_receipt_sha256, field="source_receipt_sha256")
        if not str(self.source_proposal_id or "").startswith("curation:"):
            raise AdaptiveLearningQuarantineError("QUARANTINE_PROPOSAL_ID_INVALID")
        _require_id(self.item_id, field="item_id")
        _require_sha(self.knowledge_sha256, field="knowledge_sha256")
        _require_sha(self.candidate_sha256, field="candidate_sha256")
        if self.active_level not in ACTIVE_LEVELS:
            raise AdaptiveLearningQuarantineError("QUARANTINE_ACTIVE_LEVEL_INVALID")
        if self.domain not in {"network", "security"}:
            raise AdaptiveLearningQuarantineError("QUARANTINE_DOMAIN_NOT_SENSITIVE")
        if not self.human_review_required or not self.domain_review_required:
            raise AdaptiveLearningQuarantineError("QUARANTINE_REVIEW_REQUIREMENT_MISSING")
        if not self.reason_codes or len(self.reason_codes) > 8:
            raise AdaptiveLearningQuarantineError("QUARANTINE_REASON_CODES_INVALID")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise AdaptiveLearningQuarantineError("QUARANTINE_REASON_CODES_DUPLICATE")
        for code in self.reason_codes:
            if not _REASON.fullmatch(code):
                raise AdaptiveLearningQuarantineError("QUARANTINE_REASON_CODE_INVALID")
        expected = "quarantine-review:" + hashlib.sha256(
            _canonical(self._base_payload()).encode("utf-8")
        ).hexdigest()
        if not _RECOMMENDATION_ID.fullmatch(self.recommendation_id) or self.recommendation_id != expected:
            raise AdaptiveLearningQuarantineError("QUARANTINE_RECOMMENDATION_ID_INVALID")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {"recommendation_id": self.recommendation_id, **self._base_payload()}


@dataclass(frozen=True)
class QuarantineRecommendationSet:
    status: str
    source_maintenance_receipt_sha256: str
    checkpoint_sequence: int
    checkpoint_sha256: str
    state_sha256: str
    recommendations: tuple[QuarantineReviewRecommendation, ...]
    authority: str = QUARANTINE_AUTHORITY
    schema_version: str = QUARANTINE_RECOMMENDATION_SET_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority": self.authority,
            "status": self.status,
            "source_maintenance_receipt_sha256": self.source_maintenance_receipt_sha256,
            "checkpoint_sequence": self.checkpoint_sequence,
            "checkpoint_sha256": self.checkpoint_sha256,
            "state_sha256": self.state_sha256,
            "recommendations": [row.to_payload() for row in self.recommendations],
        }

    @property
    def recommendation_set_sha256(self) -> str:
        self.validate()
        return _digest(self._base_payload())

    def validate(self) -> "QuarantineRecommendationSet":
        if self.schema_version != QUARANTINE_RECOMMENDATION_SET_SCHEMA:
            raise AdaptiveLearningQuarantineError("QUARANTINE_SET_SCHEMA_INVALID")
        if self.authority != QUARANTINE_AUTHORITY:
            raise AdaptiveLearningQuarantineError("QUARANTINE_SET_AUTHORITY_INVALID")
        if self.status not in {STATUS_NO_RECOMMENDATIONS, STATUS_RECOMMENDATIONS_READY}:
            raise AdaptiveLearningQuarantineError("QUARANTINE_SET_STATUS_INVALID")
        _require_sha(self.source_maintenance_receipt_sha256, field="source_receipt_sha256")
        if not isinstance(self.checkpoint_sequence, int) or isinstance(self.checkpoint_sequence, bool) or self.checkpoint_sequence < 1:
            raise AdaptiveLearningQuarantineError("QUARANTINE_SET_CHECKPOINT_INVALID")
        _require_sha(self.checkpoint_sha256, field="checkpoint_sha256")
        _require_sha(self.state_sha256, field="state_sha256")
        if len(self.recommendations) > _MAX_RECOMMENDATIONS:
            raise AdaptiveLearningQuarantineError("QUARANTINE_RECOMMENDATION_LIMIT_EXCEEDED")
        ordered = tuple(
            sorted(
                self.recommendations,
                key=lambda row: (row.item_id, row.knowledge_sha256, row.recommendation_id),
            )
        )
        if ordered != self.recommendations:
            raise AdaptiveLearningQuarantineError("QUARANTINE_RECOMMENDATIONS_NOT_SORTED")
        if len({row.recommendation_id for row in self.recommendations}) != len(self.recommendations):
            raise AdaptiveLearningQuarantineError("QUARANTINE_RECOMMENDATION_DUPLICATE")
        for row in self.recommendations:
            row.validate()
            if row.source_maintenance_receipt_sha256 != self.source_maintenance_receipt_sha256:
                raise AdaptiveLearningQuarantineError("QUARANTINE_SOURCE_RECEIPT_MISMATCH")
        expected_status = STATUS_RECOMMENDATIONS_READY if self.recommendations else STATUS_NO_RECOMMENDATIONS
        if self.status != expected_status:
            raise AdaptiveLearningQuarantineError("QUARANTINE_SET_STATUS_COUNT_MISMATCH")
        return self

    def to_payload(self) -> dict[str, Any]:
        return {**self._base_payload(), "recommendation_set_sha256": self.recommendation_set_sha256}


class AdaptiveLearningQuarantineProjector:
    """Project canonical high-risk maintenance reviews into advisory quarantine reviews."""

    def __init__(self, store: AdaptiveLearningStore, authority: LearningCheckpointAuthority) -> None:
        self._store = store
        self._authority = authority
        self._authority.verify(self._store)

    def _assert_active_identity(self, source: AdaptiveMaintenanceRecommendation) -> None:
        active = self._store.active(source.item_id)
        if active is None:
            raise AdaptiveLearningQuarantineError("QUARANTINE_TARGET_NOT_ACTIVE")
        candidate = active.get("candidate")
        if not isinstance(candidate, dict):
            raise AdaptiveLearningQuarantineError("QUARANTINE_TARGET_CANDIDATE_INVALID")
        if (
            str(active.get("knowledge_sha256") or "") != source.knowledge_sha256
            or str(active.get("candidate_sha256") or "") != source.candidate_sha256
            or str(active.get("level") or "") != source.active_level
            or str(candidate.get("domain") or "") != source.domain
        ):
            raise AdaptiveLearningQuarantineError("QUARANTINE_TARGET_IDENTITY_CHANGED")

    def project(self, receipt: AdaptiveLearningMaintenanceReceipt) -> QuarantineRecommendationSet:
        if not isinstance(receipt, AdaptiveLearningMaintenanceReceipt):
            raise AdaptiveLearningQuarantineError("QUARANTINE_MAINTENANCE_RECEIPT_REQUIRED")
        receipt.validate()
        if receipt.status not in {STATUS_RECOMMENDATIONS_READY}:
            raise AdaptiveLearningQuarantineError("QUARANTINE_MAINTENANCE_RECEIPT_NOT_READY")
        if (
            receipt.checkpoint_sequence is None
            or receipt.checkpoint_sha256 is None
            or receipt.state_sha256 is None
        ):
            raise AdaptiveLearningQuarantineError("QUARANTINE_MAINTENANCE_CHECKPOINT_MISSING")

        before = self._authority.verify(self._store)
        if (
            before.sequence != receipt.checkpoint_sequence
            or before.checkpoint_sha256 != receipt.checkpoint_sha256
            or before.state_sha256 != receipt.state_sha256
        ):
            raise AdaptiveLearningQuarantineError("QUARANTINE_MAINTENANCE_CHECKPOINT_STALE")

        source_receipt_sha = receipt.receipt_sha256
        recommendations: list[QuarantineReviewRecommendation] = []
        for source in receipt.recommendations:
            if source.recommendation_type != TYPE_DOMAIN_REVISION_OR_RETIREMENT_REVIEW:
                continue
            self._assert_active_identity(source)
            recommendations.append(
                QuarantineReviewRecommendation.create(
                    source_receipt_sha256=source_receipt_sha,
                    source=source,
                )
            )

        if len(recommendations) > _MAX_RECOMMENDATIONS:
            raise AdaptiveLearningQuarantineError("QUARANTINE_RECOMMENDATION_LIMIT_EXCEEDED")

        after = self._authority.verify(self._store)
        if (
            after.sequence != before.sequence
            or after.checkpoint_sha256 != before.checkpoint_sha256
            or after.state_sha256 != before.state_sha256
        ):
            raise AdaptiveLearningQuarantineError("QUARANTINE_CHECKPOINT_CHANGED")

        rows = tuple(
            sorted(
                recommendations,
                key=lambda row: (row.item_id, row.knowledge_sha256, row.recommendation_id),
            )
        )
        return QuarantineRecommendationSet(
            status=STATUS_RECOMMENDATIONS_READY if rows else STATUS_NO_RECOMMENDATIONS,
            source_maintenance_receipt_sha256=source_receipt_sha,
            checkpoint_sequence=before.sequence,
            checkpoint_sha256=before.checkpoint_sha256,
            state_sha256=before.state_sha256,
            recommendations=rows,
        ).validate()
