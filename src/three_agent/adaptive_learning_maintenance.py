"""Bounded recommendation-only maintenance over canonical Phase 4H/4I.

This module closes one orchestration gap only. Phase 4H remains the sole
observational effectiveness analyzer and Phase 4I remains the sole curation
proposal compiler. A maintenance tick composes those two read-only stages into a
bounded metadata-only receipt. It cannot stage, validate, promote, archive,
rollback, materialize, invoke models, use tools, access credentials, or perform
network/execution actions.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any

from .adaptive_learning_checkpoint import LearningCheckpointAuthority
from .adaptive_learning_curation import (
    ACTION_DOMAIN_REVISE_OR_ARCHIVE_REVIEW,
    ACTION_KEEP_ACTIVE_REVIEW,
    ACTION_OBSERVE_MORE,
    ACTION_REVISE_OR_ARCHIVE_REVIEW,
    CurationProposalSet,
    DeterministicCurationProposalCompiler,
    KnowledgeCurationProposal,
    LearningCurationError,
)
from .adaptive_learning_effectiveness import (
    DeterministicLearningEffectivenessAnalyzer,
    LearningEffectivenessError,
)
from .adaptive_learning_store import AdaptiveLearningStore
from .store import TaskStore

MAINTENANCE_RECOMMENDATION_SCHEMA = "workspace-learning-maintenance-recommendation/v1"
MAINTENANCE_RECEIPT_SCHEMA = "workspace-learning-maintenance-receipt/v1"
MAINTENANCE_AUTHORITY = "recommendation_only_no_learning_or_runtime_mutation"

STATUS_DISABLED = "DISABLED"
STATUS_NO_SIGNALS = "NO_SIGNALS"
STATUS_RECOMMENDATIONS_READY = "RECOMMENDATIONS_READY"
STATUS_SIGNAL_LIMIT_EXCEEDED = "SIGNAL_LIMIT_EXCEEDED"

TYPE_OBSERVE_MORE = "observe_more"
TYPE_KEEP_ACTIVE_REVIEW = "keep_active_review"
TYPE_REVISION_OR_RETIREMENT_REVIEW = "revision_or_retirement_review"
TYPE_DOMAIN_REVISION_OR_RETIREMENT_REVIEW = "domain_revision_or_retirement_review"

_TYPE_BY_ACTION = {
    ACTION_OBSERVE_MORE: TYPE_OBSERVE_MORE,
    ACTION_KEEP_ACTIVE_REVIEW: TYPE_KEEP_ACTIVE_REVIEW,
    ACTION_REVISE_OR_ARCHIVE_REVIEW: TYPE_REVISION_OR_RETIREMENT_REVIEW,
    ACTION_DOMAIN_REVISE_OR_ARCHIVE_REVIEW: TYPE_DOMAIN_REVISION_OR_RETIREMENT_REVIEW,
}

_MAX_SIGNALS = 128


class AdaptiveLearningMaintenanceError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AdaptiveLearningMaintenanceConfig:
    """Operator-owned bound for one recommendation-only maintenance tick."""

    enabled: bool = False
    max_signals: int = 32

    def validate(self) -> "AdaptiveLearningMaintenanceConfig":
        if not isinstance(self.enabled, bool):
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_ENABLED_INVALID")
        if (
            not isinstance(self.max_signals, int)
            or isinstance(self.max_signals, bool)
            or not 1 <= self.max_signals <= _MAX_SIGNALS
        ):
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_MAX_SIGNALS_INVALID")
        return self


@dataclass(frozen=True)
class AdaptiveMaintenanceRecommendation:
    proposal_id: str
    item_id: str
    knowledge_sha256: str
    candidate_sha256: str
    active_level: str
    domain: str
    advisory_signal: str
    curation_action: str
    recommendation_type: str
    human_review_required: bool
    domain_review_required: bool
    reason_codes: tuple[str, ...]
    schema_version: str = MAINTENANCE_RECOMMENDATION_SCHEMA

    @classmethod
    def from_proposal(cls, proposal: KnowledgeCurationProposal) -> "AdaptiveMaintenanceRecommendation":
        proposal.validate()
        recommendation_type = _TYPE_BY_ACTION.get(proposal.curation_action)
        if recommendation_type is None:
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_ACTION_UNSUPPORTED")
        return cls(
            proposal_id=proposal.proposal_id,
            item_id=proposal.item_id,
            knowledge_sha256=proposal.knowledge_sha256,
            candidate_sha256=proposal.candidate_sha256,
            active_level=proposal.active_level,
            domain=proposal.domain,
            advisory_signal=proposal.advisory_signal,
            curation_action=proposal.curation_action,
            recommendation_type=recommendation_type,
            human_review_required=proposal.human_review_required,
            domain_review_required=proposal.domain_review_required,
            reason_codes=proposal.reason_codes,
        ).validate()

    def validate(self) -> "AdaptiveMaintenanceRecommendation":
        if self.schema_version != MAINTENANCE_RECOMMENDATION_SCHEMA:
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_RECOMMENDATION_SCHEMA_INVALID")
        expected = _TYPE_BY_ACTION.get(self.curation_action)
        if expected is None or self.recommendation_type != expected:
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_RECOMMENDATION_ACTION_INVALID")
        if not self.proposal_id or not self.item_id or not self.domain:
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_RECOMMENDATION_IDENTITY_INVALID")
        if not self.knowledge_sha256.startswith("sha256:") or not self.candidate_sha256.startswith("sha256:"):
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_RECOMMENDATION_SHA_INVALID")
        if not self.reason_codes:
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_RECOMMENDATION_REASONS_REQUIRED")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        payload = asdict(self)
        payload["reason_codes"] = list(self.reason_codes)
        return payload


@dataclass(frozen=True)
class AdaptiveLearningMaintenanceReceipt:
    enabled: bool
    status: str
    scanned_signals: int
    emitted_recommendations: int
    source_snapshot_sha256: str | None
    proposal_set_sha256: str | None
    checkpoint_sequence: int | None
    checkpoint_sha256: str | None
    state_sha256: str | None
    recommendations: tuple[AdaptiveMaintenanceRecommendation, ...]
    authority: str = MAINTENANCE_AUTHORITY
    schema_version: str = MAINTENANCE_RECEIPT_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority": self.authority,
            "enabled": self.enabled,
            "status": self.status,
            "scanned_signals": self.scanned_signals,
            "emitted_recommendations": self.emitted_recommendations,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "proposal_set_sha256": self.proposal_set_sha256,
            "checkpoint_sequence": self.checkpoint_sequence,
            "checkpoint_sha256": self.checkpoint_sha256,
            "state_sha256": self.state_sha256,
            "recommendations": [item.to_payload() for item in self.recommendations],
        }

    @property
    def receipt_sha256(self) -> str:
        self.validate()
        return _digest(self._base_payload())

    def validate(self) -> "AdaptiveLearningMaintenanceReceipt":
        if self.schema_version != MAINTENANCE_RECEIPT_SCHEMA or self.authority != MAINTENANCE_AUTHORITY:
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_RECEIPT_HEADER_INVALID")
        if self.status not in {
            STATUS_DISABLED,
            STATUS_NO_SIGNALS,
            STATUS_RECOMMENDATIONS_READY,
            STATUS_SIGNAL_LIMIT_EXCEEDED,
        }:
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_RECEIPT_STATUS_INVALID")
        for value, field in (
            (self.scanned_signals, "scanned_signals"),
            (self.emitted_recommendations, "emitted_recommendations"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise AdaptiveLearningMaintenanceError(f"MAINTENANCE_RECEIPT_{field.upper()}_INVALID")
        if self.emitted_recommendations != len(self.recommendations):
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_RECEIPT_RECOMMENDATION_COUNT_MISMATCH")
        for item in self.recommendations:
            item.validate()

        if self.status == STATUS_DISABLED:
            if self.enabled or self.scanned_signals or self.emitted_recommendations or self.recommendations:
                raise AdaptiveLearningMaintenanceError("MAINTENANCE_DISABLED_RECEIPT_INVALID")
            if any(value is not None for value in (
                self.source_snapshot_sha256,
                self.proposal_set_sha256,
                self.checkpoint_sequence,
                self.checkpoint_sha256,
                self.state_sha256,
            )):
                raise AdaptiveLearningMaintenanceError("MAINTENANCE_DISABLED_RECEIPT_INVALID")
            return self

        if not self.enabled:
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_ENABLED_RECEIPT_INVALID")
        if self.source_snapshot_sha256 is None or not self.source_snapshot_sha256.startswith("sha256:"):
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_SNAPSHOT_SHA_INVALID")
        if not isinstance(self.checkpoint_sequence, int) or self.checkpoint_sequence < 1:
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_CHECKPOINT_INVALID")
        if self.checkpoint_sha256 is None or not self.checkpoint_sha256.startswith("sha256:"):
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_CHECKPOINT_SHA_INVALID")
        if self.state_sha256 is None or not self.state_sha256.startswith("sha256:"):
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_STATE_SHA_INVALID")

        if self.status == STATUS_SIGNAL_LIMIT_EXCEEDED:
            if self.proposal_set_sha256 is not None or self.recommendations:
                raise AdaptiveLearningMaintenanceError("MAINTENANCE_LIMIT_RECEIPT_INVALID")
            return self

        if self.proposal_set_sha256 is None or not self.proposal_set_sha256.startswith("sha256:"):
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_PROPOSAL_SET_SHA_INVALID")
        if self.status == STATUS_NO_SIGNALS and (self.scanned_signals or self.recommendations):
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_NO_SIGNAL_RECEIPT_INVALID")
        if self.status == STATUS_RECOMMENDATIONS_READY and (
            self.scanned_signals < 1 or self.emitted_recommendations != self.scanned_signals
        ):
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_READY_RECEIPT_INVALID")
        return self

    def to_payload(self) -> dict[str, Any]:
        return {**self._base_payload(), "receipt_sha256": self.receipt_sha256}


class AdaptiveLearningMaintenanceAdvisor:
    """One bounded read-only effectiveness -> curation recommendation tick."""

    def __init__(
        self,
        config: AdaptiveLearningMaintenanceConfig,
        task_store: TaskStore,
        learning_store: AdaptiveLearningStore,
        authority: LearningCheckpointAuthority,
    ) -> None:
        self.config = config.validate()
        self.task_store = task_store
        self.learning_store = learning_store
        self.authority = authority

    def _disabled(self) -> AdaptiveLearningMaintenanceReceipt:
        return AdaptiveLearningMaintenanceReceipt(
            enabled=False,
            status=STATUS_DISABLED,
            scanned_signals=0,
            emitted_recommendations=0,
            source_snapshot_sha256=None,
            proposal_set_sha256=None,
            checkpoint_sequence=None,
            checkpoint_sha256=None,
            state_sha256=None,
            recommendations=(),
        ).validate()

    def run_once(self) -> AdaptiveLearningMaintenanceReceipt:
        if not self.config.enabled:
            return self._disabled()

        before = self.authority.verify(self.learning_store)
        try:
            snapshot = DeterministicLearningEffectivenessAnalyzer(self.task_store).snapshot()
        except LearningEffectivenessError as exc:
            raise AdaptiveLearningMaintenanceError(
                "MAINTENANCE_EFFECTIVENESS_BLOCKED:" + str(exc)
            ) from exc

        signal_count = len(snapshot.signals)
        if signal_count > self.config.max_signals:
            after = self.authority.verify(self.learning_store)
            if after.checkpoint_sha256 != before.checkpoint_sha256:
                raise AdaptiveLearningMaintenanceError("MAINTENANCE_CHECKPOINT_CHANGED")
            return AdaptiveLearningMaintenanceReceipt(
                enabled=True,
                status=STATUS_SIGNAL_LIMIT_EXCEEDED,
                scanned_signals=signal_count,
                emitted_recommendations=0,
                source_snapshot_sha256=snapshot.snapshot_sha256,
                proposal_set_sha256=None,
                checkpoint_sequence=before.sequence,
                checkpoint_sha256=before.checkpoint_sha256,
                state_sha256=before.state_sha256,
                recommendations=(),
            ).validate()

        try:
            proposal_set: CurationProposalSet = DeterministicCurationProposalCompiler(
                self.learning_store,
                self.authority,
            ).compile(snapshot)
        except LearningCurationError as exc:
            raise AdaptiveLearningMaintenanceError(
                "MAINTENANCE_CURATION_BLOCKED:" + str(exc)
            ) from exc

        after = self.authority.verify(self.learning_store)
        if (
            before.sequence != after.sequence
            or before.checkpoint_sha256 != after.checkpoint_sha256
            or before.state_sha256 != after.state_sha256
        ):
            raise AdaptiveLearningMaintenanceError("MAINTENANCE_CHECKPOINT_CHANGED")

        recommendations = tuple(
            AdaptiveMaintenanceRecommendation.from_proposal(proposal)
            for proposal in proposal_set.proposals
        )
        status = STATUS_NO_SIGNALS if not recommendations else STATUS_RECOMMENDATIONS_READY
        return AdaptiveLearningMaintenanceReceipt(
            enabled=True,
            status=status,
            scanned_signals=signal_count,
            emitted_recommendations=len(recommendations),
            source_snapshot_sha256=snapshot.snapshot_sha256,
            proposal_set_sha256=proposal_set.proposal_set_sha256,
            checkpoint_sequence=before.sequence,
            checkpoint_sha256=before.checkpoint_sha256,
            state_sha256=before.state_sha256,
            recommendations=recommendations,
        ).validate()
