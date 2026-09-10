"""Deterministic, evidence-bound curation proposals for adaptive knowledge.

Phase 4I converts Phase 4H observational effectiveness signals into metadata-only
review proposals bound to the exact authenticated active knowledge version. It
never mutates learning state and does not expose promotion, archive, rollback,
staging, network, shell, credential, or deployment authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .adaptive_learning_checkpoint import LearningCheckpointAuthority
from .adaptive_learning_contract import DOMAINS
from .adaptive_learning_effectiveness import (
    EFFECTIVENESS_SNAPSHOT_SCHEMA,
    INTERPRETATION,
    SIGNAL_DOMAIN_REVIEW,
    SIGNAL_INSUFFICIENT,
    SIGNAL_REVIEW,
    SIGNAL_SUPPORT,
    KnowledgeEffectivenessSignal,
    LearningEffectivenessSnapshot,
)
from .adaptive_learning_store import ACTIVE_LEVELS, AdaptiveLearningStore

CURATION_PROPOSAL_SCHEMA = "workspace-learning-curation-proposal/v1"
CURATION_SET_SCHEMA = "workspace-learning-curation-proposal-set/v1"

ACTION_OBSERVE_MORE = "OBSERVE_MORE"
ACTION_KEEP_ACTIVE_REVIEW = "KEEP_ACTIVE_REVIEW"
ACTION_REVISE_OR_ARCHIVE_REVIEW = "REVISE_OR_ARCHIVE_REVIEW"
ACTION_DOMAIN_REVISE_OR_ARCHIVE_REVIEW = "DOMAIN_REVISE_OR_ARCHIVE_REVIEW"

_ACTION_BY_SIGNAL = {
    SIGNAL_INSUFFICIENT: ACTION_OBSERVE_MORE,
    SIGNAL_SUPPORT: ACTION_KEEP_ACTIVE_REVIEW,
    SIGNAL_REVIEW: ACTION_REVISE_OR_ARCHIVE_REVIEW,
    SIGNAL_DOMAIN_REVIEW: ACTION_DOMAIN_REVISE_OR_ARCHIVE_REVIEW,
}
_REVIEW_ACTIONS = {
    ACTION_KEEP_ACTIVE_REVIEW,
    ACTION_REVISE_OR_ARCHIVE_REVIEW,
    ACTION_DOMAIN_REVISE_OR_ARCHIVE_REVIEW,
}
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_PROPOSAL_ID = re.compile(r"^curation:[0-9a-f]{64}$")


class LearningCurationError(ValueError):
    """Curation input or authenticated active-state binding is unsafe."""


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha_payload(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _require_identifier(value: Any, *, field: str, limit: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit or any(ch in text for ch in "\r\n\x00"):
        raise LearningCurationError(f"invalid {field}")
    return text


def _require_count(value: Any, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise LearningCurationError(f"invalid {field}")
    return value


@dataclass(frozen=True)
class CurationEvidenceCounters:
    unique_task_observations: int
    unique_reuse_receipts: int
    isolated_task_observations: int
    confounded_task_observations: int
    verified_success_after_reuse: int
    failed_after_reuse: int
    waiting_human_after_reuse: int
    pending_after_reuse: int
    done_unverified_after_reuse: int
    isolated_verified_success: int
    isolated_failed: int
    isolated_waiting_human: int
    isolated_done_unverified: int

    @classmethod
    def from_signal(cls, signal: KnowledgeEffectivenessSignal) -> "CurationEvidenceCounters":
        return cls(
            unique_task_observations=signal.unique_task_observations,
            unique_reuse_receipts=signal.unique_reuse_receipts,
            isolated_task_observations=signal.isolated_task_observations,
            confounded_task_observations=signal.confounded_task_observations,
            verified_success_after_reuse=signal.verified_success_after_reuse,
            failed_after_reuse=signal.failed_after_reuse,
            waiting_human_after_reuse=signal.waiting_human_after_reuse,
            pending_after_reuse=signal.pending_after_reuse,
            done_unverified_after_reuse=signal.done_unverified_after_reuse,
            isolated_verified_success=signal.isolated_verified_success,
            isolated_failed=signal.isolated_failed,
            isolated_waiting_human=signal.isolated_waiting_human,
            isolated_done_unverified=signal.isolated_done_unverified,
        ).validate()

    def validate(self) -> "CurationEvidenceCounters":
        for field, value in self.to_payload().items():
            _require_count(value, field=field)
        if (
            self.isolated_task_observations + self.confounded_task_observations
            != self.unique_task_observations
        ):
            raise LearningCurationError("curation observation partition mismatch")
        if (
            self.verified_success_after_reuse
            + self.failed_after_reuse
            + self.waiting_human_after_reuse
            + self.pending_after_reuse
            + self.done_unverified_after_reuse
            != self.unique_task_observations
        ):
            raise LearningCurationError("curation outcome partition mismatch")
        if self.isolated_verified_success > self.verified_success_after_reuse:
            raise LearningCurationError("isolated success exceeds total")
        if self.isolated_failed > self.failed_after_reuse:
            raise LearningCurationError("isolated failed exceeds total")
        if self.isolated_waiting_human > self.waiting_human_after_reuse:
            raise LearningCurationError("isolated waiting exceeds total")
        if self.isolated_done_unverified > self.done_unverified_after_reuse:
            raise LearningCurationError("isolated unverified exceeds total")
        isolated_known = (
            self.isolated_verified_success
            + self.isolated_failed
            + self.isolated_waiting_human
            + self.isolated_done_unverified
        )
        if isolated_known > self.isolated_task_observations:
            raise LearningCurationError("isolated outcomes exceed isolated observations")
        return self

    def to_payload(self) -> dict[str, int]:
        return {
            "unique_task_observations": self.unique_task_observations,
            "unique_reuse_receipts": self.unique_reuse_receipts,
            "isolated_task_observations": self.isolated_task_observations,
            "confounded_task_observations": self.confounded_task_observations,
            "verified_success_after_reuse": self.verified_success_after_reuse,
            "failed_after_reuse": self.failed_after_reuse,
            "waiting_human_after_reuse": self.waiting_human_after_reuse,
            "pending_after_reuse": self.pending_after_reuse,
            "done_unverified_after_reuse": self.done_unverified_after_reuse,
            "isolated_verified_success": self.isolated_verified_success,
            "isolated_failed": self.isolated_failed,
            "isolated_waiting_human": self.isolated_waiting_human,
            "isolated_done_unverified": self.isolated_done_unverified,
        }


@dataclass(frozen=True)
class _ActiveKnowledgeIdentity:
    item_id: str
    knowledge_sha256: str
    candidate_sha256: str
    level: str
    domain: str

    def validate(self) -> "_ActiveKnowledgeIdentity":
        _require_identifier(self.item_id, field="item_id")
        if not _SHA.fullmatch(self.knowledge_sha256):
            raise LearningCurationError("invalid active knowledge_sha256")
        if not _SHA.fullmatch(self.candidate_sha256):
            raise LearningCurationError("invalid active candidate_sha256")
        if self.level not in ACTIVE_LEVELS:
            raise LearningCurationError("curation target is not approved/enterprise")
        if self.domain not in DOMAINS:
            raise LearningCurationError("invalid active domain")
        return self


def _review_requirements(*, domain: str, level: str, action: str) -> tuple[bool, bool]:
    human = action in _REVIEW_ACTIONS or level == "enterprise"
    domain_review = (
        action == ACTION_DOMAIN_REVISE_OR_ARCHIVE_REVIEW
        or (domain in {"network", "security"} and (action in _REVIEW_ACTIONS or level == "enterprise"))
    )
    if domain_review:
        human = True
    return human, domain_review


@dataclass(frozen=True)
class KnowledgeCurationProposal:
    proposal_id: str
    source_snapshot_sha256: str
    effectiveness_signal_sha256: str
    item_id: str
    knowledge_sha256: str
    candidate_sha256: str
    active_level: str
    domain: str
    advisory_signal: str
    curation_action: str
    evidence: CurationEvidenceCounters
    human_review_required: bool
    domain_review_required: bool
    reason_codes: tuple[str, ...]
    capability_grants: tuple[str, ...] = ()
    interpretation: str = INTERPRETATION
    schema_version: str = CURATION_PROPOSAL_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "effectiveness_signal_sha256": self.effectiveness_signal_sha256,
            "item_id": self.item_id,
            "knowledge_sha256": self.knowledge_sha256,
            "candidate_sha256": self.candidate_sha256,
            "active_level": self.active_level,
            "domain": self.domain,
            "advisory_signal": self.advisory_signal,
            "curation_action": self.curation_action,
            "evidence": self.evidence.to_payload(),
            "human_review_required": self.human_review_required,
            "domain_review_required": self.domain_review_required,
            "reason_codes": list(self.reason_codes),
            "capability_grants": list(self.capability_grants),
            "interpretation": self.interpretation,
        }

    @classmethod
    def create(
        cls,
        *,
        source_snapshot_sha256: str,
        effectiveness_signal_sha256: str,
        active: _ActiveKnowledgeIdentity,
        signal: KnowledgeEffectivenessSignal,
    ) -> "KnowledgeCurationProposal":
        active.validate()
        action = _ACTION_BY_SIGNAL.get(signal.advisory_signal)
        if action is None:
            raise LearningCurationError("unsupported Phase 4H advisory signal")
        human, domain_review = _review_requirements(
            domain=active.domain,
            level=active.level,
            action=action,
        )
        reasons = [
            f"PHASE4H_{signal.advisory_signal}",
            f"CURATION_{action}",
            f"ACTIVE_LEVEL_{active.level.upper()}",
        ]
        if human:
            reasons.append("HUMAN_REVIEW_REQUIRED")
        if domain_review:
            reasons.append("DOMAIN_REVIEW_REQUIRED")
        evidence = CurationEvidenceCounters.from_signal(signal)
        draft = cls(
            proposal_id="curation:" + "0" * 64,
            source_snapshot_sha256=source_snapshot_sha256,
            effectiveness_signal_sha256=effectiveness_signal_sha256,
            item_id=active.item_id,
            knowledge_sha256=active.knowledge_sha256,
            candidate_sha256=active.candidate_sha256,
            active_level=active.level,
            domain=active.domain,
            advisory_signal=signal.advisory_signal,
            curation_action=action,
            evidence=evidence,
            human_review_required=human,
            domain_review_required=domain_review,
            reason_codes=tuple(reasons),
        )
        proposal_id = "curation:" + hashlib.sha256(
            _canonical(draft._base_payload()).encode("utf-8")
        ).hexdigest()
        return cls(
            proposal_id=proposal_id,
            source_snapshot_sha256=draft.source_snapshot_sha256,
            effectiveness_signal_sha256=draft.effectiveness_signal_sha256,
            item_id=draft.item_id,
            knowledge_sha256=draft.knowledge_sha256,
            candidate_sha256=draft.candidate_sha256,
            active_level=draft.active_level,
            domain=draft.domain,
            advisory_signal=draft.advisory_signal,
            curation_action=draft.curation_action,
            evidence=draft.evidence,
            human_review_required=draft.human_review_required,
            domain_review_required=draft.domain_review_required,
            reason_codes=draft.reason_codes,
        ).validate()

    def validate(self) -> "KnowledgeCurationProposal":
        if self.schema_version != CURATION_PROPOSAL_SCHEMA:
            raise LearningCurationError("curation proposal schema mismatch")
        if self.interpretation != INTERPRETATION:
            raise LearningCurationError("curation interpretation mismatch")
        if self.capability_grants != ():
            raise LearningCurationError("curation proposal cannot grant capabilities")
        for value, field in (
            (self.source_snapshot_sha256, "source_snapshot_sha256"),
            (self.effectiveness_signal_sha256, "effectiveness_signal_sha256"),
            (self.knowledge_sha256, "knowledge_sha256"),
            (self.candidate_sha256, "candidate_sha256"),
        ):
            if not _SHA.fullmatch(value):
                raise LearningCurationError(f"invalid {field}")
        _require_identifier(self.item_id, field="item_id")
        if self.active_level not in ACTIVE_LEVELS:
            raise LearningCurationError("invalid active level")
        if self.domain not in DOMAINS:
            raise LearningCurationError("invalid curation domain")
        expected_action = _ACTION_BY_SIGNAL.get(self.advisory_signal)
        if expected_action is None or self.curation_action != expected_action:
            raise LearningCurationError("curation action/signal mismatch")
        expected_human, expected_domain = _review_requirements(
            domain=self.domain,
            level=self.active_level,
            action=self.curation_action,
        )
        if self.human_review_required != expected_human:
            raise LearningCurationError("human review requirement mismatch")
        if self.domain_review_required != expected_domain:
            raise LearningCurationError("domain review requirement mismatch")
        self.evidence.validate()
        if not self.reason_codes or len(self.reason_codes) > 8:
            raise LearningCurationError("invalid curation reason codes")
        if len(set(self.reason_codes)) != len(self.reason_codes):
            raise LearningCurationError("duplicate curation reason codes")
        for code in self.reason_codes:
            if not re.fullmatch(r"[A-Z0-9][A-Z0-9_.:-]{0,127}", code):
                raise LearningCurationError("invalid curation reason code")
        expected_id = "curation:" + hashlib.sha256(
            _canonical(self._base_payload()).encode("utf-8")
        ).hexdigest()
        if not _PROPOSAL_ID.fullmatch(self.proposal_id) or self.proposal_id != expected_id:
            raise LearningCurationError("curation proposal identity mismatch")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {"proposal_id": self.proposal_id, **self._base_payload()}


@dataclass(frozen=True)
class CurationProposalSet:
    source_snapshot_sha256: str
    checkpoint_sequence: int
    checkpoint_sha256: str
    state_sha256: str
    proposals: tuple[KnowledgeCurationProposal, ...]
    capability_grants: tuple[str, ...] = ()
    schema_version: str = CURATION_SET_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "source_snapshot_sha256": self.source_snapshot_sha256,
            "checkpoint_sequence": self.checkpoint_sequence,
            "checkpoint_sha256": self.checkpoint_sha256,
            "state_sha256": self.state_sha256,
            "proposals": [proposal.to_payload() for proposal in self.proposals],
            "capability_grants": list(self.capability_grants),
        }

    @property
    def proposal_set_sha256(self) -> str:
        return _sha_payload(self._base_payload())

    def validate(self) -> "CurationProposalSet":
        if self.schema_version != CURATION_SET_SCHEMA:
            raise LearningCurationError("curation set schema mismatch")
        if self.capability_grants != ():
            raise LearningCurationError("curation set cannot grant capabilities")
        if not _SHA.fullmatch(self.source_snapshot_sha256):
            raise LearningCurationError("invalid source snapshot hash")
        if not isinstance(self.checkpoint_sequence, int) or isinstance(self.checkpoint_sequence, bool):
            raise LearningCurationError("invalid checkpoint sequence")
        if self.checkpoint_sequence < 1:
            raise LearningCurationError("invalid checkpoint sequence")
        if not _SHA.fullmatch(self.checkpoint_sha256) or not _SHA.fullmatch(self.state_sha256):
            raise LearningCurationError("invalid checkpoint binding")
        ordered = tuple(sorted(self.proposals, key=lambda p: (p.item_id, p.knowledge_sha256, p.proposal_id)))
        if ordered != self.proposals:
            raise LearningCurationError("curation proposals must be deterministically sorted")
        if len({proposal.proposal_id for proposal in self.proposals}) != len(self.proposals):
            raise LearningCurationError("duplicate curation proposal")
        for proposal in self.proposals:
            proposal.validate()
            if proposal.source_snapshot_sha256 != self.source_snapshot_sha256:
                raise LearningCurationError("proposal snapshot binding mismatch")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {**self._base_payload(), "proposal_set_sha256": self.proposal_set_sha256}


class DeterministicCurationProposalCompiler:
    """Compile Phase 4H signals into review-only proposals.

    The compiler verifies the Phase 3.1 checkpoint/witness before and after reading
    active knowledge state. It calls only read/verification operations. Its public
    API is ``compile``; it has no promotion/archive/rollback/stage/remediation API.
    """

    __slots__ = ("_store", "_authority")

    def __init__(
        self,
        store: AdaptiveLearningStore,
        authority: LearningCheckpointAuthority,
    ) -> None:
        self._store = store
        self._authority = authority
        self._authority.verify(self._store)

    @staticmethod
    def _validate_snapshot(snapshot: LearningEffectivenessSnapshot) -> None:
        if not isinstance(snapshot, LearningEffectivenessSnapshot):
            raise LearningCurationError("LearningEffectivenessSnapshot required")
        if snapshot.schema_version != EFFECTIVENESS_SNAPSHOT_SCHEMA:
            raise LearningCurationError("effectiveness snapshot schema mismatch")
        if snapshot.interpretation != INTERPRETATION:
            raise LearningCurationError("effectiveness interpretation mismatch")
        if not _SHA.fullmatch(snapshot.snapshot_sha256):
            raise LearningCurationError("invalid effectiveness snapshot hash")
        identities: set[tuple[str, str, str]] = set()
        for signal in snapshot.signals:
            if not isinstance(signal, KnowledgeEffectivenessSignal):
                raise LearningCurationError("invalid effectiveness signal")
            _require_identifier(signal.item_id, field="item_id")
            if not _SHA.fullmatch(signal.knowledge_sha256):
                raise LearningCurationError("invalid signal knowledge_sha256")
            if signal.domain not in DOMAINS:
                raise LearningCurationError("invalid signal domain")
            if signal.interpretation != INTERPRETATION:
                raise LearningCurationError("signal interpretation mismatch")
            if signal.advisory_signal not in _ACTION_BY_SIGNAL:
                raise LearningCurationError("unsupported advisory signal")
            CurationEvidenceCounters.from_signal(signal)
            identity = (signal.item_id, signal.knowledge_sha256, signal.domain)
            if identity in identities:
                raise LearningCurationError("duplicate effectiveness signal identity")
            identities.add(identity)

    def _active_identity(self, item_id: str) -> _ActiveKnowledgeIdentity:
        with self._store.connect() as conn:
            self._store._assert_ledger_integrity(conn)
            row = self._store._active_row(conn, item_id)
            if row is None:
                raise LearningCurationError(f"CURATION_TARGET_NOT_ACTIVE:{item_id}")
            candidate = self._store._candidate_from_row(row)
            candidate.validate()
            return _ActiveKnowledgeIdentity(
                item_id=str(row["item_id"]),
                knowledge_sha256=str(row["knowledge_sha256"]),
                candidate_sha256=str(row["candidate_sha256"]),
                level=str(row["level"]),
                domain=candidate.domain,
            ).validate()

    def compile(self, snapshot: LearningEffectivenessSnapshot) -> CurationProposalSet:
        self._validate_snapshot(snapshot)
        before = self._authority.verify(self._store)

        proposals: list[KnowledgeCurationProposal] = []
        for signal in sorted(
            snapshot.signals,
            key=lambda value: (value.item_id, value.knowledge_sha256, value.domain),
        ):
            active = self._active_identity(signal.item_id)
            if active.knowledge_sha256 != signal.knowledge_sha256:
                raise LearningCurationError(
                    f"CURATION_TARGET_SHA_MISMATCH:{signal.item_id}"
                )
            if active.domain != signal.domain:
                raise LearningCurationError(
                    f"CURATION_TARGET_DOMAIN_MISMATCH:{signal.item_id}"
                )
            signal_sha = _sha_payload(signal.to_payload())
            proposals.append(
                KnowledgeCurationProposal.create(
                    source_snapshot_sha256=snapshot.snapshot_sha256,
                    effectiveness_signal_sha256=signal_sha,
                    active=active,
                    signal=signal,
                )
            )

        after = self._authority.verify(self._store)
        if (
            before.sequence != after.sequence
            or before.checkpoint_sha256 != after.checkpoint_sha256
            or before.state_sha256 != after.state_sha256
        ):
            raise LearningCurationError("CHECKPOINT_CHANGED_DURING_CURATION_COMPILE")

        result = CurationProposalSet(
            source_snapshot_sha256=snapshot.snapshot_sha256,
            checkpoint_sequence=before.sequence,
            checkpoint_sha256=before.checkpoint_sha256,
            state_sha256=before.state_sha256,
            proposals=tuple(proposals),
        )
        return result.validate()
