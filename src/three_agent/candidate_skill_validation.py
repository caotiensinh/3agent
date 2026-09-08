"""Checkpointed validation bridge for staged CandidateSkill proposals.

This module fills one narrow lifecycle gap without creating a second learning or
promotion system. It deterministically derives the canonical
``LearningValidationReceipt`` from the immutable staged ``KnowledgeCandidate``
and its CandidateSkill security receipt, then uses the existing
``LearningOperatorGateway`` for the single ``candidate -> validated`` transition.

Approved/enterprise promotion remains exclusively owned by
``AuthenticatedLearningPromotionService``. No production skill files are written
here and no runtime capability is granted.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from .adaptive_learning_checkpoint import LearningCheckpointAuthority, LearningOperatorGateway
from .adaptive_learning_contract import KnowledgeCandidate, LearningValidationReceipt
from .adaptive_learning_store import AdaptiveLearningStore, AdaptiveLearningStoreError
from .candidate_skill import CandidateSkill, CandidateSkillError, CandidateSkillSecurityReceipt

CANDIDATE_SKILL_VALIDATION_RESULT_SCHEMA = "workspace-candidate-skill-validation-result/v1"
_VALIDATOR_VERSION = "candidate-skill-validation/v1"
_VALIDATOR_IDS = (
    "validator:candidate-skill-contract",
    "validator:candidate-skill-evidence",
    "validator:candidate-skill-security",
)
_VALIDATION_CHECKS = {
    "SCHEMA": True,
    "EVIDENCE": True,
    "SECURITY": True,
    "DOMAIN_POLICY": True,
    "PRODUCTION_FORMAT": True,
    "VERIFIED_SUCCESS_LINEAGE": True,
    "NO_CAPABILITY_GRANTS": True,
}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class CandidateSkillValidationError(ValueError):
    """A staged skill cannot safely enter the canonical validated level."""

    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _candidate_id(value: str) -> str:
    candidate_id = str(value or "").strip()
    if not _ID_RE.fullmatch(candidate_id):
        raise CandidateSkillValidationError("CANDIDATE_SKILL_VALIDATION_ID_INVALID")
    return candidate_id


@dataclass(frozen=True)
class _StoredCandidate:
    candidate: KnowledgeCandidate
    item_id: str
    knowledge_sha256: str
    level: str
    disposition: str
    validation_receipt_sha256: str | None
    staged_at: str


@dataclass(frozen=True)
class CandidateSkillValidationResult:
    status: str
    candidate_id: str
    candidate_sha256: str
    item_id: str
    knowledge_sha256: str
    level: str
    disposition: str
    proposed_skill_name: str
    security_receipt_sha256: str
    validation_receipt_sha256: str
    checkpoint_sequence: int
    checkpoint_state_sha256: str
    schema_version: str = CANDIDATE_SKILL_VALIDATION_RESULT_SCHEMA

    def validate(self) -> "CandidateSkillValidationResult":
        if self.schema_version != CANDIDATE_SKILL_VALIDATION_RESULT_SCHEMA:
            raise CandidateSkillValidationError("CANDIDATE_SKILL_VALIDATION_SCHEMA_INVALID")
        if self.status not in {"validated", "already_validated"}:
            raise CandidateSkillValidationError("CANDIDATE_SKILL_VALIDATION_STATUS_INVALID")
        if not _ID_RE.fullmatch(self.candidate_id) or not _ID_RE.fullmatch(self.item_id):
            raise CandidateSkillValidationError("CANDIDATE_SKILL_VALIDATION_ID_INVALID")
        for value, code in (
            (self.candidate_sha256, "CANDIDATE_SKILL_VALIDATION_CANDIDATE_SHA_INVALID"),
            (self.knowledge_sha256, "CANDIDATE_SKILL_VALIDATION_KNOWLEDGE_SHA_INVALID"),
            (self.security_receipt_sha256, "CANDIDATE_SKILL_VALIDATION_SECURITY_SHA_INVALID"),
            (self.validation_receipt_sha256, "CANDIDATE_SKILL_VALIDATION_RECEIPT_SHA_INVALID"),
            (self.checkpoint_state_sha256, "CANDIDATE_SKILL_VALIDATION_STATE_SHA_INVALID"),
        ):
            if not _SHA_RE.fullmatch(value):
                raise CandidateSkillValidationError(code)
        if self.level != "validated" or self.disposition != "staged":
            raise CandidateSkillValidationError("CANDIDATE_SKILL_VALIDATION_STATE_INVALID")
        if not isinstance(self.checkpoint_sequence, int) or isinstance(
            self.checkpoint_sequence, bool
        ) or self.checkpoint_sequence < 1:
            raise CandidateSkillValidationError("CANDIDATE_SKILL_VALIDATION_CHECKPOINT_INVALID")
        if not self.proposed_skill_name:
            raise CandidateSkillValidationError("CANDIDATE_SKILL_VALIDATION_NAME_INVALID")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


class CandidateSkillValidationService:
    """Validate one exact staged CandidateSkill through canonical learning state.

    The caller supplies only ``candidate_id``. Candidate bytes, evidence lineage,
    domain policy, production-skill preview, and validation receipt are all
    reconstructed from the authenticated immutable learning store. This avoids a
    caller-controlled receipt/check surface.
    """

    def __init__(
        self,
        store: AdaptiveLearningStore,
        authority: LearningCheckpointAuthority,
    ) -> None:
        self.__store = store
        self.__operator = LearningOperatorGateway(store, authority)
        # Fail closed immediately if DB/ledger/checkpoint do not match.
        self.__operator.verify()

    def _row(self, candidate_id: str, *, level: str | None = None):
        with self.__store.connect() as conn:
            self.__store._assert_ledger_integrity(conn)
            if level is None:
                row = self.__store._candidate_level_row(conn, candidate_id)
            else:
                row = conn.execute(
                    "SELECT * FROM learning_versions WHERE candidate_id=? AND level=? "
                    "ORDER BY version_id DESC LIMIT 1",
                    (candidate_id, level),
                ).fetchone()
            if row is None:
                return None
            candidate = self.__store._candidate_from_row(row)
            return dict(row), candidate

    def _staged(self, candidate_id: str) -> _StoredCandidate:
        found = self._row(candidate_id, level="candidate")
        if found is None:
            raise CandidateSkillValidationError("CANDIDATE_SKILL_NOT_STAGED")
        row, candidate = found
        try:
            CandidateSkill.from_candidate(candidate)
        except CandidateSkillError as exc:
            raise CandidateSkillValidationError(exc.reason_code) from exc
        if str(row["disposition"]) != "staged":
            raise CandidateSkillValidationError("CANDIDATE_SKILL_STAGE_STATE_INVALID")
        return _StoredCandidate(
            candidate=candidate,
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            level=str(row["level"]),
            disposition=str(row["disposition"]),
            validation_receipt_sha256=(
                None
                if row["validation_receipt_sha256"] is None
                else str(row["validation_receipt_sha256"])
            ),
            staged_at=str(row["created_at"]),
        )

    def build_receipt(self, candidate_id: str) -> LearningValidationReceipt:
        """Reconstruct the exact deterministic validation receipt after restart.

        ``staged_at`` is immutable storage provenance. The actual validation-event
        time remains in the canonical learning ledger/checkpoint; using staged_at
        here keeps this pure receipt reproducible without a second receipt store.
        """

        candidate_key = _candidate_id(candidate_id)
        staged = self._staged(candidate_key)
        security = CandidateSkillSecurityReceipt.create(staged.candidate)
        identity = {
            "schema_version": "workspace-candidate-skill-validation-receipt-identity/v1",
            "validator_version": _VALIDATOR_VERSION,
            "candidate_id": staged.candidate.candidate_id,
            "candidate_sha256": staged.candidate.sha256,
            "security_receipt_sha256": security.sha256,
            "item_id": staged.item_id,
            "knowledge_sha256": staged.knowledge_sha256,
            "staged_at": staged.staged_at,
        }
        receipt_id = "receipt:candidate-skill:" + _digest(identity).split(":", 1)[1]
        return LearningValidationReceipt(
            receipt_id=receipt_id,
            candidate_id=staged.candidate.candidate_id,
            candidate_sha256=staged.candidate.sha256,
            checks=dict(_VALIDATION_CHECKS),
            validator_ids=_VALIDATOR_IDS,
            evidence_ref_ids=staged.candidate.evidence_ref_ids,
            evidence_hashes=staged.candidate.evidence_hashes,
            domain_reviewer_id=None,
            human_reviewer_id=None,
            created_at=staged.staged_at,
        ).validate()

    def validate_candidate(self, candidate_id: str) -> CandidateSkillValidationResult:
        candidate_key = _candidate_id(candidate_id)
        before = self.__operator.verify()
        latest = self._row(candidate_key)
        if latest is None:
            raise CandidateSkillValidationError("CANDIDATE_SKILL_NOT_STAGED")
        latest_row, latest_candidate = latest
        latest_level = str(latest_row["level"])

        staged = self._staged(candidate_key)
        if latest_candidate.sha256 != staged.candidate.sha256:
            raise CandidateSkillValidationError("CANDIDATE_SKILL_VERSION_CHANGED")
        view = CandidateSkill.from_candidate(staged.candidate)
        security = CandidateSkillSecurityReceipt.create(staged.candidate)
        receipt = self.build_receipt(candidate_key)
        receipt_sha = _digest(receipt.to_payload())

        if latest_level == "validated":
            stored_receipt = str(latest_row["validation_receipt_sha256"] or "")
            if stored_receipt != receipt_sha:
                raise CandidateSkillValidationError(
                    "CANDIDATE_SKILL_VALIDATION_RECEIPT_STATE_MISMATCH"
                )
            return self._result(
                status="already_validated",
                row=latest_row,
                candidate=staged.candidate,
                view=view,
                security=security,
                validation_receipt_sha256=receipt_sha,
                checkpoint=before,
            )
        if latest_level != "candidate":
            raise CandidateSkillValidationError(
                "CANDIDATE_SKILL_VALIDATION_LEVEL_INVALID:" + latest_level
            )

        try:
            self.__operator.promote(
                candidate_key,
                target_level="validated",
                receipt=receipt,
                actor_id="validator:candidate-skill-v1",
                reason_code="CANDIDATE_SKILL_VALIDATION_PASSED",
            )
        except AdaptiveLearningStoreError as exc:
            raise CandidateSkillValidationError(
                "CANDIDATE_SKILL_VALIDATION_STORE_BLOCKED:" + str(exc)
            ) from exc

        after = self.__operator.verify()
        validated = self._row(candidate_key)
        if validated is None:
            raise CandidateSkillValidationError("CANDIDATE_SKILL_VALIDATION_RESULT_MISSING")
        row, candidate = validated
        if (
            str(row["level"]) != "validated"
            or str(row["disposition"]) != "staged"
            or candidate.sha256 != staged.candidate.sha256
            or str(row["validation_receipt_sha256"] or "") != receipt_sha
        ):
            raise CandidateSkillValidationError("CANDIDATE_SKILL_VALIDATION_RESULT_INVALID")
        if self.__store.active(staged.item_id) is not None:
            raise CandidateSkillValidationError("CANDIDATE_SKILL_VALIDATION_ACTIVATED_EARLY")
        if after.sequence < before.sequence:
            raise CandidateSkillValidationError("CANDIDATE_SKILL_VALIDATION_CHECKPOINT_REGRESSED")

        return self._result(
            status="validated",
            row=row,
            candidate=candidate,
            view=view,
            security=security,
            validation_receipt_sha256=receipt_sha,
            checkpoint=after,
        )

    @staticmethod
    def _result(
        *,
        status: str,
        row: dict[str, Any],
        candidate: KnowledgeCandidate,
        view: CandidateSkill,
        security: CandidateSkillSecurityReceipt,
        validation_receipt_sha256: str,
        checkpoint: Any,
    ) -> CandidateSkillValidationResult:
        return CandidateSkillValidationResult(
            status=status,
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            level=str(row["level"]),
            disposition=str(row["disposition"]),
            proposed_skill_name=view.proposed_skill_name,
            security_receipt_sha256=security.sha256,
            validation_receipt_sha256=validation_receipt_sha256,
            checkpoint_sequence=int(checkpoint.sequence),
            checkpoint_state_sha256=str(checkpoint.state_sha256),
        ).validate()
