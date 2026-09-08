"""Human-review queue and approval boundary for validated CandidateSkill proposals.

The queue is a computed view over the canonical authenticated learning store. It
creates no second mutable queue database: a CandidateSkill is pending exactly
while its latest immutable version is ``validated`` + ``staged``.

A review packet explains the proposed skill to a human without exposing raw
evidence bytes. Approval is bound to the exact candidate, validation receipt,
checkpoint, and review-packet fingerprint the reviewer saw. The existing
``AuthenticatedLearningPromotionService`` remains the only mutation authority for
``validated -> approved``. Production filesystem publication is deliberately a
separate boundary.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from .adaptive_learning_checkpoint import LearningCheckpointAuthority
from .adaptive_learning_contract import KnowledgeCandidate
from .adaptive_learning_promotion import (
    AuthenticatedLearningPromotionService,
    LearningReviewerAuthorizationPolicy,
    PromotionBoundCheckpointAuthority,
)
from .adaptive_learning_store import AdaptiveLearningStore
from .candidate_skill import CandidateSkill, CandidateSkillError, CandidateSkillSecurityReceipt
from .candidate_skill_validation import CandidateSkillValidationService
from .workspace_auth import WorkspaceAuthStore

CANDIDATE_SKILL_REVIEW_SUMMARY_SCHEMA = "workspace-candidate-skill-review-summary/v1"
CANDIDATE_SKILL_REVIEW_PACKET_SCHEMA = "workspace-candidate-skill-review-packet/v1"
CANDIDATE_SKILL_APPROVAL_RESULT_SCHEMA = "workspace-candidate-skill-approval-result/v1"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_PENDING = 100


class CandidateSkillReviewError(ValueError):
    """The requested review/approval state is stale, invalid, or not pending."""

    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _candidate_id(value: str) -> str:
    text = str(value or "").strip()
    if not _ID_RE.fullmatch(text):
        raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_ID_INVALID")
    return text


def _expected_sha(value: str, *, code: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA_RE.fullmatch(text):
        raise CandidateSkillReviewError(code)
    return text


def _skill_view(candidate: KnowledgeCandidate) -> CandidateSkill:
    try:
        return CandidateSkill.from_candidate(candidate)
    except CandidateSkillError as exc:
        raise CandidateSkillReviewError(exc.reason_code) from exc


@dataclass(frozen=True)
class CandidateSkillReviewSummary:
    candidate_id: str
    candidate_sha256: str
    proposed_skill_name: str
    title: str
    domain: str
    scope: str
    risk_level: str
    sensitivity: str
    execution_mode: str
    verified_experience_count: int
    evidence_ref_count: int
    benefit_summary: str
    state: str = "pending_human_approval"
    schema_version: str = CANDIDATE_SKILL_REVIEW_SUMMARY_SCHEMA

    def validate(self) -> "CandidateSkillReviewSummary":
        if self.schema_version != CANDIDATE_SKILL_REVIEW_SUMMARY_SCHEMA:
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_SUMMARY_SCHEMA_INVALID")
        if self.state != "pending_human_approval":
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_STATE_INVALID")
        _candidate_id(self.candidate_id)
        _expected_sha(
            self.candidate_sha256,
            code="CANDIDATE_SKILL_REVIEW_CANDIDATE_SHA_INVALID",
        )
        if not self.proposed_skill_name or not self.title or not self.domain or not self.scope:
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_SUMMARY_INCOMPLETE")
        if self.verified_experience_count < 1 or self.evidence_ref_count < 1:
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_PROVENANCE_EMPTY")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class CandidateSkillReviewPacket:
    candidate_id: str
    candidate_sha256: str
    proposed_skill_name: str
    proposed_skill_sha256: str
    proposed_skill_size_bytes: int
    title: str
    domain: str
    scope: str
    risk_level: str
    sensitivity: str
    execution_mode: str
    purpose: str
    workflow_steps: tuple[str, ...]
    benefits: tuple[str, ...]
    input_contract: dict[str, Any]
    output_contract: dict[str, Any]
    evidence_summary: dict[str, Any]
    authority_summary: dict[str, Any]
    security_receipt_sha256: str
    validation_receipt_sha256: str
    expected_checkpoint_sequence: int
    expected_checkpoint_state_sha256: str
    proposed_skill_markdown: str
    review_fingerprint: str
    state: str = "pending_human_approval"
    schema_version: str = CANDIDATE_SKILL_REVIEW_PACKET_SCHEMA

    def validate(self) -> "CandidateSkillReviewPacket":
        if self.schema_version != CANDIDATE_SKILL_REVIEW_PACKET_SCHEMA:
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_PACKET_SCHEMA_INVALID")
        if self.state != "pending_human_approval":
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_STATE_INVALID")
        _candidate_id(self.candidate_id)
        for value, code in (
            (self.candidate_sha256, "CANDIDATE_SKILL_REVIEW_CANDIDATE_SHA_INVALID"),
            (self.proposed_skill_sha256, "CANDIDATE_SKILL_REVIEW_SKILL_SHA_INVALID"),
            (self.security_receipt_sha256, "CANDIDATE_SKILL_REVIEW_SECURITY_SHA_INVALID"),
            (self.validation_receipt_sha256, "CANDIDATE_SKILL_REVIEW_VALIDATION_SHA_INVALID"),
            (
                self.expected_checkpoint_state_sha256,
                "CANDIDATE_SKILL_REVIEW_CHECKPOINT_SHA_INVALID",
            ),
            (self.review_fingerprint, "CANDIDATE_SKILL_REVIEW_FINGERPRINT_INVALID"),
        ):
            _expected_sha(value, code=code)
        if (
            not isinstance(self.expected_checkpoint_sequence, int)
            or isinstance(self.expected_checkpoint_sequence, bool)
            or self.expected_checkpoint_sequence < 1
        ):
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_CHECKPOINT_INVALID")
        if not self.workflow_steps or not self.benefits or not self.proposed_skill_markdown:
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_PACKET_INCOMPLETE")
        if self.authority_summary.get("capability_grants") != []:
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_CAPABILITY_GRANT_FORBIDDEN")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        payload = asdict(self)
        payload["workflow_steps"] = list(self.workflow_steps)
        payload["benefits"] = list(self.benefits)
        return payload


@dataclass(frozen=True)
class CandidateSkillApprovalResult:
    status: str
    candidate_id: str
    candidate_sha256: str
    review_fingerprint: str
    target_level: str
    actor_id: str
    checkpoint_sequence: int
    checkpoint_state_sha256: str
    publication_state: str = "approved_not_materialized"
    schema_version: str = CANDIDATE_SKILL_APPROVAL_RESULT_SCHEMA

    def validate(self) -> "CandidateSkillApprovalResult":
        if self.schema_version != CANDIDATE_SKILL_APPROVAL_RESULT_SCHEMA:
            raise CandidateSkillReviewError("CANDIDATE_SKILL_APPROVAL_SCHEMA_INVALID")
        if self.status != "approved" or self.target_level != "approved":
            raise CandidateSkillReviewError("CANDIDATE_SKILL_APPROVAL_STATE_INVALID")
        if self.publication_state != "approved_not_materialized":
            raise CandidateSkillReviewError("CANDIDATE_SKILL_PUBLICATION_STATE_INVALID")
        _candidate_id(self.candidate_id)
        for value, code in (
            (self.candidate_sha256, "CANDIDATE_SKILL_APPROVAL_CANDIDATE_SHA_INVALID"),
            (self.review_fingerprint, "CANDIDATE_SKILL_APPROVAL_FINGERPRINT_INVALID"),
            (self.checkpoint_state_sha256, "CANDIDATE_SKILL_APPROVAL_CHECKPOINT_SHA_INVALID"),
        ):
            _expected_sha(value, code=code)
        if not self.actor_id.startswith("workspace-user:usr_"):
            raise CandidateSkillReviewError("CANDIDATE_SKILL_APPROVAL_ACTOR_INVALID")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


class CandidateSkillReviewQueue:
    """Read-only human review projection over canonical learning state."""

    def __init__(
        self,
        store: AdaptiveLearningStore,
        authority: LearningCheckpointAuthority,
    ) -> None:
        self._store = store
        self._authority = authority
        self._validation = CandidateSkillValidationService(store, authority)
        self._authority.verify(store)

    @staticmethod
    def _is_pending(row: dict[str, Any], candidate: KnowledgeCandidate) -> bool:
        return (
            candidate.kind == "skill"
            and str(row["level"]) == "validated"
            and str(row["disposition"]) == "staged"
        )

    def list_pending(self, *, limit: int = 50) -> tuple[CandidateSkillReviewSummary, ...]:
        """List pending skills without letting newer non-pending rows hide older work.

        SQLite streams the result cursor. The query first removes non-pending
        levels/dispositions at the database boundary; Python then validates each
        immutable row and filters non-skill kinds before applying the human-facing
        limit. This keeps memory bounded without truncating before the real filter.
        """

        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= _MAX_PENDING:
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_LIMIT_INVALID")
        self._authority.verify(self._store)
        pending: list[CandidateSkillReviewSummary] = []
        with self._store.connect() as conn:
            self._store._assert_ledger_integrity(conn)
            rows = conn.execute(
                """
                SELECT lv.*
                FROM learning_versions AS lv
                JOIN (
                    SELECT candidate_id, MAX(version_id) AS version_id
                    FROM learning_versions
                    GROUP BY candidate_id
                ) AS latest ON latest.version_id = lv.version_id
                WHERE lv.level='validated' AND lv.disposition='staged'
                ORDER BY lv.version_id DESC
                """
            )
            for row in rows:
                candidate = self._store._candidate_from_row(row)
                row_dict = dict(row)
                if not self._is_pending(row_dict, candidate):
                    continue
                view = _skill_view(candidate)
                pending.append(self._summary(candidate, view))
                if len(pending) >= limit:
                    break
        return tuple(pending)

    def _pending(self, candidate_id: str) -> tuple[dict[str, Any], KnowledgeCandidate]:
        key = _candidate_id(candidate_id)
        with self._store.connect() as conn:
            self._store._assert_ledger_integrity(conn)
            row = self._store._candidate_level_row(conn, key)
            if row is None:
                raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_NOT_FOUND")
            candidate = self._store._candidate_from_row(row)
            row_dict = dict(row)
        if not self._is_pending(row_dict, candidate):
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_NOT_PENDING")
        return row_dict, candidate

    def get(self, candidate_id: str) -> CandidateSkillReviewPacket:
        """Build the exact packet a human must inspect before approval."""

        row, candidate = self._pending(candidate_id)
        checkpoint = self._authority.verify(self._store)
        view = _skill_view(candidate)
        security = CandidateSkillSecurityReceipt.create(candidate)
        validation_receipt = self._validation.build_receipt(candidate.candidate_id)
        validation_sha = _digest(validation_receipt.to_payload())
        if validation_sha != str(row["validation_receipt_sha256"] or ""):
            raise CandidateSkillReviewError("CANDIDATE_SKILL_REVIEW_VALIDATION_STATE_MISMATCH")
        markdown = CandidateSkill.render_proposed_document(candidate)

        workflow_steps = (
            "Input: consume only verified evidence or observations already admitted for "
            f"domain '{candidate.domain}' and scope '{candidate.scope}'.",
            "Process: apply the proposed "
            f"'{candidate.execution_mode}' procedure shown in the SKILL.md preview; "
            "the skill itself does not invoke tools or grant authority.",
            "Output: return reusable procedural guidance for a matching future task; "
            "any external action remains subject to the runtime capability authority.",
        )
        benefits = (
            "Preserve a procedure learned from verified-success experience so a human can "
            "review it once and reuse the same knowledge consistently on matching tasks.",
            "Keep reusable knowledge separate from tool, credential, network-write, and "
            "device-control authority; this skill grants none of those capabilities.",
        )
        input_contract = {
            "domain": candidate.domain,
            "scope": candidate.scope,
            "accepted_source": "verified_evidence_or_observation",
            "evidence_ref_count": len(candidate.evidence_ref_ids),
            "source_task_count": len(candidate.source_task_ids),
            "typed_data_schema": None,
            "schema_note": (
                "The current KnowledgeCandidate schema does not separately type a concrete "
                "input datatype; exact runtime inputs remain governed by the task/tool contract."
            ),
        }
        output_contract = {
            "kind": "instruction_only_reusable_procedure",
            "execution_mode": candidate.execution_mode,
            "production_artifact": f"skills/{view.proposed_skill_name}/SKILL.md",
            "capability_grants": [],
            "schema_note": (
                "The skill contributes guidance only. Tool outputs and side effects remain "
                "outside this skill contract and require separate runtime authorization."
            ),
        }
        evidence_summary = {
            "source_experience_ids": list(candidate.source_experience_ids),
            "source_experience_hashes": list(candidate.source_experience_hashes),
            "source_task_ids": list(candidate.source_task_ids),
            "evidence_ref_ids": list(candidate.evidence_ref_ids),
            "evidence_hashes": list(candidate.evidence_hashes),
            "source_outcomes": list(candidate.source_outcomes),
            "raw_evidence_included": False,
        }
        authority_summary = {
            "skill_is_knowledge_only": True,
            "capability_grants": [],
            "network_access_granted": False,
            "credential_access_granted": False,
            "production_write_granted": False,
            "human_approval_required": True,
        }
        purpose = self._purpose(candidate)
        fingerprint_payload = {
            "schema_version": "workspace-candidate-skill-review-fingerprint/v1",
            "candidate_id": candidate.candidate_id,
            "candidate_sha256": candidate.sha256,
            "proposed_skill_name": view.proposed_skill_name,
            "proposed_skill_sha256": view.proposed_skill_sha256,
            "title": candidate.title,
            "domain": candidate.domain,
            "scope": candidate.scope,
            "risk_level": candidate.risk_level,
            "sensitivity": candidate.sensitivity,
            "execution_mode": candidate.execution_mode,
            "purpose": purpose,
            "workflow_steps": list(workflow_steps),
            "benefits": list(benefits),
            "input_contract": input_contract,
            "output_contract": output_contract,
            "evidence_summary": evidence_summary,
            "authority_summary": authority_summary,
            "security_receipt_sha256": security.sha256,
            "validation_receipt_sha256": validation_sha,
            "expected_checkpoint_sequence": checkpoint.sequence,
            "expected_checkpoint_state_sha256": checkpoint.state_sha256,
            "proposed_skill_markdown_sha256": view.proposed_skill_sha256,
        }
        return CandidateSkillReviewPacket(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            proposed_skill_name=view.proposed_skill_name,
            proposed_skill_sha256=view.proposed_skill_sha256,
            proposed_skill_size_bytes=view.proposed_skill_size_bytes,
            title=candidate.title,
            domain=candidate.domain,
            scope=candidate.scope,
            risk_level=candidate.risk_level,
            sensitivity=candidate.sensitivity,
            execution_mode=candidate.execution_mode,
            purpose=purpose,
            workflow_steps=workflow_steps,
            benefits=benefits,
            input_contract=input_contract,
            output_contract=output_contract,
            evidence_summary=evidence_summary,
            authority_summary=authority_summary,
            security_receipt_sha256=security.sha256,
            validation_receipt_sha256=validation_sha,
            expected_checkpoint_sequence=int(checkpoint.sequence),
            expected_checkpoint_state_sha256=str(checkpoint.state_sha256),
            proposed_skill_markdown=markdown,
            review_fingerprint=_digest(fingerprint_payload),
        ).validate()

    @staticmethod
    def _purpose(candidate: KnowledgeCandidate) -> str:
        return (
            f"Proposed reusable skill for '{candidate.title}' within scope "
            f"'{candidate.scope}'. It packages verified procedural knowledge only; "
            "it does not add runtime capability."
        )

    @staticmethod
    def _summary(candidate: KnowledgeCandidate, view: CandidateSkill) -> CandidateSkillReviewSummary:
        return CandidateSkillReviewSummary(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            proposed_skill_name=view.proposed_skill_name,
            title=candidate.title,
            domain=candidate.domain,
            scope=candidate.scope,
            risk_level=candidate.risk_level,
            sensitivity=candidate.sensitivity,
            execution_mode=candidate.execution_mode,
            verified_experience_count=len(candidate.source_experience_ids),
            evidence_ref_count=len(candidate.evidence_ref_ids),
            benefit_summary=(
                "Reusable verified-success procedural knowledge; human approval is required "
                "before production publication."
            ),
        ).validate()


class CandidateSkillApprovalService:
    """Approve the exact review packet through existing authenticated promotion."""

    def __init__(
        self,
        auth: WorkspaceAuthStore,
        store: AdaptiveLearningStore,
        authority: PromotionBoundCheckpointAuthority,
        reviewer_policy: LearningReviewerAuthorizationPolicy,
    ) -> None:
        self._store = store
        self._authority = authority
        self._queue = CandidateSkillReviewQueue(store, authority)
        self._validation = CandidateSkillValidationService(store, authority)
        self._promotion = AuthenticatedLearningPromotionService(
            auth,
            store,
            authority,
            reviewer_policy,
        )

    @property
    def queue(self) -> CandidateSkillReviewQueue:
        return self._queue

    def approve(
        self,
        *,
        session_token: str,
        client_ip: str,
        candidate_id: str,
        expected_candidate_sha256: str,
        expected_review_fingerprint: str,
        confirm_approve: bool,
    ) -> CandidateSkillApprovalResult:
        if confirm_approve is not True:
            raise CandidateSkillReviewError("CANDIDATE_SKILL_APPROVAL_CONFIRMATION_REQUIRED")
        candidate_sha = _expected_sha(
            expected_candidate_sha256,
            code="CANDIDATE_SKILL_APPROVAL_CANDIDATE_SHA_INVALID",
        )
        fingerprint = _expected_sha(
            expected_review_fingerprint,
            code="CANDIDATE_SKILL_APPROVAL_FINGERPRINT_INVALID",
        )

        # Rebuild immediately before authorization. Any candidate, receipt, or
        # checkpoint change produces a different packet and invalidates the click.
        packet = self._queue.get(candidate_id)
        if packet.candidate_sha256 != candidate_sha:
            raise CandidateSkillReviewError("CANDIDATE_SKILL_APPROVAL_CANDIDATE_CHANGED")
        if packet.review_fingerprint != fingerprint:
            raise CandidateSkillReviewError("CANDIDATE_SKILL_APPROVAL_REVIEW_CHANGED")

        _, candidate = self._queue._pending(candidate_id)
        receipt = self._validation.build_receipt(candidate.candidate_id)
        ceremony = self._promotion.prepare(
            session_token=session_token,
            client_ip=client_ip,
            candidate=candidate,
            target_level="approved",
        )
        if (
            ceremony.expected_checkpoint_sequence != packet.expected_checkpoint_sequence
            or ceremony.expected_state_sha256 != packet.expected_checkpoint_state_sha256
        ):
            raise CandidateSkillReviewError("CANDIDATE_SKILL_APPROVAL_CHECKPOINT_CHANGED")

        result = self._promotion.promote(
            ceremony=ceremony,
            session_token=session_token,
            client_ip=client_ip,
            candidate=candidate,
            receipt=receipt,
        )
        if result.get("status") != "promoted" or result.get("target_level") != "approved":
            raise CandidateSkillReviewError("CANDIDATE_SKILL_APPROVAL_RESULT_INVALID")
        return CandidateSkillApprovalResult(
            status="approved",
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            review_fingerprint=packet.review_fingerprint,
            target_level="approved",
            actor_id=str(result["actor_id"]),
            checkpoint_sequence=int(result["checkpoint_sequence"]),
            checkpoint_state_sha256=str(result["checkpoint_state_sha256"]),
        ).validate()
