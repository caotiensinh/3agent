"""Phase 4K deterministic evaluation for staged curation revisions.

No model decides PASS/FAIL here. Phase 4K binds an exact Phase 4J STAGED
receipt, exact active base and exact checkpoint; re-runs contract/domain
safety checks; persists only the existing ``validated`` level; and requires the
existing Phase 4E authenticated promotion service for approved/enterprise.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Iterator

from .adaptive_learning_checkpoint import LearningCheckpoint, LearningCheckpointError, LearningOperatorGateway
from .adaptive_learning_contract import KnowledgeCandidate, LearningValidationReceipt
from .adaptive_learning_curation_revision import AuthenticatedCurationRevisionApproval, CurationRevisionReceiptStore
from .adaptive_learning_effectiveness import INTERPRETATION as EFFECTIVENESS_INTERPRETATION, KnowledgeEffectivenessSignal
from .adaptive_learning_evaluation import AdaptiveLearningDomainValidator
from .adaptive_learning_promotion import AuthenticatedLearningPromotionService, LearningPromotionCeremony, PromotionBoundCheckpointAuthority
from .adaptive_learning_store import ACTIVE_LEVELS, AdaptiveLearningStore

REVISION_EVALUATION_SCHEMA = "workspace-learning-revision-evaluation/v1"
REVISION_VALIDATION_RESULT_SCHEMA = "workspace-learning-revision-validation-result/v1"
REVISION_ROLLBACK_PLAN_SCHEMA = "workspace-learning-revision-rollback-plan/v1"
REVISION_EFFECTIVENESS_COMPARISON_SCHEMA = "workspace-learning-revision-effectiveness-comparison/v1"
REVISION_EVALUATION_INTERPRETATION = "deterministic_safety_eligibility_not_quality_or_causality_claim"

PASS = "PASS"
FAIL = "FAIL"
_STAGED_LEVELS = {"candidate", "validated", "approved"}
_LOCKED_FIELDS = ("domain", "kind", "sensitivity", "risk_level", "ownership", "execution_mode")
_LINEAGE_FIELDS = (
    "source_experience_ids", "source_experience_hashes", "source_domains",
    "source_sensitivities", "source_task_ids", "source_outcomes",
)
_CHANGED_FIELDS = ("title", "content", "scope")
_CHECKS = (
    "PATCH_ACTION", "LEARNER_MANAGED", "ACTIVE_BASE_PRESENT", "ACTIVE_LEVEL_SUPPORTED",
    "EXACT_TARGET_BINDING", "LOCKED_METADATA_PRESERVED", "SOURCE_LINEAGE_PRESERVED",
    "CURATION_APPROVAL_EVIDENCE_BOUND", "CONTENT_CHANGED", "NON_SECRET_REVISION",
    "CONTRACT_VALID", "DOMAIN_VALIDATION_PASSED", "NO_DOMAIN_SAFETY_REGRESSION",
    "ROLLBACK_BASE_AVAILABLE",
)
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_REASON = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")


class RevisionEvaluationError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


class RevisionEvaluationAuthorizationError(PermissionError):
    pass


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value).encode("utf-8")).hexdigest()


def _sha(value: str, code: str) -> str:
    value = str(value or "").strip().lower()
    if not _SHA.fullmatch(value):
        raise RevisionEvaluationError(code)
    return value


def _text(value: str, code: str) -> str:
    value = str(value or "").strip()
    if not value or len(value) > 160 or any(ch in value for ch in "\r\n\x00"):
        raise RevisionEvaluationError(code)
    return value


@dataclass(frozen=True)
class RevisionEvaluationPackage:
    candidate_id: str
    candidate_sha256: str
    candidate_knowledge_sha256: str
    candidate_level: str
    item_id: str
    base_candidate_id: str
    base_candidate_sha256: str
    base_knowledge_sha256: str
    base_level: str
    curation_approval_id: str
    curation_approval_sha256: str
    curation_proposal_id: str
    curation_revision_receipt_sha256: str
    domain: str
    kind: str
    sensitivity: str
    risk_level: str
    ownership: str
    execution_mode: str
    changed_fields: tuple[str, ...]
    checks: tuple[tuple[str, bool], ...]
    reason_codes: tuple[str, ...]
    result: str
    checkpoint_sequence: int
    checkpoint_sha256: str
    state_sha256: str
    created_at: str
    schema_version: str = REVISION_EVALUATION_SCHEMA
    interpretation: str = REVISION_EVALUATION_INTERPRETATION
    post_activation_observation: str = "phase4h_exact_knowledge_sha_required"

    def validate(self) -> "RevisionEvaluationPackage":
        if self.schema_version != REVISION_EVALUATION_SCHEMA or self.interpretation != REVISION_EVALUATION_INTERPRETATION:
            raise RevisionEvaluationError("REVISION_EVALUATION_HEADER_INVALID")
        if self.post_activation_observation != "phase4h_exact_knowledge_sha_required":
            raise RevisionEvaluationError("REVISION_EVALUATION_OBSERVATION_INVALID")
        for value in (self.candidate_id, self.item_id, self.base_candidate_id, self.curation_approval_id, self.curation_proposal_id, self.domain, self.kind, self.sensitivity, self.risk_level, self.ownership, self.execution_mode):
            _text(value, "REVISION_EVALUATION_IDENTIFIER_INVALID")
        for value in (self.candidate_sha256, self.candidate_knowledge_sha256, self.base_candidate_sha256, self.base_knowledge_sha256, self.curation_approval_sha256, self.curation_revision_receipt_sha256, self.checkpoint_sha256, self.state_sha256):
            _sha(value, "REVISION_EVALUATION_SHA_INVALID")
        if self.candidate_level not in _STAGED_LEVELS or self.base_level not in ACTIVE_LEVELS:
            raise RevisionEvaluationError("REVISION_EVALUATION_LEVEL_INVALID")
        if not isinstance(self.checkpoint_sequence, int) or isinstance(self.checkpoint_sequence, bool) or self.checkpoint_sequence < 1:
            raise RevisionEvaluationError("REVISION_EVALUATION_CHECKPOINT_SEQUENCE_INVALID")
        if not _UTC.fullmatch(str(self.created_at or "")):
            raise RevisionEvaluationError("REVISION_EVALUATION_CREATED_AT_INVALID")
        if tuple(k for k, _ in self.checks) != _CHECKS or any(not isinstance(v, bool) for _, v in self.checks):
            raise RevisionEvaluationError("REVISION_EVALUATION_CHECKS_INVALID")
        if tuple(x for x in _CHANGED_FIELDS if x in self.changed_fields) != self.changed_fields or len(set(self.changed_fields)) != len(self.changed_fields):
            raise RevisionEvaluationError("REVISION_EVALUATION_CHANGED_FIELDS_INVALID")
        if len(set(self.reason_codes)) != len(self.reason_codes) or any(not _REASON.fullmatch(str(x or "")) for x in self.reason_codes):
            raise RevisionEvaluationError("REVISION_EVALUATION_REASONS_INVALID")
        all_pass = all(v for _, v in self.checks)
        if self.result not in {PASS, FAIL} or (self.result == PASS) != (all_pass and not self.reason_codes):
            raise RevisionEvaluationError("REVISION_EVALUATION_RESULT_INCONSISTENT")
        return self

    @property
    def check_map(self) -> dict[str, bool]:
        self.validate()
        return dict(self.checks)

    @property
    def next_transition(self) -> str | None:
        self.validate()
        if self.result != PASS:
            return None
        if self.candidate_level == "candidate":
            return "validated"
        if self.candidate_level == "validated":
            return "approved"
        if self.candidate_level == "approved" and self.base_level == "enterprise":
            return "enterprise"
        return None

    def _payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version, "interpretation": self.interpretation,
            "candidate_id": self.candidate_id, "candidate_sha256": self.candidate_sha256,
            "candidate_knowledge_sha256": self.candidate_knowledge_sha256, "candidate_level": self.candidate_level,
            "item_id": self.item_id, "base_candidate_id": self.base_candidate_id,
            "base_candidate_sha256": self.base_candidate_sha256, "base_knowledge_sha256": self.base_knowledge_sha256,
            "base_level": self.base_level, "curation_approval_id": self.curation_approval_id,
            "curation_approval_sha256": self.curation_approval_sha256, "curation_proposal_id": self.curation_proposal_id,
            "curation_revision_receipt_sha256": self.curation_revision_receipt_sha256,
            "domain": self.domain, "kind": self.kind, "sensitivity": self.sensitivity,
            "risk_level": self.risk_level, "ownership": self.ownership, "execution_mode": self.execution_mode,
            "changed_fields": list(self.changed_fields), "checks": dict(self.checks), "reason_codes": list(self.reason_codes),
            "result": self.result, "post_activation_observation": self.post_activation_observation,
            "checkpoint_sequence": self.checkpoint_sequence, "checkpoint_sha256": self.checkpoint_sha256,
            "state_sha256": self.state_sha256, "created_at": self.created_at,
        }

    @property
    def evaluation_sha256(self) -> str:
        self.validate()
        return _digest(self._payload())

    def to_payload(self) -> dict[str, Any]:
        return {**self._payload(), "evaluation_sha256": self.evaluation_sha256}


class DeterministicRevisionEvaluator:
    def __init__(self, store: AdaptiveLearningStore, authority: PromotionBoundCheckpointAuthority, revision_receipts: CurationRevisionReceiptStore) -> None:
        self.store = store
        self.authority = authority
        self.revision_receipts = revision_receipts
        authority.verify(store)

    def _rows(self, candidate_id: str):
        with self.store.connect() as conn:
            self.store._assert_ledger_integrity(conn)
            row = self.store._candidate_level_row(conn, candidate_id)
            if row is None or str(row["level"]) not in _STAGED_LEVELS or str(row["disposition"]) != "staged":
                raise RevisionEvaluationError("REVISION_EVALUATION_CANDIDATE_NOT_STAGED")
            candidate = self.store._candidate_from_row(row)
            active_row = self.store._active_row(conn, str(row["item_id"]))
            active = None if active_row is None else self.store._candidate_from_row(active_row)
            return dict(row), candidate, None if active_row is None else dict(active_row), active

    def _phase4j(self, candidate: KnowledgeCandidate, approval: AuthenticatedCurationRevisionApproval):
        approval.validate()
        receipt = self.revision_receipts.read(approval)
        if receipt is None or receipt.status != "completed" or receipt.result != "STAGED" or receipt.candidate_sha256 != candidate.sha256 or receipt.base_knowledge_sha256 != approval.knowledge_sha256 or receipt.approval_id != approval.approval_id or receipt.proposal_id != approval.proposal_id:
            raise RevisionEvaluationError("REVISION_EVALUATION_PHASE4J_RECEIPT_MISSING_OR_MISMATCHED")
        approval_ref = "curation-approval:" + approval.approval_id.rsplit(":", 1)[1]
        if not candidate.evidence_ref_ids or not candidate.evidence_hashes or candidate.evidence_ref_ids[-1] != approval_ref or candidate.evidence_hashes[-1] != approval.sha256 or candidate.target_item_id != approval.item_id or candidate.base_item_sha256 != approval.knowledge_sha256:
            raise RevisionEvaluationError("REVISION_EVALUATION_PHASE4J_APPROVAL_BINDING_MISMATCH")
        return receipt

    def candidate(self, package: RevisionEvaluationPackage) -> KnowledgeCandidate:
        package.validate()
        row, candidate, _, _ = self._rows(package.candidate_id)
        if candidate.sha256 != package.candidate_sha256 or str(row["knowledge_sha256"]) != package.candidate_knowledge_sha256 or str(row["level"]) != package.candidate_level or str(row["item_id"]) != package.item_id:
            raise RevisionEvaluationError("REVISION_EVALUATION_CANDIDATE_CHANGED")
        return candidate

    def compile(self, candidate_id: str, *, approval: AuthenticatedCurationRevisionApproval) -> RevisionEvaluationPackage:
        checkpoint = self.authority.verify(self.store)
        row, candidate, active_row, active = self._rows(candidate_id)
        revision_receipt = self._phase4j(candidate, approval)
        checks = {name: False for name in _CHECKS}
        checks["PATCH_ACTION"] = candidate.action == "patch"
        checks["LEARNER_MANAGED"] = candidate.ownership == "learner_managed"
        checks["ACTIVE_BASE_PRESENT"] = active_row is not None and active is not None
        reasons: list[str] = []
        if active_row is None or active is None:
            raise RevisionEvaluationError("REVISION_EVALUATION_ACTIVE_BASE_MISSING")
        base_level = str(active_row["level"])
        base_sha = str(active_row["knowledge_sha256"])
        checks["ACTIVE_LEVEL_SUPPORTED"] = base_level in ACTIVE_LEVELS
        checks["EXACT_TARGET_BINDING"] = candidate.target_item_id == str(active_row["item_id"]) and candidate.base_item_sha256 == base_sha and approval.item_id == str(active_row["item_id"]) and approval.knowledge_sha256 == base_sha and approval.candidate_sha256 == str(active_row["candidate_sha256"]) and approval.domain == candidate.domain
        checks["LOCKED_METADATA_PRESERVED"] = all(getattr(candidate, f) == getattr(active, f) for f in _LOCKED_FIELDS)
        checks["SOURCE_LINEAGE_PRESERVED"] = all(getattr(candidate, f) == getattr(active, f) for f in _LINEAGE_FIELDS)
        checks["CURATION_APPROVAL_EVIDENCE_BOUND"] = len(candidate.evidence_ref_ids) == len(active.evidence_ref_ids) + 1 and len(candidate.evidence_hashes) == len(active.evidence_hashes) + 1 and candidate.evidence_ref_ids[:-1] == active.evidence_ref_ids and candidate.evidence_hashes[:-1] == active.evidence_hashes and candidate.evidence_ref_ids[-1] == "curation-approval:" + approval.approval_id.rsplit(":", 1)[1] and candidate.evidence_hashes[-1] == approval.sha256
        changed = tuple(f for f in _CHANGED_FIELDS if getattr(candidate, f).strip() != getattr(active, f).strip())
        checks["CONTENT_CHANGED"] = bool(changed)
        checks["NON_SECRET_REVISION"] = candidate.sensitivity != "secret"
        candidate.validate()
        checks["CONTRACT_VALID"] = True
        candidate_domain_reasons = AdaptiveLearningDomainValidator.validate(candidate)
        base_domain_reasons = AdaptiveLearningDomainValidator.validate(active)
        checks["DOMAIN_VALIDATION_PASSED"] = not candidate_domain_reasons
        checks["NO_DOMAIN_SAFETY_REGRESSION"] = not any(x not in base_domain_reasons for x in candidate_domain_reasons)
        checks["ROLLBACK_BASE_AVAILABLE"] = checks["EXACT_TARGET_BINDING"] and base_level in ACTIVE_LEVELS and str(active_row["disposition"]) == "active_snapshot"
        reasons.extend(name for name in _CHECKS if not checks[name])
        reasons.extend("DOMAIN:" + code for code in candidate_domain_reasons)
        reason_codes = tuple(dict.fromkeys(reasons))
        result = PASS if all(checks.values()) else FAIL
        return RevisionEvaluationPackage(
            candidate_id=candidate.candidate_id, candidate_sha256=candidate.sha256,
            candidate_knowledge_sha256=str(row["knowledge_sha256"]), candidate_level=str(row["level"]),
            item_id=str(row["item_id"]), base_candidate_id=str(active_row["candidate_id"]),
            base_candidate_sha256=str(active_row["candidate_sha256"]), base_knowledge_sha256=base_sha,
            base_level=base_level, curation_approval_id=approval.approval_id,
            curation_approval_sha256=approval.sha256, curation_proposal_id=approval.proposal_id,
            curation_revision_receipt_sha256=revision_receipt.record_sha256,
            domain=candidate.domain, kind=candidate.kind, sensitivity=candidate.sensitivity,
            risk_level=candidate.risk_level, ownership=candidate.ownership, execution_mode=candidate.execution_mode,
            changed_fields=changed, checks=tuple((name, checks[name]) for name in _CHECKS),
            reason_codes=reason_codes, result=result, checkpoint_sequence=checkpoint.sequence,
            checkpoint_sha256=checkpoint.checkpoint_sha256, state_sha256=checkpoint.state_sha256,
            created_at=checkpoint.created_at,
        ).validate()

    def require_fresh_pass(self, package: RevisionEvaluationPackage, *, approval: AuthenticatedCurationRevisionApproval) -> RevisionEvaluationPackage:
        package.validate()
        if package.result != PASS:
            raise RevisionEvaluationError("REVISION_EVALUATION_NOT_PASSED")
        if package.curation_approval_id != approval.approval_id or package.curation_approval_sha256 != approval.sha256:
            raise RevisionEvaluationError("REVISION_EVALUATION_APPROVAL_CHANGED")
        fresh = self.compile(package.candidate_id, approval=approval)
        if fresh.evaluation_sha256 != package.evaluation_sha256:
            raise RevisionEvaluationError("REVISION_EVALUATION_STALE")
        return fresh


class RevisionEvaluationBoundCheckpointAuthority(PromotionBoundCheckpointAuthority):
    """Adds exact Phase 4K candidate->validated state binding to Phase 4E authority."""
    def __init__(self, *args, **kwargs) -> None:
        super().__init__(*args, **kwargs)
        self._revision_expected = threading.local()

    @contextmanager
    def expect_revision_validation(self, *, sequence: int, checkpoint_sha256: str, state_sha256: str) -> Iterator[None]:
        if not isinstance(sequence, int) or isinstance(sequence, bool) or sequence < 1:
            raise LearningCheckpointError("REVISION_VALIDATION_EXPECTED_SEQUENCE_INVALID")
        expected = (sequence, _sha(checkpoint_sha256, "REVISION_VALIDATION_EXPECTED_CHECKPOINT_SHA_INVALID"), _sha(state_sha256, "REVISION_VALIDATION_EXPECTED_STATE_SHA_INVALID"))
        if getattr(self._revision_expected, "value", None) is not None:
            raise LearningCheckpointError("REVISION_VALIDATION_EXPECTATION_ALREADY_ACTIVE")
        self._revision_expected.value = expected
        try:
            yield
        finally:
            self._revision_expected.value = None

    def _mutate(self, store: AdaptiveLearningStore, *, mutation_kind: str, **kwargs):
        if getattr(self._revision_expected, "value", None) is not None and mutation_kind != "promote":
            raise LearningCheckpointError("REVISION_VALIDATION_MUTATION_KIND_MISMATCH")
        return super()._mutate(store, mutation_kind=mutation_kind, **kwargs)

    def _verify_store(self, store: AdaptiveLearningStore) -> LearningCheckpoint:
        checkpoint = super()._verify_store(store)
        expected = getattr(self._revision_expected, "value", None)
        if expected is None:
            return checkpoint
        self._revision_expected.value = None
        if (checkpoint.sequence, checkpoint.checkpoint_sha256, checkpoint.state_sha256) != expected:
            raise LearningCheckpointError("REVISION_VALIDATION_EXPECTED_STATE_MISMATCH")
        return checkpoint


@dataclass(frozen=True)
class RevisionValidationResult:
    candidate_id: str
    candidate_sha256: str
    validation_receipt: LearningValidationReceipt
    checkpoint_sequence: int
    checkpoint_sha256: str
    state_sha256: str
    schema_version: str = REVISION_VALIDATION_RESULT_SCHEMA

    def to_payload(self) -> dict[str, Any]:
        return {"schema_version": self.schema_version, "candidate_id": self.candidate_id, "candidate_sha256": self.candidate_sha256, "validation_receipt": self.validation_receipt.to_payload(), "checkpoint_sequence": self.checkpoint_sequence, "checkpoint_sha256": self.checkpoint_sha256, "state_sha256": self.state_sha256}


class RevisionValidationGate:
    def __init__(self, store: AdaptiveLearningStore, authority: RevisionEvaluationBoundCheckpointAuthority, revision_receipts: CurationRevisionReceiptStore) -> None:
        self.authority = authority
        self.evaluator = DeterministicRevisionEvaluator(store, authority, revision_receipts)
        self.operator = LearningOperatorGateway(store, authority)

    def validate_candidate(self, package: RevisionEvaluationPackage, *, approval: AuthenticatedCurationRevisionApproval) -> RevisionValidationResult:
        fresh = self.evaluator.require_fresh_pass(package, approval=approval)
        if fresh.next_transition != "validated":
            raise RevisionEvaluationError("REVISION_VALIDATION_TRANSITION_NOT_ALLOWED")
        candidate = self.evaluator.candidate(fresh)
        receipt = LearningValidationReceipt(
            receipt_id="receipt:phase4k:" + fresh.evaluation_sha256.split(":", 1)[1],
            candidate_id=candidate.candidate_id, candidate_sha256=candidate.sha256,
            checks=dict(fresh.checks),
            validator_ids=("validator:phase4k:lineage", "validator:phase4k:domain", "validator:phase4k:checkpoint"),
            evidence_ref_ids=candidate.evidence_ref_ids, evidence_hashes=candidate.evidence_hashes,
            domain_reviewer_id=None, human_reviewer_id=None, created_at=fresh.created_at,
        ).validate()
        with self.authority.expect_revision_validation(sequence=fresh.checkpoint_sequence, checkpoint_sha256=fresh.checkpoint_sha256, state_sha256=fresh.state_sha256):
            self.operator.promote(candidate.candidate_id, target_level="validated", receipt=receipt, actor_id="operator:phase4k-validator", reason_code="REVISION_EVALUATION_PASSED")
        after = self.operator.verify()
        return RevisionValidationResult(candidate.candidate_id, candidate.sha256, receipt, after.sequence, after.checkpoint_sha256, after.state_sha256)


class RevisionActivationGate:
    def __init__(self, store: AdaptiveLearningStore, authority: RevisionEvaluationBoundCheckpointAuthority, revision_receipts: CurationRevisionReceiptStore, promotion_service: AuthenticatedLearningPromotionService) -> None:
        self.evaluator = DeterministicRevisionEvaluator(store, authority, revision_receipts)
        self.promotion = promotion_service

    def prepare(self, *, package: RevisionEvaluationPackage, approval: AuthenticatedCurationRevisionApproval, session_token: str, client_ip: str) -> LearningPromotionCeremony:
        fresh = self.evaluator.require_fresh_pass(package, approval=approval)
        target = fresh.next_transition
        if target not in {"approved", "enterprise"}:
            raise RevisionEvaluationAuthorizationError("REVISION_ACTIVATION_PACKAGE_NOT_READY")
        candidate = self.evaluator.candidate(fresh)
        ceremony = self.promotion.prepare(session_token=session_token, client_ip=client_ip, candidate=candidate, target_level=target)
        if ceremony.expected_checkpoint_sequence != fresh.checkpoint_sequence or ceremony.expected_state_sha256 != fresh.state_sha256:
            raise RevisionEvaluationAuthorizationError("REVISION_ACTIVATION_EVALUATION_STALE")
        return ceremony

    def promote(self, *, package: RevisionEvaluationPackage, approval: AuthenticatedCurationRevisionApproval, session_token: str, client_ip: str, receipt: LearningValidationReceipt) -> dict[str, object]:
        ceremony = self.prepare(package=package, approval=approval, session_token=session_token, client_ip=client_ip)
        candidate = self.evaluator.candidate(package)
        return self.promotion.promote(ceremony=ceremony, session_token=session_token, client_ip=client_ip, candidate=candidate, receipt=receipt)


@dataclass(frozen=True)
class RevisionRollbackPlan:
    item_id: str
    target_knowledge_sha256: str
    expected_current_sha256: str
    operator_only: bool = True
    automatic_rollback: bool = False
    schema_version: str = REVISION_ROLLBACK_PLAN_SCHEMA

    @classmethod
    def from_evaluation(cls, package: RevisionEvaluationPackage) -> "RevisionRollbackPlan":
        package.validate()
        if package.result != PASS:
            raise RevisionEvaluationError("REVISION_ROLLBACK_PLAN_REQUIRES_PASS")
        return cls(package.item_id, package.base_knowledge_sha256, package.candidate_knowledge_sha256).validate()

    def validate(self) -> "RevisionRollbackPlan":
        _text(self.item_id, "REVISION_ROLLBACK_ITEM_INVALID")
        _sha(self.target_knowledge_sha256, "REVISION_ROLLBACK_TARGET_INVALID")
        _sha(self.expected_current_sha256, "REVISION_ROLLBACK_CURRENT_INVALID")
        if not self.operator_only or self.automatic_rollback:
            raise RevisionEvaluationError("REVISION_ROLLBACK_AUTHORITY_INVALID")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {"schema_version": self.schema_version, "item_id": self.item_id, "target_knowledge_sha256": self.target_knowledge_sha256, "expected_current_sha256": self.expected_current_sha256, "operator_only": True, "automatic_rollback": False}


@dataclass(frozen=True)
class RevisionEffectivenessComparison:
    item_id: str
    domain: str
    base_knowledge_sha256: str
    revised_knowledge_sha256: str
    base_advisory_signal: str
    revised_advisory_signal: str
    isolated_task_observation_delta: int
    isolated_verified_success_delta: int
    isolated_failed_delta: int
    isolated_waiting_human_delta: int
    isolated_done_unverified_delta: int
    schema_version: str = REVISION_EFFECTIVENESS_COMPARISON_SCHEMA
    interpretation: str = EFFECTIVENESS_INTERPRETATION
    authority: str = "review_only_no_learning_store_mutation"

    def to_payload(self) -> dict[str, Any]:
        return self.__dict__.copy()


def compare_revision_effectiveness(package: RevisionEvaluationPackage, *, base: KnowledgeEffectivenessSignal, revised: KnowledgeEffectivenessSignal) -> RevisionEffectivenessComparison:
    """Compare exact Phase 4H observations; do not claim causality or auto-promote."""
    package.validate()
    if base.item_id != package.item_id or revised.item_id != package.item_id or base.domain != package.domain or revised.domain != package.domain or base.knowledge_sha256 != package.base_knowledge_sha256 or revised.knowledge_sha256 != package.candidate_knowledge_sha256 or base.interpretation != EFFECTIVENESS_INTERPRETATION or revised.interpretation != EFFECTIVENESS_INTERPRETATION:
        raise RevisionEvaluationError("REVISION_EFFECTIVENESS_BINDING_MISMATCH")
    return RevisionEffectivenessComparison(
        item_id=package.item_id, domain=package.domain,
        base_knowledge_sha256=base.knowledge_sha256, revised_knowledge_sha256=revised.knowledge_sha256,
        base_advisory_signal=base.advisory_signal, revised_advisory_signal=revised.advisory_signal,
        isolated_task_observation_delta=revised.isolated_task_observations - base.isolated_task_observations,
        isolated_verified_success_delta=revised.isolated_verified_success - base.isolated_verified_success,
        isolated_failed_delta=revised.isolated_failed - base.isolated_failed,
        isolated_waiting_human_delta=revised.isolated_waiting_human - base.isolated_waiting_human,
        isolated_done_unverified_delta=revised.isolated_done_unverified - base.isolated_done_unverified,
    )
