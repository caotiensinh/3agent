"""Controlled CandidateSkill projection and self-learning service.

``KnowledgeCandidate(kind="skill")`` remains the canonical learning object and
``AdaptiveLearningStore`` remains the canonical persistence boundary. This module
adds only a skill-specific projection, production-format preview, deterministic
security receipt, post-restart inspection, and a create-only staging service over
the existing verified reflection path.

The model may propose procedural knowledge. It cannot write ``skills/``, edit the
production registry, grant capabilities, promote, archive, or roll back learning
state through this surface.
"""
from __future__ import annotations

import hashlib
import json
import re
import threading
import unicodedata
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from .adaptive_learning_admission import VerifiedLearningSourceEnvelope
from .adaptive_learning_contract import KnowledgeCandidate, LearningContractError
from .adaptive_learning_evaluation import AdaptiveLearningDomainValidator
from .adaptive_learning_reflection import (
    ReflectionCoordinator,
    ReflectionOutcome,
    ReflectionReceiptStore,
    TrustedReflectionContentBroker,
)
from .adaptive_learning_reflection_contract import (
    ReflectionDomainBinding,
    ReflectionResult,
)
from .adaptive_learning_store import AdaptiveLearningStore
from .skills import (
    MAX_SKILL_BYTES,
    SkillSecurityError,
    _scan_instruction_text,
    _skill_digest,
)

CANDIDATE_SKILL_SCHEMA = "workspace-candidate-skill/v1"
CANDIDATE_SKILL_SECURITY_RECEIPT_SCHEMA = "workspace-candidate-skill-security-receipt/v1"
CANDIDATE_SKILL_LEARNING_OUTCOME_SCHEMA = "workspace-candidate-skill-learning-outcome/v1"
CANDIDATE_SKILL_INSPECTION_SCHEMA = "workspace-candidate-skill-inspection/v1"

_MAX_SKILL_NAME_CHARS = 64
_MAX_DESCRIPTION_CHARS = 240
_SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_BIDI_OR_TAG_RE = re.compile(r"[\u202a-\u202e\u2066-\u2069\U000E0000-\U000E007F]")


class CandidateSkillError(ValueError):
    """A learned candidate cannot safely become a production-skill proposal."""

    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _canonical_text_bytes(text: str) -> bytes:
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


def _safe_display_text(value: str, *, limit: int) -> str:
    """Return one compact UTF-8 display line without authority-bearing controls.

    Production skill names stay ASCII for portable paths, but descriptions and
    headings must remain multilingual. In particular, Japanese field knowledge
    must not be discarded merely because it cannot be ASCII-transliterated.
    """

    text = unicodedata.normalize("NFKC", " ".join(str(value or "").split())).strip()
    if not text:
        raise CandidateSkillError("CANDIDATE_SKILL_TEXT_EMPTY")
    if _BIDI_OR_TAG_RE.search(text):
        raise CandidateSkillError("CANDIDATE_SKILL_TEXT_UNSAFE")
    if any(ord(char) < 32 for char in text):
        raise CandidateSkillError("CANDIDATE_SKILL_TEXT_UNSAFE")
    return text[:limit].rstrip()


def _slug(value: str, *, suffix: str) -> str:
    folded = unicodedata.normalize("NFKD", str(value or ""))
    ascii_text = folded.encode("ascii", "ignore").decode("ascii").lower()
    stem = re.sub(r"[^a-z0-9]+", "-", ascii_text).strip("-") or "learned-skill"
    suffix = re.sub(r"[^a-f0-9]", "", suffix.lower())[:10] or "candidate"
    max_stem = max(1, _MAX_SKILL_NAME_CHARS - len(suffix) - 1)
    stem = stem[:max_stem].strip("-") or "learned"
    name = f"{stem}-{suffix}"
    if not _SKILL_NAME_RE.fullmatch(name):
        raise CandidateSkillError("CANDIDATE_SKILL_NAME_INVALID")
    return name


def _description(title: str, scope: str) -> str:
    title_text = _safe_display_text(title, limit=140)
    scope_text = _safe_display_text(scope, limit=72)
    text = f"Use this evidence-bound learned procedure for {scope_text}: {title_text}."
    if len(text) > _MAX_DESCRIPTION_CHARS:
        text = text[: _MAX_DESCRIPTION_CHARS - 1].rstrip(" .") + "."
    return text


def _render_document(*, name: str, title: str, scope: str, content: str) -> str:
    title_text = _safe_display_text(title, limit=160)
    scope_text = _safe_display_text(scope, limit=240)
    body = str(content or "").replace("\r\n", "\n").replace("\r", "\n").strip()
    if not body:
        raise CandidateSkillError("CANDIDATE_SKILL_CONTENT_EMPTY")
    description = _description(title_text, scope_text)
    return (
        "---\n"
        f"name: {name}\n"
        f"description: {description}\n"
        "---\n\n"
        f"# {title_text}\n\n"
        "## Scope\n\n"
        f"{scope_text}\n\n"
        "## Procedure\n\n"
        f"{body}\n"
    )


def _validate_rendered_document(name: str, document: str) -> tuple[bytes, str]:
    raw = _canonical_text_bytes(document)
    if len(raw) > MAX_SKILL_BYTES:
        raise CandidateSkillError("CANDIDATE_SKILL_PRODUCTION_SIZE_EXCEEDED")
    try:
        _scan_instruction_text(name, document)
    except SkillSecurityError as exc:
        raise CandidateSkillError("CANDIDATE_SKILL_SECURITY_SCAN_BLOCKED") from exc
    return raw, "sha256:" + _skill_digest(raw)


def _validate_domain_policy(candidate: KnowledgeCandidate) -> None:
    reasons = AdaptiveLearningDomainValidator.validate(candidate)
    if reasons:
        raise CandidateSkillError(
            "CANDIDATE_SKILL_DOMAIN_VALIDATION_BLOCKED:" + ",".join(reasons)
        )


def _preview_reflection_result(result: ReflectionResult) -> bool:
    """Return True only when a model result is a safe compact create proposal."""

    result.validate()
    if result.result != "CANDIDATE" or result.kind != "skill" or result.action != "create":
        return False
    try:
        # 64 chars is the maximum portable production skill name. Using the
        # maximum here makes the preview size check conservative.
        placeholder = "candidate-" + "a" * 54
        document = _render_document(
            name=placeholder,
            title=result.title,
            scope=result.scope,
            content=result.content,
        )
        _validate_rendered_document(placeholder, document)
    except CandidateSkillError:
        return False
    return True


@dataclass(frozen=True)
class CandidateSkill:
    """Skill-specific immutable view over canonical ``KnowledgeCandidate``."""

    candidate_id: str
    candidate_sha256: str
    domain: str
    action: str
    sensitivity: str
    risk_level: str
    proposed_skill_name: str
    proposed_skill_sha256: str
    proposed_skill_size_bytes: int
    source_experience_count: int
    unique_source_task_count: int
    evidence_ref_count: int
    unique_evidence_hash_count: int
    provenance_sha256: str
    schema_version: str = CANDIDATE_SKILL_SCHEMA

    @classmethod
    def from_candidate(cls, candidate: KnowledgeCandidate) -> "CandidateSkill":
        try:
            candidate.validate()
        except LearningContractError as exc:
            raise CandidateSkillError("CANDIDATE_SKILL_CONTRACT_INVALID") from exc
        if candidate.kind != "skill":
            raise CandidateSkillError("CANDIDATE_SKILL_KIND_REQUIRED")
        # V1 deliberately supports create only. Patch/supersede require exact
        # production-name and active-version lineage and are implemented later.
        if candidate.action != "create":
            raise CandidateSkillError("CANDIDATE_SKILL_CREATE_ONLY")
        if any(outcome != "verified_success" for outcome in candidate.source_outcomes):
            raise CandidateSkillError("CANDIDATE_SKILL_VERIFIED_SUCCESS_REQUIRED")
        _validate_domain_policy(candidate)

        candidate_sha = candidate.sha256
        if not _SHA_RE.fullmatch(candidate_sha):
            raise CandidateSkillError("CANDIDATE_SKILL_SHA_INVALID")
        name = _slug(candidate.title, suffix=candidate_sha.split(":", 1)[1])
        document = _render_document(
            name=name,
            title=candidate.title,
            scope=candidate.scope,
            content=candidate.content,
        )
        raw, document_sha = _validate_rendered_document(name, document)
        provenance = {
            "schema_version": "workspace-candidate-skill-provenance/v1",
            "candidate_id": candidate.candidate_id,
            "candidate_sha256": candidate_sha,
            "domain": candidate.domain,
            "action": candidate.action,
            "source_experience_ids": list(candidate.source_experience_ids),
            "source_experience_hashes": list(candidate.source_experience_hashes),
            "source_task_ids": list(candidate.source_task_ids),
            "source_outcomes": list(candidate.source_outcomes),
            "evidence_ref_ids": list(candidate.evidence_ref_ids),
            "evidence_hashes": list(candidate.evidence_hashes),
        }
        return cls(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate_sha,
            domain=candidate.domain,
            action=candidate.action,
            sensitivity=candidate.sensitivity,
            risk_level=candidate.risk_level,
            proposed_skill_name=name,
            proposed_skill_sha256=document_sha,
            proposed_skill_size_bytes=len(raw),
            source_experience_count=len(candidate.source_experience_ids),
            unique_source_task_count=len(set(candidate.source_task_ids)),
            evidence_ref_count=len(candidate.evidence_ref_ids),
            unique_evidence_hash_count=len(set(candidate.evidence_hashes)),
            provenance_sha256=_digest(provenance),
        ).validate()

    def validate(self) -> "CandidateSkill":
        if self.schema_version != CANDIDATE_SKILL_SCHEMA:
            raise CandidateSkillError("CANDIDATE_SKILL_SCHEMA_INVALID")
        if self.action != "create":
            raise CandidateSkillError("CANDIDATE_SKILL_CREATE_ONLY")
        for value, code in (
            (self.candidate_sha256, "CANDIDATE_SKILL_SHA_INVALID"),
            (self.proposed_skill_sha256, "CANDIDATE_SKILL_DOCUMENT_SHA_INVALID"),
            (self.provenance_sha256, "CANDIDATE_SKILL_PROVENANCE_SHA_INVALID"),
        ):
            if not _SHA_RE.fullmatch(value):
                raise CandidateSkillError(code)
        if not _SKILL_NAME_RE.fullmatch(self.proposed_skill_name):
            raise CandidateSkillError("CANDIDATE_SKILL_NAME_INVALID")
        if not 1 <= self.proposed_skill_size_bytes <= MAX_SKILL_BYTES:
            raise CandidateSkillError("CANDIDATE_SKILL_PRODUCTION_SIZE_EXCEEDED")
        for value, code in (
            (self.source_experience_count, "CANDIDATE_SKILL_EXPERIENCE_COUNT_INVALID"),
            (self.unique_source_task_count, "CANDIDATE_SKILL_TASK_COUNT_INVALID"),
            (self.evidence_ref_count, "CANDIDATE_SKILL_EVIDENCE_COUNT_INVALID"),
            (self.unique_evidence_hash_count, "CANDIDATE_SKILL_EVIDENCE_HASH_COUNT_INVALID"),
        ):
            if not isinstance(value, int) or isinstance(value, bool) or value < 1:
                raise CandidateSkillError(code)
        if self.unique_source_task_count > self.source_experience_count:
            raise CandidateSkillError("CANDIDATE_SKILL_TASK_COVERAGE_INVALID")
        if self.unique_evidence_hash_count > self.evidence_ref_count:
            raise CandidateSkillError("CANDIDATE_SKILL_EVIDENCE_COVERAGE_INVALID")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    @staticmethod
    def render_proposed_document(candidate: KnowledgeCandidate) -> str:
        view = CandidateSkill.from_candidate(candidate)
        document = _render_document(
            name=view.proposed_skill_name,
            title=candidate.title,
            scope=candidate.scope,
            content=candidate.content,
        )
        raw, sha = _validate_rendered_document(view.proposed_skill_name, document)
        if len(raw) != view.proposed_skill_size_bytes or sha != view.proposed_skill_sha256:
            raise CandidateSkillError("CANDIDATE_SKILL_DOCUMENT_BINDING_MISMATCH")
        return document


@dataclass(frozen=True)
class CandidateSkillSecurityReceipt:
    candidate_id: str
    candidate_sha256: str
    proposed_skill_name: str
    proposed_skill_sha256: str
    proposed_skill_size_bytes: int
    provenance_sha256: str
    checks: tuple[str, ...]
    capability_grants: tuple[str, ...] = ()
    schema_version: str = CANDIDATE_SKILL_SECURITY_RECEIPT_SCHEMA

    @classmethod
    def create(cls, candidate: KnowledgeCandidate) -> "CandidateSkillSecurityReceipt":
        view = CandidateSkill.from_candidate(candidate)
        return cls(
            candidate_id=view.candidate_id,
            candidate_sha256=view.candidate_sha256,
            proposed_skill_name=view.proposed_skill_name,
            proposed_skill_sha256=view.proposed_skill_sha256,
            proposed_skill_size_bytes=view.proposed_skill_size_bytes,
            provenance_sha256=view.provenance_sha256,
            checks=(
                "CANDIDATE_KIND_SKILL",
                "VERIFIED_SUCCESS_LINEAGE",
                "EVIDENCE_BOUND",
                "DOMAIN_POLICY_VALIDATION",
                "PRODUCTION_SIZE_BOUND",
                "SKILL_CONTENT_SECURITY_SCAN",
                "NO_CAPABILITY_GRANTS",
            ),
        ).validate()

    def validate(self) -> "CandidateSkillSecurityReceipt":
        if self.schema_version != CANDIDATE_SKILL_SECURITY_RECEIPT_SCHEMA:
            raise CandidateSkillError("CANDIDATE_SKILL_RECEIPT_SCHEMA_INVALID")
        if self.capability_grants != ():
            raise CandidateSkillError("CANDIDATE_SKILL_CAPABILITY_GRANT_FORBIDDEN")
        for value in (
            self.candidate_sha256,
            self.proposed_skill_sha256,
            self.provenance_sha256,
        ):
            if not _SHA_RE.fullmatch(value):
                raise CandidateSkillError("CANDIDATE_SKILL_RECEIPT_SHA_INVALID")
        expected_checks = {
            "CANDIDATE_KIND_SKILL",
            "VERIFIED_SUCCESS_LINEAGE",
            "EVIDENCE_BOUND",
            "DOMAIN_POLICY_VALIDATION",
            "PRODUCTION_SIZE_BOUND",
            "SKILL_CONTENT_SECURITY_SCAN",
            "NO_CAPABILITY_GRANTS",
        }
        if set(self.checks) != expected_checks or len(self.checks) != len(expected_checks):
            raise CandidateSkillError("CANDIDATE_SKILL_RECEIPT_CHECKS_INVALID")
        if not _SKILL_NAME_RE.fullmatch(self.proposed_skill_name):
            raise CandidateSkillError("CANDIDATE_SKILL_NAME_INVALID")
        if not 1 <= self.proposed_skill_size_bytes <= MAX_SKILL_BYTES:
            raise CandidateSkillError("CANDIDATE_SKILL_PRODUCTION_SIZE_EXCEEDED")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        payload = asdict(self)
        payload["checks"] = list(self.checks)
        payload["capability_grants"] = []
        return payload

    @property
    def sha256(self) -> str:
        return _digest(self.to_payload())


class _SkillOnlyReflectionRunner:
    """Filter generic reflection output before candidate construction/staging."""

    def __init__(self, delegate: Any):
        self._delegate = delegate

    def run(self, packet: Any) -> ReflectionResult:
        result = self._delegate.run(packet)
        result.validate()
        if result.result == "NO_LEARNING_VALUE":
            return result
        if _preview_reflection_result(result):
            return result
        # The generic ReflectionCoordinator claims replay identity before model
        # execution. Returning the strict no-value shape lets that canonical path
        # close its receipt instead of leaving an invalid skill proposal claimed.
        return ReflectionResult(
            result="NO_LEARNING_VALUE",
            kind="none",
            title="",
            content="",
            scope="",
            action="none",
            execution_mode="none",
            reusable_value_reason="Candidate did not satisfy the controlled skill-learning contract.",
        ).validate()


class _CandidateSkillStagingGateway:
    """Guard one exact candidate before the canonical stage-only gateway."""

    def __init__(self, delegate: Any):
        self._delegate = delegate
        self._receipts: dict[str, CandidateSkillSecurityReceipt] = {}
        self._lock = threading.Lock()

    def stage(self, candidate: KnowledgeCandidate) -> dict[str, Any]:
        receipt = CandidateSkillSecurityReceipt.create(candidate)
        result = self._delegate.stage(candidate)
        with self._lock:
            self._receipts[candidate.sha256] = receipt
        return result

    def receipt_for(self, candidate_sha256: str) -> CandidateSkillSecurityReceipt | None:
        with self._lock:
            return self._receipts.get(str(candidate_sha256 or "").strip().lower())


@dataclass(frozen=True)
class CandidateSkillLearningOutcome:
    result: str
    admission_id: str
    domain: str
    candidate_id: str | None
    candidate_sha256: str | None
    security_receipt_sha256: str | None
    proposed_skill_name: str | None
    schema_version: str = CANDIDATE_SKILL_LEARNING_OUTCOME_SCHEMA

    def validate(self) -> "CandidateSkillLearningOutcome":
        if self.schema_version != CANDIDATE_SKILL_LEARNING_OUTCOME_SCHEMA:
            raise CandidateSkillError("CANDIDATE_SKILL_OUTCOME_SCHEMA_INVALID")
        if self.result == "STAGED":
            if not self.candidate_id or not _ID_RE.fullmatch(self.candidate_id):
                raise CandidateSkillError("CANDIDATE_SKILL_OUTCOME_CANDIDATE_ID_INVALID")
            if not self.candidate_sha256 or not _SHA_RE.fullmatch(self.candidate_sha256):
                raise CandidateSkillError("CANDIDATE_SKILL_OUTCOME_CANDIDATE_SHA_INVALID")
            if not self.security_receipt_sha256 or not _SHA_RE.fullmatch(
                self.security_receipt_sha256
            ):
                raise CandidateSkillError("CANDIDATE_SKILL_OUTCOME_RECEIPT_SHA_INVALID")
            if not self.proposed_skill_name or not _SKILL_NAME_RE.fullmatch(
                self.proposed_skill_name
            ):
                raise CandidateSkillError("CANDIDATE_SKILL_OUTCOME_NAME_INVALID")
        elif self.result == "NO_LEARNING_VALUE":
            if any(
                value is not None
                for value in (
                    self.candidate_id,
                    self.candidate_sha256,
                    self.security_receipt_sha256,
                    self.proposed_skill_name,
                )
            ):
                raise CandidateSkillError("CANDIDATE_SKILL_NO_VALUE_METADATA_FORBIDDEN")
        else:
            raise CandidateSkillError("CANDIDATE_SKILL_OUTCOME_RESULT_INVALID")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class CandidateSkillInspection:
    """Audit-safe post-restart projection of one canonical stored skill candidate."""

    candidate_id: str
    candidate_sha256: str
    item_id: str
    knowledge_sha256: str
    level: str
    disposition: str
    proposed_skill_name: str
    proposed_skill_sha256: str
    provenance_sha256: str
    security_receipt_sha256: str
    schema_version: str = CANDIDATE_SKILL_INSPECTION_SCHEMA

    def validate(self) -> "CandidateSkillInspection":
        if self.schema_version != CANDIDATE_SKILL_INSPECTION_SCHEMA:
            raise CandidateSkillError("CANDIDATE_SKILL_INSPECTION_SCHEMA_INVALID")
        for value, code in (
            (self.candidate_sha256, "CANDIDATE_SKILL_INSPECTION_CANDIDATE_SHA_INVALID"),
            (self.knowledge_sha256, "CANDIDATE_SKILL_INSPECTION_KNOWLEDGE_SHA_INVALID"),
            (self.proposed_skill_sha256, "CANDIDATE_SKILL_INSPECTION_DOCUMENT_SHA_INVALID"),
            (self.provenance_sha256, "CANDIDATE_SKILL_INSPECTION_PROVENANCE_SHA_INVALID"),
            (self.security_receipt_sha256, "CANDIDATE_SKILL_INSPECTION_RECEIPT_SHA_INVALID"),
        ):
            if not _SHA_RE.fullmatch(value):
                raise CandidateSkillError(code)
        if not _ID_RE.fullmatch(self.candidate_id) or not _ID_RE.fullmatch(self.item_id):
            raise CandidateSkillError("CANDIDATE_SKILL_INSPECTION_ID_INVALID")
        if self.level not in {"candidate", "validated", "approved", "enterprise"}:
            raise CandidateSkillError("CANDIDATE_SKILL_INSPECTION_LEVEL_INVALID")
        if self.disposition not in {"staged", "active_snapshot"}:
            raise CandidateSkillError("CANDIDATE_SKILL_INSPECTION_DISPOSITION_INVALID")
        if not _SKILL_NAME_RE.fullmatch(self.proposed_skill_name):
            raise CandidateSkillError("CANDIDATE_SKILL_INSPECTION_NAME_INVALID")
        return self

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


class CandidateSkillInspector:
    """Read one skill candidate through canonical store integrity checks.

    The store remains authoritative. This adapter reuses its ledger and immutable
    candidate-row verification and derives the security receipt from exact stored
    candidate bytes, so no additional receipt database or restart-sensitive RAM
    state is required.
    """

    def __init__(self, store: AdaptiveLearningStore):
        self._store = store

    def inspect(self, candidate_id: str) -> CandidateSkillInspection:
        candidate_key = str(candidate_id or "").strip()
        if not _ID_RE.fullmatch(candidate_key):
            raise CandidateSkillError("CANDIDATE_SKILL_INSPECTION_ID_INVALID")
        with self._store.connect() as conn:
            self._store._assert_ledger_integrity(conn)
            row = self._store._candidate_level_row(conn, candidate_key)
            if row is None:
                raise CandidateSkillError("CANDIDATE_SKILL_NOT_FOUND")
            candidate = self._store._candidate_from_row(row)
            view = CandidateSkill.from_candidate(candidate)
            receipt = CandidateSkillSecurityReceipt.create(candidate)
            return CandidateSkillInspection(
                candidate_id=candidate.candidate_id,
                candidate_sha256=candidate.sha256,
                item_id=str(row["item_id"]),
                knowledge_sha256=str(row["knowledge_sha256"]),
                level=str(row["level"]),
                disposition=str(row["disposition"]),
                proposed_skill_name=view.proposed_skill_name,
                proposed_skill_sha256=view.proposed_skill_sha256,
                provenance_sha256=view.provenance_sha256,
                security_receipt_sha256=receipt.sha256,
            ).validate()


class CandidateSkillLearningService:
    """Agent-facing staging-only self-learning service for new skill candidates.

    Inputs are the existing capability-free verified source envelope, a trusted
    domain binding, and exact admitted evidence bytes. The service does not accept
    a production skill path or registry path and exposes create only. Promotion is
    intentionally absent from this API.
    """

    def __init__(
        self,
        staging_gateway: Any,
        runner: Any,
        receipt_store: ReflectionReceiptStore,
        *,
        broker: TrustedReflectionContentBroker | None = None,
    ):
        self._staging = _CandidateSkillStagingGateway(staging_gateway)
        self._coordinator = ReflectionCoordinator(
            self._staging,
            _SkillOnlyReflectionRunner(runner),
            receipt_store,
            broker=broker,
        )

    def create(
        self,
        envelope: VerifiedLearningSourceEnvelope,
        binding: ReflectionDomainBinding,
        evidence_payloads: Mapping[str, bytes],
    ) -> CandidateSkillLearningOutcome:
        envelope.to_payload()
        if envelope.capability_grants:
            raise CandidateSkillError("CANDIDATE_SKILL_SOURCE_CAPABILITY_GRANT_FORBIDDEN")
        outcome: ReflectionOutcome = self._coordinator.reflect_and_stage(
            envelope,
            binding,
            evidence_payloads,
            allowed_action="create",
        )
        if outcome.result != "STAGED" or outcome.candidate_sha256 is None:
            return CandidateSkillLearningOutcome(
                result=outcome.result,
                admission_id=outcome.admission_id,
                domain=outcome.domain,
                candidate_id=None,
                candidate_sha256=None,
                security_receipt_sha256=None,
                proposed_skill_name=None,
            ).validate()
        receipt = self._staging.receipt_for(outcome.candidate_sha256)
        if receipt is None:
            raise CandidateSkillError("CANDIDATE_SKILL_SECURITY_RECEIPT_MISSING")
        return CandidateSkillLearningOutcome(
            result="STAGED",
            admission_id=outcome.admission_id,
            domain=outcome.domain,
            candidate_id=outcome.candidate_id,
            candidate_sha256=outcome.candidate_sha256,
            security_receipt_sha256=receipt.sha256,
            proposed_skill_name=receipt.proposed_skill_name,
        ).validate()
