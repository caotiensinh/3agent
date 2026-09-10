"""Exact staged skill-revision identity for held-out evaluation.

The subject is derived only from an already-PASS Phase 4K RevisionEvaluationPackage
and the exact immutable KnowledgeCandidate bound by that package.  Rendering reuses
the same canonical helpers used by production supersession.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any

from .adaptive_learning_contract import KnowledgeCandidate
from .adaptive_learning_revision_evaluation import RevisionEvaluationPackage
from .candidate_skill import (
    CandidateSkillError,
    _render_document,
    _slug,
    _validate_domain_policy,
    _validate_rendered_document,
)

SCHEMA_VERSION = "workspace-heldout-candidate-skill-subject/v1"
AUTHORITY = "evaluation_identity_only_no_stage_promotion_or_runtime_mutation"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class CandidateSkillEvaluationSubjectError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha_payload(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True)
class CandidateSkillEvaluationSubject:
    candidate_id: str
    candidate_sha256: str
    candidate_knowledge_sha256: str
    item_id: str
    base_knowledge_sha256: str
    domain: str
    skill_name: str
    skill_sha256: str
    skill_size_bytes: int
    revision_evaluation_sha256: str
    authority: str = AUTHORITY
    schema_version: str = SCHEMA_VERSION

    def validate(self) -> "CandidateSkillEvaluationSubject":
        if self.schema_version != SCHEMA_VERSION or self.authority != AUTHORITY:
            raise CandidateSkillEvaluationSubjectError("CANDIDATE_SUBJECT_HEADER_INVALID")
        if not _ID.fullmatch(self.candidate_id) or not _ID.fullmatch(self.item_id):
            raise CandidateSkillEvaluationSubjectError("CANDIDATE_SUBJECT_ID_INVALID")
        for value in (
            self.candidate_sha256,
            self.candidate_knowledge_sha256,
            self.base_knowledge_sha256,
            self.skill_sha256,
            self.revision_evaluation_sha256,
        ):
            if not _SHA.fullmatch(value):
                raise CandidateSkillEvaluationSubjectError("CANDIDATE_SUBJECT_SHA_INVALID")
        if not self.domain or len(self.domain) > 64:
            raise CandidateSkillEvaluationSubjectError("CANDIDATE_SUBJECT_DOMAIN_INVALID")
        if not self.skill_name or len(self.skill_name) > 64:
            raise CandidateSkillEvaluationSubjectError("CANDIDATE_SUBJECT_SKILL_NAME_INVALID")
        if not isinstance(self.skill_size_bytes, int) or isinstance(self.skill_size_bytes, bool) or self.skill_size_bytes < 1:
            raise CandidateSkillEvaluationSubjectError("CANDIDATE_SUBJECT_SIZE_INVALID")
        return self

    @property
    def subject_sha256(self) -> str:
        self.validate()
        return _sha_payload(asdict(self))

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["subject_sha256"] = self.subject_sha256
        return payload

    @classmethod
    def from_revision(
        cls,
        package: RevisionEvaluationPackage,
        candidate: KnowledgeCandidate,
    ) -> "CandidateSkillEvaluationSubject":
        try:
            package.validate()
            candidate.validate()
        except Exception as exc:
            raise CandidateSkillEvaluationSubjectError("CANDIDATE_SUBJECT_INPUT_INVALID") from exc
        if package.result != "PASS":
            raise CandidateSkillEvaluationSubjectError("CANDIDATE_SUBJECT_PHASE4K_PASS_REQUIRED")
        if package.kind != "skill" or candidate.kind != "skill" or candidate.action != "patch":
            raise CandidateSkillEvaluationSubjectError("CANDIDATE_SUBJECT_SKILL_PATCH_REQUIRED")
        if (
            candidate.candidate_id != package.candidate_id
            or candidate.sha256 != package.candidate_sha256
            or candidate.domain != package.domain
            or candidate.target_item_id != package.item_id
            or candidate.base_item_sha256 != package.base_knowledge_sha256
        ):
            raise CandidateSkillEvaluationSubjectError("CANDIDATE_SUBJECT_PHASE4K_BINDING_MISMATCH")
        try:
            _validate_domain_policy(candidate)
            name = _slug(candidate.title, suffix=candidate.sha256.split(":", 1)[1])
            document = _render_document(
                name=name,
                title=candidate.title,
                scope=candidate.scope,
                content=candidate.content,
            )
            raw, digest = _validate_rendered_document(name, document)
        except CandidateSkillError as exc:
            raise CandidateSkillEvaluationSubjectError("CANDIDATE_SUBJECT_RENDER_BLOCKED") from exc
        return cls(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            candidate_knowledge_sha256=package.candidate_knowledge_sha256,
            item_id=package.item_id,
            base_knowledge_sha256=package.base_knowledge_sha256,
            domain=package.domain,
            skill_name=name,
            skill_sha256=digest,
            skill_size_bytes=len(raw),
            revision_evaluation_sha256=package.evaluation_sha256,
        ).validate()
