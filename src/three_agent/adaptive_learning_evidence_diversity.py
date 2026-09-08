"""Deterministic evidence-diversity policy for adaptive-learning candidates.

The policy evaluates exact ExperienceRecord/EvidenceReference provenance before
higher-trust evaluation or promotion. It is advisory/evaluation-only in v0.1:
it does not stage, promote, archive, materialize, invoke tools/models, or grant
runtime authority.

"Independent" means a distinct canonical source_task_id. The current learning
contract does not carry a source-device identity, so this module intentionally
does not claim device/vendor independence that cannot be proven.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from .adaptive_learning_contract import (
    DOMAINS,
    ExperienceRecord,
    KnowledgeCandidate,
    LearningContractError,
)

EVIDENCE_DIVERSITY_POLICY_SCHEMA = "workspace-learning-evidence-diversity-policy/v1"
EVIDENCE_DIVERSITY_ASSESSMENT_SCHEMA = "workspace-learning-evidence-diversity-assessment/v1"
EVIDENCE_DIVERSITY_AUTHORITY = "evaluation_policy_only_no_learning_or_runtime_mutation"
INDEPENDENCE_SEMANTICS = "distinct_source_task_id_only"

PROFILE_VALIDATED = "validated"
PROFILE_APPROVED = "approved"
PROFILE_ENTERPRISE = "enterprise"
PROFILES = {PROFILE_VALIDATED, PROFILE_APPROVED, PROFILE_ENTERPRISE}

_REASON = re.compile(r"^[A-Z0-9][A-Z0-9_]{0,95}$")
_MAX_EXPERIENCES = 32
_MAX_EVIDENCE = 128


class EvidenceDiversityError(ValueError):
    """Evidence diversity inputs are malformed, stale, or lineage-inconsistent."""


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _count(value: Any, field: str, *, minimum: int = 0, maximum: int = 128) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not minimum <= value <= maximum:
        raise EvidenceDiversityError(f"invalid {field}")
    return value


@dataclass(frozen=True)
class EvidenceDiversityPolicy:
    """Operator/evaluator-owned minimums; never an authority grant."""

    profile: str
    min_independent_tasks: int
    min_unique_evidence_hashes: int
    min_source_types: int
    min_collection_modes: int
    min_non_synthetic_tasks: int
    authority: str = EVIDENCE_DIVERSITY_AUTHORITY
    independence_semantics: str = INDEPENDENCE_SEMANTICS
    schema_version: str = EVIDENCE_DIVERSITY_POLICY_SCHEMA

    @classmethod
    def for_profile(cls, profile: str) -> "EvidenceDiversityPolicy":
        name = str(profile or "").strip().lower()
        defaults = {
            PROFILE_VALIDATED: (1, 1, 1, 1, 0),
            PROFILE_APPROVED: (2, 2, 1, 1, 1),
            PROFILE_ENTERPRISE: (3, 3, 2, 1, 2),
        }
        if name not in defaults:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_PROFILE_INVALID")
        tasks, hashes, source_types, modes, real_tasks = defaults[name]
        return cls(
            profile=name,
            min_independent_tasks=tasks,
            min_unique_evidence_hashes=hashes,
            min_source_types=source_types,
            min_collection_modes=modes,
            min_non_synthetic_tasks=real_tasks,
        ).validate()

    def validate(self) -> "EvidenceDiversityPolicy":
        if self.schema_version != EVIDENCE_DIVERSITY_POLICY_SCHEMA:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_POLICY_SCHEMA_INVALID")
        if self.authority != EVIDENCE_DIVERSITY_AUTHORITY:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_POLICY_AUTHORITY_INVALID")
        if self.independence_semantics != INDEPENDENCE_SEMANTICS:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_INDEPENDENCE_INVALID")
        if self.profile not in PROFILES:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_PROFILE_INVALID")
        _count(self.min_independent_tasks, "min_independent_tasks", minimum=1, maximum=32)
        _count(self.min_unique_evidence_hashes, "min_unique_evidence_hashes", minimum=1)
        _count(self.min_source_types, "min_source_types", minimum=1, maximum=16)
        _count(self.min_collection_modes, "min_collection_modes", minimum=1, maximum=16)
        _count(self.min_non_synthetic_tasks, "min_non_synthetic_tasks", maximum=32)
        if self.min_non_synthetic_tasks > self.min_independent_tasks:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_NON_SYNTHETIC_THRESHOLD_INVALID")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    @property
    def policy_sha256(self) -> str:
        return _digest(self.to_payload())


@dataclass(frozen=True)
class EvidenceDiversityAssessment:
    candidate_id: str
    candidate_sha256: str
    domain: str
    profile: str
    policy_sha256: str
    experience_count: int
    evidence_reference_count: int
    independent_task_count: int
    unique_evidence_hash_count: int
    unique_source_type_count: int
    unique_collection_mode_count: int
    synthetic_task_count: int
    non_synthetic_task_count: int
    passed: bool
    reason_codes: tuple[str, ...]
    authority: str = EVIDENCE_DIVERSITY_AUTHORITY
    independence_semantics: str = INDEPENDENCE_SEMANTICS
    schema_version: str = EVIDENCE_DIVERSITY_ASSESSMENT_SCHEMA

    def validate(self) -> "EvidenceDiversityAssessment":
        if self.schema_version != EVIDENCE_DIVERSITY_ASSESSMENT_SCHEMA:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_ASSESSMENT_SCHEMA_INVALID")
        if self.authority != EVIDENCE_DIVERSITY_AUTHORITY:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_ASSESSMENT_AUTHORITY_INVALID")
        if self.independence_semantics != INDEPENDENCE_SEMANTICS:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_INDEPENDENCE_INVALID")
        if not self.candidate_id or len(self.candidate_id) > 128:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_CANDIDATE_ID_INVALID")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.candidate_sha256):
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_CANDIDATE_SHA_INVALID")
        if self.domain not in DOMAINS or self.profile not in PROFILES:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_SCOPE_INVALID")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.policy_sha256):
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_POLICY_SHA_INVALID")
        for field in (
            "experience_count",
            "evidence_reference_count",
            "independent_task_count",
            "unique_evidence_hash_count",
            "unique_source_type_count",
            "unique_collection_mode_count",
            "synthetic_task_count",
            "non_synthetic_task_count",
        ):
            _count(getattr(self, field), field)
        if self.synthetic_task_count + self.non_synthetic_task_count != self.independent_task_count:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_TASK_PARTITION_INVALID")
        if not isinstance(self.passed, bool):
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_RESULT_INVALID")
        if len(self.reason_codes) > 16 or len(set(self.reason_codes)) != len(self.reason_codes):
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_REASONS_INVALID")
        for code in self.reason_codes:
            if not _REASON.fullmatch(code):
                raise EvidenceDiversityError("EVIDENCE_DIVERSITY_REASONS_INVALID")
        if self.passed != (not self.reason_codes):
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_RESULT_REASON_MISMATCH")
        return self

    def _base_payload(self) -> dict[str, Any]:
        self.validate()
        payload = asdict(self)
        payload["reason_codes"] = list(self.reason_codes)
        return payload

    @property
    def assessment_sha256(self) -> str:
        return _digest(self._base_payload())

    def to_payload(self) -> dict[str, Any]:
        return {**self._base_payload(), "assessment_sha256": self.assessment_sha256}


class DeterministicEvidenceDiversityEvaluator:
    """Bind exact candidate lineage to exact experiences and assess minimum diversity."""

    @staticmethod
    def _validated_source(
        candidate: KnowledgeCandidate,
        experiences: Iterable[ExperienceRecord],
    ) -> tuple[ExperienceRecord, ...]:
        try:
            candidate.validate()
        except LearningContractError as exc:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_CANDIDATE_INVALID") from exc
        source = tuple(experiences)
        if not 1 <= len(source) <= _MAX_EXPERIENCES:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_EXPERIENCE_COUNT_INVALID")

        experience_ids: list[str] = []
        experience_hashes: list[str] = []
        source_tasks: list[str] = []
        source_domains: list[str] = []
        source_sensitivities: list[str] = []
        source_outcomes: list[str] = []
        evidence_pairs: list[tuple[str, str]] = []
        evidence_count = 0
        for item in source:
            try:
                item.validate()
            except LearningContractError as exc:
                raise EvidenceDiversityError("EVIDENCE_DIVERSITY_EXPERIENCE_INVALID") from exc
            if item.domain != candidate.domain:
                raise EvidenceDiversityError("EVIDENCE_DIVERSITY_DOMAIN_MISMATCH")
            experience_ids.append(item.experience_id)
            experience_hashes.append(item.sha256)
            source_tasks.append(item.task_id)
            source_domains.append(item.domain)
            source_sensitivities.append(item.sensitivity)
            source_outcomes.append(item.outcome)
            for evidence in item.evidence:
                evidence_count += 1
                evidence_pairs.append((evidence.ref_id, evidence.sha256))
        if evidence_count > _MAX_EVIDENCE:
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_EVIDENCE_CAPACITY_EXCEEDED")
        if len(experience_ids) != len(set(experience_ids)) or len(experience_hashes) != len(set(experience_hashes)):
            raise EvidenceDiversityError("EVIDENCE_DIVERSITY_EXPERIENCE_DUPLICATE")

        expected_tasks = tuple(dict.fromkeys(source_tasks))
        expected_pairs = tuple(dict.fromkeys(evidence_pairs))
        bindings = (
            (candidate.source_experience_ids, tuple(experience_ids), "EXPERIENCE_ID"),
            (candidate.source_experience_hashes, tuple(experience_hashes), "EXPERIENCE_SHA"),
            (candidate.source_domains, tuple(source_domains), "SOURCE_DOMAIN"),
            (candidate.source_sensitivities, tuple(source_sensitivities), "SOURCE_SENSITIVITY"),
            (candidate.source_task_ids, expected_tasks, "SOURCE_TASK"),
            (candidate.source_outcomes, tuple(source_outcomes), "SOURCE_OUTCOME"),
            (candidate.evidence_ref_ids, tuple(pair[0] for pair in expected_pairs), "EVIDENCE_REF"),
            (candidate.evidence_hashes, tuple(pair[1] for pair in expected_pairs), "EVIDENCE_SHA"),
        )
        for actual, expected, label in bindings:
            if tuple(actual) != tuple(expected):
                raise EvidenceDiversityError(f"EVIDENCE_DIVERSITY_{label}_LINEAGE_MISMATCH")
        return source

    @classmethod
    def evaluate(
        cls,
        candidate: KnowledgeCandidate,
        experiences: Iterable[ExperienceRecord],
        policy: EvidenceDiversityPolicy,
    ) -> EvidenceDiversityAssessment:
        policy.validate()
        source = cls._validated_source(candidate, experiences)
        evidence = tuple(ref for item in source for ref in item.evidence)
        task_ids = {item.task_id for item in source}
        evidence_hashes = {item.sha256 for item in evidence}
        source_types = {item.source_type for item in evidence}
        collection_modes = {item.collection_mode for item in evidence}

        task_synthetic: dict[str, bool] = {}
        for item in source:
            flags = [ref.source_type == "synthetic_fixture" or ref.collection_mode == "synthetic" for ref in item.evidence]
            task_synthetic.setdefault(item.task_id, True)
            task_synthetic[item.task_id] = task_synthetic[item.task_id] and bool(flags) and all(flags)
        synthetic_tasks = sum(1 for value in task_synthetic.values() if value)
        non_synthetic_tasks = len(task_synthetic) - synthetic_tasks

        reasons: list[str] = []
        if len(task_ids) < policy.min_independent_tasks:
            reasons.append("INSUFFICIENT_INDEPENDENT_TASKS")
        if len(evidence_hashes) < policy.min_unique_evidence_hashes:
            reasons.append("INSUFFICIENT_UNIQUE_EVIDENCE")
        if len(source_types) < policy.min_source_types:
            reasons.append("INSUFFICIENT_SOURCE_TYPE_DIVERSITY")
        if len(collection_modes) < policy.min_collection_modes:
            reasons.append("INSUFFICIENT_COLLECTION_MODE_DIVERSITY")
        if non_synthetic_tasks < policy.min_non_synthetic_tasks:
            reasons.append("INSUFFICIENT_NON_SYNTHETIC_TASKS")
        if policy.profile in {PROFILE_APPROVED, PROFILE_ENTERPRISE} and non_synthetic_tasks == 0:
            reasons.append("SYNTHETIC_ONLY_EVIDENCE")

        return EvidenceDiversityAssessment(
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            domain=candidate.domain,
            profile=policy.profile,
            policy_sha256=policy.policy_sha256,
            experience_count=len(source),
            evidence_reference_count=len(evidence),
            independent_task_count=len(task_ids),
            unique_evidence_hash_count=len(evidence_hashes),
            unique_source_type_count=len(source_types),
            unique_collection_mode_count=len(collection_modes),
            synthetic_task_count=synthetic_tasks,
            non_synthetic_task_count=non_synthetic_tasks,
            passed=not reasons,
            reason_codes=tuple(dict.fromkeys(reasons)),
        ).validate()
