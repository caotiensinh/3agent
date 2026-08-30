"""Deterministic, runtime-inert contracts for WorkSpace adaptive learning."""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from .task_contract import RISK_LEVELS, SENSITIVITIES

SCHEMAS = {
    "evidence": "workspace-learning-evidence/v1",
    "experience": "workspace-learning-experience/v1",
    "candidate": "workspace-learning-candidate/v1",
    "contradiction": "workspace-learning-contradiction/v1",
    "receipt": "workspace-learning-validation-receipt/v1",
}
DOMAINS = {"network", "security", "analyst", "general"}
KINDS = {"memory", "skill", "analytical_pattern", "reference"}
OUTCOMES = {"verified_success", "verified_failure", "partial", "unresolved"}
OWNERS = {"system", "user_team", "learner_managed"}
ACTIONS = {"create", "patch", "supersede"}
LEVELS = ("candidate", "validated", "approved", "enterprise")
EXECUTION_MODES = {"analysis_only", "passive", "read_only", "offline", "synthetic"}
COLLECTION_MODES = {"passive", "read_only", "offline", "synthetic", "local_artifact"}
SOURCE_TYPES = {"syslog", "application_log", "pcap", "device_snapshot", "monitoring_export",
                "read_only_status", "inventory", "synthetic_fixture", "task_artifact", "document", "other"}

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_CHECK = re.compile(r"^[A-Z0-9][A-Z0-9_]{0,95}$")
_INJECTION = (
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|system|developer)\s+instructions", re.I),
    re.compile(r"disable\s+(?:the\s+)?security\s+(?:policy|gate|controls?)", re.I),
    re.compile(r"bypass\s+(?:the\s+)?(?:approval|policy|security|audit)", re.I),
    re.compile(r"exfiltrat(?:e|ion).{0,48}(?:credential|secret|token|password|key)", re.I),
)


class LearningContractError(ValueError):
    pass


def _strict(payload: Any, schema: str, fields: set[str]) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != fields or payload.get("schema_version") != schema:
        raise LearningContractError(f"invalid or non-strict payload for {schema}")
    return dict(payload)


def _id(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not _ID.fullmatch(text):
        raise LearningContractError(f"invalid {name}")
    return text


def _sha(value: Any, name: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise LearningContractError(f"invalid {name}")
    return text


def _utc(value: Any, name: str) -> str:
    text = str(value or "").strip()
    if not _UTC.fullmatch(text):
        raise LearningContractError(f"invalid {name}")
    return text


def _enum(value: Any, allowed: set[str], name: str) -> str:
    text = str(value or "").strip()
    if text not in allowed:
        raise LearningContractError(f"unsupported {name}: {text}")
    return text


def _text(value: Any, name: str, limit: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > limit or any(ord(char) < 32 and char not in "\n\t\r" for char in text):
        raise LearningContractError(f"invalid {name}")
    return text


def _seq(values: Any, validator, name: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise LearningContractError(f"invalid {name}")
    output = tuple(validator(value, name) for value in values)
    if not output or len(output) > 32 or len(set(output)) != len(output):
        raise LearningContractError(f"invalid {name}")
    return output


def _scan(text: str) -> None:
    if any(char in text for char in ("\u200b", "\u200c", "\u200d", "\ufeff")) or any(
        pattern.search(text) for pattern in _INJECTION
    ):
        raise LearningContractError("persistent learning content failed security scan")


def _jsonable(obj: Any) -> Any:
    if isinstance(obj, tuple):
        return [_jsonable(value) for value in obj]
    if isinstance(obj, list):
        return [_jsonable(value) for value in obj]
    if isinstance(obj, dict):
        return {str(key): _jsonable(value) for key, value in obj.items()}
    return obj


def _payload(obj: Any) -> dict[str, Any]:
    return _jsonable(asdict(obj))


def _digest(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class EvidenceReference:
    ref_id: str
    sha256: str
    source_type: str
    source_task_id: str
    sensitivity: str
    collection_mode: str
    created_at: str
    vendor_family: str | None = None
    version: str | None = None
    schema_version: str = SCHEMAS["evidence"]

    FIELDS = {
        "schema_version", "ref_id", "sha256", "source_type", "source_task_id", "sensitivity",
        "collection_mode", "created_at", "vendor_family", "version"
    }

    def validate(self):
        _id(self.ref_id, "ref_id")
        _sha(self.sha256, "sha256")
        _enum(self.source_type, SOURCE_TYPES, "source_type")
        _id(self.source_task_id, "source_task_id")
        _enum(self.sensitivity, SENSITIVITIES, "sensitivity")
        _enum(self.collection_mode, COLLECTION_MODES, "collection_mode")
        _utc(self.created_at, "created_at")
        for name, value in (("vendor_family", self.vendor_family), ("version", self.version)):
            if value is not None and len(str(value)) > 240:
                raise LearningContractError(f"invalid {name}")
        return self

    def to_payload(self):
        self.validate()
        return _payload(self)

    @classmethod
    def from_payload(cls, payload):
        return cls(**_strict(payload, SCHEMAS["evidence"], cls.FIELDS)).validate()


@dataclass(frozen=True)
class ExperienceRecord:
    experience_id: str
    domain: str
    task_id: str
    outcome: str
    sensitivity: str
    summary: str
    evidence: tuple[EvidenceReference, ...]
    created_at: str
    schema_version: str = SCHEMAS["experience"]

    FIELDS = {
        "schema_version", "experience_id", "domain", "task_id", "outcome", "sensitivity",
        "summary", "evidence", "created_at"
    }

    def validate(self):
        _id(self.experience_id, "experience_id")
        _enum(self.domain, DOMAINS, "domain")
        _id(self.task_id, "task_id")
        _enum(self.outcome, OUTCOMES, "outcome")
        _enum(self.sensitivity, SENSITIVITIES, "sensitivity")
        _text(self.summary, "summary", 4000)
        if not self.evidence or len(self.evidence) > 32:
            raise LearningContractError("invalid evidence")
        refs = set()
        for item in self.evidence:
            item.validate()
            if item.ref_id in refs or item.source_task_id != self.task_id:
                raise LearningContractError("evidence lineage mismatch")
            refs.add(item.ref_id)
        _utc(self.created_at, "created_at")
        return self

    def to_payload(self):
        self.validate()
        return _payload(self)

    @classmethod
    def from_payload(cls, payload):
        data = _strict(payload, SCHEMAS["experience"], cls.FIELDS)
        if not isinstance(data["evidence"], list):
            raise LearningContractError("evidence must be a list")
        data["evidence"] = tuple(EvidenceReference.from_payload(item) for item in data["evidence"])
        return cls(**data).validate()


@dataclass(frozen=True)
class KnowledgeCandidate:
    candidate_id: str
    domain: str
    kind: str
    title: str
    content: str
    scope: str
    sensitivity: str
    risk_level: str
    ownership: str
    action: str
    execution_mode: str
    source_experience_ids: tuple[str, ...]
    source_task_ids: tuple[str, ...]
    source_outcomes: tuple[str, ...]
    evidence_ref_ids: tuple[str, ...]
    evidence_hashes: tuple[str, ...]
    target_item_id: str | None
    base_item_sha256: str | None
    created_at: str
    schema_version: str = SCHEMAS["candidate"]

    FIELDS = {
        "schema_version", "candidate_id", "domain", "kind", "title", "content", "scope",
        "sensitivity", "risk_level", "ownership", "action", "execution_mode",
        "source_experience_ids", "source_task_ids", "source_outcomes", "evidence_ref_ids",
        "evidence_hashes", "target_item_id", "base_item_sha256", "created_at"
    }

    def validate(self):
        _id(self.candidate_id, "candidate_id")
        _enum(self.domain, DOMAINS, "domain")
        _enum(self.kind, KINDS, "kind")
        title = _text(self.title, "title", 160)
        content = _text(self.content, "content", 12000)
        _scan(title + "\n" + content)
        _text(self.scope, "scope", 240)
        _enum(self.sensitivity, SENSITIVITIES, "sensitivity")
        _enum(self.risk_level, RISK_LEVELS, "risk_level")
        _enum(self.ownership, OWNERS, "ownership")
        _enum(self.action, ACTIONS, "action")
        _enum(self.execution_mode, EXECUTION_MODES, "execution_mode")
        experience_ids = _seq(self.source_experience_ids, _id, "source_experience_ids")
        _seq(self.source_task_ids, _id, "source_task_ids")
        if not isinstance(self.source_outcomes, tuple) or len(self.source_outcomes) != len(experience_ids):
            raise LearningContractError("source outcome mismatch")
        for outcome in self.source_outcomes:
            _enum(outcome, OUTCOMES, "source_outcome")
        if self.kind in {"memory", "skill"} and any(
            outcome != "verified_success" for outcome in self.source_outcomes
        ):
            raise LearningContractError("memory/skill requires verified-success experience")
        refs = _seq(self.evidence_ref_ids, _id, "evidence_ref_ids")
        hashes = _seq(self.evidence_hashes, _sha, "evidence_hashes")
        if len(refs) != len(hashes):
            raise LearningContractError("evidence reference/hash mismatch")
        if self.action == "create":
            if self.target_item_id is not None or self.base_item_sha256 is not None:
                raise LearningContractError("create cannot specify base item")
        else:
            _id(self.target_item_id, "target_item_id")
            _sha(self.base_item_sha256, "base_item_sha256")
        _utc(self.created_at, "created_at")
        return self

    @classmethod
    def from_experiences(cls, *, experiences: Iterable[ExperienceRecord], **kwargs):
        source = tuple(experiences)
        domain = str(kwargs.get("domain") or "")
        if not source:
            raise LearningContractError("candidate requires experience")
        for item in source:
            item.validate()
            if item.domain != domain:
                raise LearningContractError("candidate/source domain mismatch")
        evidence = tuple(ref for item in source for ref in item.evidence)
        kwargs.setdefault("target_item_id", None)
        kwargs.setdefault("base_item_sha256", None)
        pairs = list(dict.fromkeys((ref.ref_id, ref.sha256) for ref in evidence))
        return cls(
            source_experience_ids=tuple(item.experience_id for item in source),
            source_task_ids=tuple(dict.fromkeys(item.task_id for item in source)),
            source_outcomes=tuple(item.outcome for item in source),
            evidence_ref_ids=tuple(pair[0] for pair in pairs),
            evidence_hashes=tuple(pair[1] for pair in pairs),
            **kwargs,
        ).validate()

    def to_payload(self):
        self.validate()
        return _payload(self)

    @property
    def sha256(self):
        return _digest(self.to_payload())

    @classmethod
    def from_payload(cls, payload):
        data = _strict(payload, SCHEMAS["candidate"], cls.FIELDS)
        for key in (
            "source_experience_ids", "source_task_ids", "source_outcomes",
            "evidence_ref_ids", "evidence_hashes"
        ):
            if not isinstance(data[key], list):
                raise LearningContractError(f"{key} must be a list")
            data[key] = tuple(data[key])
        return cls(**data).validate()


@dataclass(frozen=True)
class ContradictionRecord:
    contradiction_id: str
    candidate_id: str
    evidence_ref_ids: tuple[str, ...]
    evidence_hashes: tuple[str, ...]
    summary: str
    status: str
    created_at: str
    resolved_at: str | None = None
    schema_version: str = SCHEMAS["contradiction"]

    def validate(self):
        _id(self.contradiction_id, "contradiction_id")
        _id(self.candidate_id, "candidate_id")
        refs = _seq(self.evidence_ref_ids, _id, "evidence_ref_ids")
        hashes = _seq(self.evidence_hashes, _sha, "evidence_hashes")
        if len(refs) != len(hashes):
            raise LearningContractError("contradiction evidence mismatch")
        _text(self.summary, "summary", 2000)
        _enum(self.status, {"open", "resolved", "dismissed"}, "status")
        _utc(self.created_at, "created_at")
        if self.status == "open" and self.resolved_at is not None:
            raise LearningContractError("open contradiction cannot be resolved")
        if self.status != "open":
            _utc(self.resolved_at, "resolved_at")
        return self


@dataclass(frozen=True)
class LearningValidationReceipt:
    receipt_id: str
    candidate_id: str
    candidate_sha256: str
    checks: dict[str, bool]
    validator_ids: tuple[str, ...]
    evidence_ref_ids: tuple[str, ...]
    evidence_hashes: tuple[str, ...]
    domain_reviewer_id: str | None
    human_reviewer_id: str | None
    created_at: str
    schema_version: str = SCHEMAS["receipt"]

    def validate(self):
        _id(self.receipt_id, "receipt_id")
        _id(self.candidate_id, "candidate_id")
        _sha(self.candidate_sha256, "candidate_sha256")
        if not isinstance(self.checks, dict) or not self.checks:
            raise LearningContractError("validation checks required")
        names = set()
        for name, value in self.checks.items():
            check = str(name).strip().upper()
            if not _CHECK.fullmatch(check) or not isinstance(value, bool) or check in names:
                raise LearningContractError("invalid validation check")
            names.add(check)
        _seq(self.validator_ids, _id, "validator_ids")
        refs = _seq(self.evidence_ref_ids, _id, "evidence_ref_ids")
        hashes = _seq(self.evidence_hashes, _sha, "evidence_hashes")
        if len(refs) != len(hashes):
            raise LearningContractError("validation evidence mismatch")
        if self.domain_reviewer_id is not None:
            _id(self.domain_reviewer_id, "domain_reviewer_id")
        if self.human_reviewer_id is not None:
            _id(self.human_reviewer_id, "human_reviewer_id")
        _utc(self.created_at, "created_at")
        return self

    @property
    def passed(self):
        return bool(self.checks) and all(self.checks.values())


@dataclass(frozen=True)
class PromotionDecision:
    allowed: bool
    current_level: str
    target_level: str
    reason_codes: tuple[str, ...]


class AdaptiveLearningPolicy:
    """Pure gate: a positive decision never grants runtime capability."""

    @staticmethod
    def evaluate(
        candidate: KnowledgeCandidate,
        *,
        current_level: str,
        target_level: str,
        receipt: LearningValidationReceipt | None,
        contradictions: Iterable[ContradictionRecord] = (),
    ) -> PromotionDecision:
        candidate.validate()
        if current_level not in LEVELS or target_level not in LEVELS:
            raise LearningContractError("invalid promotion level")
        if LEVELS.index(target_level) != LEVELS.index(current_level) + 1:
            return PromotionDecision(
                False, current_level, target_level, ("NON_MONOTONIC_OR_SKIPPED_LEVEL",)
            )

        reasons = []
        for contradiction in contradictions:
            contradiction.validate()
            if contradiction.candidate_id != candidate.candidate_id:
                raise LearningContractError("contradiction candidate mismatch")
            if contradiction.status == "open":
                reasons.append("OPEN_CONTRADICTION")

        if receipt is None:
            reasons.append("MISSING_VALIDATION_RECEIPT")
        else:
            receipt.validate()
            if receipt.candidate_id != candidate.candidate_id:
                reasons.append("RECEIPT_CANDIDATE_MISMATCH")
            if receipt.candidate_sha256 != candidate.sha256:
                reasons.append("RECEIPT_HASH_MISMATCH")
            if not receipt.passed:
                reasons.append("VALIDATION_CHECK_FAILED")
            if receipt.evidence_ref_ids != candidate.evidence_ref_ids:
                reasons.append("VALIDATION_EVIDENCE_REF_MISMATCH")
            if receipt.evidence_hashes != candidate.evidence_hashes:
                reasons.append("VALIDATION_EVIDENCE_HASH_MISMATCH")

        if target_level in {"approved", "enterprise"}:
            human_required = (
                target_level == "enterprise"
                or candidate.domain in {"network", "security"}
                or candidate.risk_level in {"high", "critical"}
            )
            if human_required and (receipt is None or receipt.human_reviewer_id is None):
                reasons.append("HUMAN_REVIEW_REQUIRED")
            if candidate.domain in {"network", "security"} and (
                receipt is None or receipt.domain_reviewer_id is None
            ):
                reasons.append("DOMAIN_REVIEW_REQUIRED")

        if (
            target_level == "enterprise"
            and candidate.ownership == "learner_managed"
            and (receipt is None or receipt.human_reviewer_id is None)
        ):
            reasons.append("LEARNER_MANAGED_ENTERPRISE_REQUIRES_HUMAN_ADOPTION")

        return PromotionDecision(
            not reasons,
            current_level,
            target_level,
            tuple(dict.fromkeys(reasons)),
        )
