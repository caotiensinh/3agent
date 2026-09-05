from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

CASE_SCHEMA = "workspace-network-experience-case/v1"
PATTERN_SCHEMA = "workspace-network-evidence-pattern/v1"
SKILL_CANDIDATE_SCHEMA = "workspace-network-skill-candidate/v1"

EVIDENCE_ROLES = {"supporting", "contradicting", "discriminator", "outcome"}
CAUSE_BASES = {"ground_truth", "operator_verified", "unknown"}
REMEDIATION_BASES = {
    "observed_outcome",
    "ground_truth",
    "authoritative_reference",
    "operator_verified",
}


class NetworkExperienceError(ValueError):
    """An experience artifact violates the evidence-first contract."""


def _bounded(value: Any, field: str, *, max_len: int = 512) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len:
        raise NetworkExperienceError(f"{field} must be a non-empty bounded string")
    return text


def _compact_list(values: Any, field: str, *, max_items: int = 64) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)):
        raise NetworkExperienceError(f"{field} must be a list")
    if not values or len(values) > max_items:
        raise NetworkExperienceError(f"{field} must contain 1..{max_items} items")
    result = tuple(_bounded(item, field) for item in values)
    if len(set(result)) != len(result):
        raise NetworkExperienceError(f"{field} must not contain duplicates")
    return result


def _sha256(value: str, field: str) -> str:
    text = _bounded(value, field, max_len=71)
    if not text.startswith("sha256:") or len(text) != 71:
        raise NetworkExperienceError(f"{field} must be sha256:<64-hex>")
    try:
        int(text[7:], 16)
    except ValueError as exc:
        raise NetworkExperienceError(f"{field} must be sha256:<64-hex>") from exc
    return text


def canonical_fingerprint(payload: dict[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class EvidenceRef:
    evidence_id: str
    role: str
    observation: str
    source_ref: str
    source_sha256: str

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "EvidenceRef":
        role = _bounded(value.get("role"), "evidence.role", max_len=32)
        if role not in EVIDENCE_ROLES:
            raise NetworkExperienceError(
                f"evidence.role must be one of {sorted(EVIDENCE_ROLES)}"
            )
        return cls(
            evidence_id=_bounded(value.get("evidence_id"), "evidence.evidence_id", max_len=128),
            role=role,
            observation=_bounded(value.get("observation"), "evidence.observation", max_len=1024),
            source_ref=_bounded(value.get("source_ref"), "evidence.source_ref", max_len=256),
            source_sha256=_sha256(value.get("source_sha256"), "evidence.source_sha256"),
        )

    def as_dict(self) -> dict[str, str]:
        return {
            "evidence_id": self.evidence_id,
            "role": self.role,
            "observation": self.observation,
            "source_ref": self.source_ref,
            "source_sha256": self.source_sha256,
        }


@dataclass(frozen=True)
class RemediationStep:
    action: str
    basis: str
    evidence_ids: tuple[str, ...]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RemediationStep":
        basis = _bounded(value.get("basis"), "remediation.basis", max_len=48)
        if basis not in REMEDIATION_BASES:
            raise NetworkExperienceError(
                "remediation.basis must be evidence-backed; inferred/unverified remediation is forbidden"
            )
        return cls(
            action=_bounded(value.get("action"), "remediation.action", max_len=1024),
            basis=basis,
            evidence_ids=_compact_list(
                value.get("evidence_ids"), "remediation.evidence_ids", max_items=16
            ),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "basis": self.basis,
            "evidence_ids": list(self.evidence_ids),
        }


@dataclass(frozen=True)
class ExperienceCase:
    case_id: str
    dataset_id: str
    incident_class: str
    symptoms: tuple[str, ...]
    evidence: tuple[EvidenceRef, ...]
    candidate_causes: tuple[str, ...]
    confirmed_cause: str | None
    cause_basis: str
    remediation: tuple[RemediationStep, ...]
    outcome: str | None
    confidence: float
    provenance_refs: tuple[str, ...]
    schema_version: str = CASE_SCHEMA

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ExperienceCase":
        if value.get("schema_version", CASE_SCHEMA) != CASE_SCHEMA:
            raise NetworkExperienceError(f"unsupported case schema; expected {CASE_SCHEMA}")

        evidence_raw = value.get("evidence")
        if not isinstance(evidence_raw, list) or len(evidence_raw) < 2 or len(evidence_raw) > 128:
            raise NetworkExperienceError(
                "experience case requires 2..128 compact evidence references; raw log payloads are not a case"
            )
        evidence = tuple(EvidenceRef.from_dict(item) for item in evidence_raw)
        ids = {item.evidence_id for item in evidence}
        if len(ids) != len(evidence):
            raise NetworkExperienceError("evidence_id values must be unique within a case")

        cause_basis = _bounded(value.get("cause_basis", "unknown"), "cause_basis", max_len=32)
        if cause_basis not in CAUSE_BASES:
            raise NetworkExperienceError(f"cause_basis must be one of {sorted(CAUSE_BASES)}")
        raw_confirmed = value.get("confirmed_cause")
        confirmed_cause = None if raw_confirmed in {None, ""} else _bounded(
            raw_confirmed, "confirmed_cause", max_len=1024
        )
        if confirmed_cause is not None and cause_basis == "unknown":
            raise NetworkExperienceError(
                "confirmed_cause requires ground_truth or operator_verified cause_basis"
            )
        if confirmed_cause is None and cause_basis != "unknown":
            raise NetworkExperienceError(
                "cause_basis must be unknown when no confirmed_cause exists"
            )

        remediation_raw = value.get("remediation", [])
        if not isinstance(remediation_raw, list) or len(remediation_raw) > 32:
            raise NetworkExperienceError("remediation must be a list with at most 32 steps")
        remediation = tuple(RemediationStep.from_dict(item) for item in remediation_raw)
        for step in remediation:
            missing = set(step.evidence_ids) - ids
            if missing:
                raise NetworkExperienceError(
                    f"remediation references evidence not present in the case: {sorted(missing)}"
                )

        try:
            confidence = float(value.get("confidence"))
        except (TypeError, ValueError) as exc:
            raise NetworkExperienceError("confidence must be a number from 0 to 1") from exc
        if not 0.0 <= confidence <= 1.0:
            raise NetworkExperienceError("confidence must be a number from 0 to 1")

        raw_outcome = value.get("outcome")
        outcome = None if raw_outcome in {None, ""} else _bounded(raw_outcome, "outcome", max_len=1024)

        return cls(
            case_id=_bounded(value.get("case_id"), "case_id", max_len=128),
            dataset_id=_bounded(value.get("dataset_id"), "dataset_id", max_len=80),
            incident_class=_bounded(value.get("incident_class"), "incident_class", max_len=128),
            symptoms=_compact_list(value.get("symptoms"), "symptoms", max_items=32),
            evidence=evidence,
            candidate_causes=_compact_list(
                value.get("candidate_causes"), "candidate_causes", max_items=16
            ),
            confirmed_cause=confirmed_cause,
            cause_basis=cause_basis,
            remediation=remediation,
            outcome=outcome,
            confidence=confidence,
            provenance_refs=_compact_list(
                value.get("provenance_refs"), "provenance_refs", max_items=32
            ),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "case_id": self.case_id,
            "dataset_id": self.dataset_id,
            "incident_class": self.incident_class,
            "symptoms": list(self.symptoms),
            "evidence": [item.as_dict() for item in self.evidence],
            "candidate_causes": list(self.candidate_causes),
            "confirmed_cause": self.confirmed_cause,
            "cause_basis": self.cause_basis,
            "remediation": [item.as_dict() for item in self.remediation],
            "outcome": self.outcome,
            "confidence": self.confidence,
            "provenance_refs": list(self.provenance_refs),
        }

    def fingerprint(self) -> str:
        return canonical_fingerprint(self.as_dict())


@dataclass(frozen=True)
class EvidencePattern:
    pattern_id: str
    title: str
    supporting_case_ids: tuple[str, ...]
    symptoms: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    discriminators: tuple[str, ...]
    likely_causes: tuple[str, ...]
    false_positive_checks: tuple[str, ...]
    schema_version: str = PATTERN_SCHEMA

    @classmethod
    def from_dict(
        cls,
        value: dict[str, Any],
        *,
        minimum_independent_cases: int = 2,
    ) -> "EvidencePattern":
        if value.get("schema_version", PATTERN_SCHEMA) != PATTERN_SCHEMA:
            raise NetworkExperienceError(
                f"unsupported pattern schema; expected {PATTERN_SCHEMA}"
            )
        cases = _compact_list(
            value.get("supporting_case_ids"), "supporting_case_ids", max_items=256
        )
        if len(cases) < max(2, int(minimum_independent_cases)):
            raise NetworkExperienceError(
                "an evidence pattern requires multiple independent supporting cases"
            )
        return cls(
            pattern_id=_bounded(value.get("pattern_id"), "pattern_id", max_len=128),
            title=_bounded(value.get("title"), "title", max_len=256),
            supporting_case_ids=cases,
            symptoms=_compact_list(value.get("symptoms"), "symptoms", max_items=32),
            evidence_requirements=_compact_list(
                value.get("evidence_requirements"), "evidence_requirements", max_items=32
            ),
            discriminators=_compact_list(
                value.get("discriminators"), "discriminators", max_items=32
            ),
            likely_causes=_compact_list(
                value.get("likely_causes"), "likely_causes", max_items=16
            ),
            false_positive_checks=_compact_list(
                value.get("false_positive_checks"), "false_positive_checks", max_items=32
            ),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "pattern_id": self.pattern_id,
            "title": self.title,
            "supporting_case_ids": list(self.supporting_case_ids),
            "symptoms": list(self.symptoms),
            "evidence_requirements": list(self.evidence_requirements),
            "discriminators": list(self.discriminators),
            "likely_causes": list(self.likely_causes),
            "false_positive_checks": list(self.false_positive_checks),
        }

    def fingerprint(self) -> str:
        return canonical_fingerprint(self.as_dict())


@dataclass(frozen=True)
class SkillCandidate:
    name: str
    description: str
    derived_pattern_ids: tuple[str, ...]
    evidence_requirements: tuple[str, ...]
    procedure_steps: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    authority: str = "advisory"
    auto_promotable: bool = False
    schema_version: str = SKILL_CANDIDATE_SCHEMA

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SkillCandidate":
        if value.get("schema_version", SKILL_CANDIDATE_SCHEMA) != SKILL_CANDIDATE_SCHEMA:
            raise NetworkExperienceError(
                f"unsupported skill-candidate schema; expected {SKILL_CANDIDATE_SCHEMA}"
            )
        if value.get("authority", "advisory") != "advisory":
            raise NetworkExperienceError("dataset-derived skill authority must remain advisory")
        if value.get("auto_promotable", False) is not False:
            raise NetworkExperienceError(
                "dataset-derived skills may never auto-promote into the approved WorkSpace skill registry"
            )
        return cls(
            name=_bounded(value.get("name"), "name", max_len=80),
            description=_bounded(value.get("description"), "description", max_len=512),
            derived_pattern_ids=_compact_list(
                value.get("derived_pattern_ids"), "derived_pattern_ids", max_items=32
            ),
            evidence_requirements=_compact_list(
                value.get("evidence_requirements"), "evidence_requirements", max_items=32
            ),
            procedure_steps=_compact_list(
                value.get("procedure_steps"), "procedure_steps", max_items=32
            ),
            stop_conditions=_compact_list(
                value.get("stop_conditions"), "stop_conditions", max_items=16
            ),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "name": self.name,
            "description": self.description,
            "derived_pattern_ids": list(self.derived_pattern_ids),
            "evidence_requirements": list(self.evidence_requirements),
            "procedure_steps": list(self.procedure_steps),
            "stop_conditions": list(self.stop_conditions),
            "authority": self.authority,
            "auto_promotable": self.auto_promotable,
        }

    def fingerprint(self) -> str:
        return canonical_fingerprint(self.as_dict())
