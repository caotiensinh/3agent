"""Exact production-skill identity for held-out evaluation.

This module is a read-only projection over the canonical ``ApprovedSkillLoader``
registry. It does not load a second registry and grants no execution authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .skills import ApprovedSkillLoader

SCHEMA_VERSION = "workspace-heldout-production-skill-subject/v1"
AUTHORITY = "evaluation_identity_only_no_runtime_or_learning_mutation"
_SKILL = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_CANDIDATE_PROVENANCE = re.compile(
    r"^candidate:(?P<candidate_id>[A-Za-z0-9][A-Za-z0-9._:-]{0,127}):"
    r"(?P<candidate_sha>sha256:[0-9a-f]{64})$"
)


class ProductionSkillEvaluationSubjectError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha_payload(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _canonical_instruction_bytes(raw: bytes) -> bytes:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_SKILL_UTF8_INVALID") from exc
    return text.replace("\r\n", "\n").replace("\r", "\n").encode("utf-8")


@dataclass(frozen=True)
class ProductionSkillEvaluationSubject:
    skill_name: str
    skill_sha256: str
    registry_entry_sha256: str
    source_candidate_id: str | None
    source_candidate_sha256: str | None
    source_candidate_bound: bool
    authority: str = AUTHORITY
    schema_version: str = SCHEMA_VERSION

    def validate(self) -> "ProductionSkillEvaluationSubject":
        if self.schema_version != SCHEMA_VERSION or self.authority != AUTHORITY:
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_HEADER_INVALID")
        if not _SKILL.fullmatch(self.skill_name):
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_NAME_INVALID")
        if not _SHA.fullmatch(self.skill_sha256) or not _SHA.fullmatch(self.registry_entry_sha256):
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_SHA_INVALID")
        if self.source_candidate_bound:
            if not self.source_candidate_id or not self.source_candidate_sha256:
                raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_CANDIDATE_BINDING_INVALID")
            if not _SHA.fullmatch(self.source_candidate_sha256):
                raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_CANDIDATE_SHA_INVALID")
        elif self.source_candidate_id is not None or self.source_candidate_sha256 is not None:
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_CANDIDATE_BINDING_INVALID")
        return self

    @property
    def subject_sha256(self) -> str:
        self.validate()
        return _sha_payload(
            {
                "schema_version": self.schema_version,
                "skill_name": self.skill_name,
                "skill_sha256": self.skill_sha256,
                "registry_entry_sha256": self.registry_entry_sha256,
                "source_candidate_id": self.source_candidate_id,
                "source_candidate_sha256": self.source_candidate_sha256,
                "source_candidate_bound": self.source_candidate_bound,
                "authority": self.authority,
            }
        )

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["subject_sha256"] = self.subject_sha256
        return payload


class ProductionSkillEvaluationSubjectResolver:
    """Resolve one exact enabled production skill after canonical registry audit."""

    def __init__(self, approved_root: Path):
        self._root = Path(approved_root).resolve()
        self._registry_path = self._root / "registry.json"

    def resolve(
        self,
        skill_name: str,
        *,
        expected_candidate_sha256: str | None = None,
    ) -> ProductionSkillEvaluationSubject:
        name = str(skill_name or "").strip()
        if not _SKILL.fullmatch(name):
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_NAME_INVALID")
        try:
            audited = ApprovedSkillLoader(self._root).audit_registry()
        except Exception as exc:
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_REGISTRY_AUDIT_FAILED") from exc
        if name not in set(audited):
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_NOT_ENABLED_OR_AUDITED")

        try:
            payload = json.loads(self._registry_path.read_text(encoding="utf-8"))
            entry = payload["skills"][name]
        except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_REGISTRY_INVALID") from exc
        if not isinstance(entry, dict) or entry.get("enabled") is not True:
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_NOT_ENABLED_OR_AUDITED")
        if entry.get("instruction_only") is not True:
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_AUTHORITY_WIDENED")
        for field in ("network_access", "credential_access", "persistent_self_modify", "external_code_vendored"):
            if entry.get(field) is not False:
                raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_AUTHORITY_WIDENED")

        path = (self._root / name / "SKILL.md").resolve()
        expected_parent = (self._root / name).resolve()
        if path.parent != expected_parent or path.is_symlink() or not path.is_file():
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_SKILL_PATH_INVALID")
        canonical = _canonical_instruction_bytes(path.read_bytes())
        actual_plain = hashlib.sha256(canonical).hexdigest()
        registered_plain = str(entry.get("sha256") or "").strip().lower()
        if not re.fullmatch(r"[0-9a-f]{64}", registered_plain) or actual_plain != registered_plain:
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_SKILL_SHA_MISMATCH")

        provenance = entry.get("provenance")
        if not isinstance(provenance, list) or not all(isinstance(item, str) and item.strip() for item in provenance):
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_PROVENANCE_INVALID")
        matches = []
        for item in provenance:
            match = _CANDIDATE_PROVENANCE.fullmatch(item.strip())
            if match:
                matches.append((match.group("candidate_id"), match.group("candidate_sha")))
        if len(matches) > 1:
            raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_CANDIDATE_PROVENANCE_AMBIGUOUS")
        candidate_id = matches[0][0] if matches else None
        candidate_sha = matches[0][1] if matches else None

        if expected_candidate_sha256 is not None:
            expected = str(expected_candidate_sha256 or "").strip().lower()
            if not _SHA.fullmatch(expected) or candidate_sha != expected:
                raise ProductionSkillEvaluationSubjectError("PRODUCTION_SUBJECT_EXPECTED_CANDIDATE_MISMATCH")

        return ProductionSkillEvaluationSubject(
            skill_name=name,
            skill_sha256="sha256:" + actual_plain,
            registry_entry_sha256=_sha_payload(entry),
            source_candidate_id=candidate_id,
            source_candidate_sha256=candidate_sha,
            source_candidate_bound=candidate_sha is not None,
        ).validate()
