"""Content-addressed held-out proof required before skill supersession.

The proof binds exact production/candidate evaluation subjects, a strict PASS
same-benchmark comparison, and the existing Phase 4K revision package. It grants no
mutation authority by itself; the production supersession manager is the consumer.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .adaptive_learning_revision_evaluation import RevisionEvaluationPackage

SCHEMA_VERSION = "workspace-heldout-supersession-gate/v1"
AUTHORITY = "heldout_evidence_gate_only_no_direct_mutation_authority"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SKILL = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")

_PRODUCTION_KEYS = {
    "skill_name",
    "skill_sha256",
    "registry_entry_sha256",
    "source_candidate_id",
    "source_candidate_sha256",
    "source_candidate_bound",
    "authority",
    "schema_version",
    "subject_sha256",
}
_CANDIDATE_KEYS = {
    "candidate_id",
    "candidate_sha256",
    "candidate_knowledge_sha256",
    "item_id",
    "base_knowledge_sha256",
    "domain",
    "skill_name",
    "skill_sha256",
    "skill_size_bytes",
    "revision_evaluation_sha256",
    "authority",
    "schema_version",
    "subject_sha256",
}
_COMPARISON_KEYS = {
    "benchmark_id",
    "benchmark_sha256",
    "baseline_run_sha256",
    "revision_run_sha256",
    "baseline_subject_sha256",
    "revision_subject_sha256",
    "total_cases",
    "baseline_pass_count",
    "revision_pass_count",
    "regression_count",
    "improvement_count",
    "unchanged_pass_count",
    "unchanged_fail_count",
    "regressed_case_ids",
    "improved_case_ids",
    "strict_release_passed",
    "reason_codes",
    "authority",
    "schema_version",
    "comparison_sha256",
}


class HeldOutSupersessionGateError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _require_sha(value: Any, code: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise HeldOutSupersessionGateError(code)
    return text


def _verified_payload(payload: Mapping[str, Any], keys: set[str], digest_field: str, code: str) -> dict[str, Any]:
    if not isinstance(payload, Mapping) or set(payload) != keys:
        raise HeldOutSupersessionGateError(code)
    data = dict(payload)
    supplied = _require_sha(data.pop(digest_field, None), code)
    if _sha(data) != supplied:
        raise HeldOutSupersessionGateError(code)
    data[digest_field] = supplied
    return data


@dataclass(frozen=True)
class HeldOutSupersessionGateProof:
    item_id: str
    candidate_id: str
    candidate_sha256: str
    candidate_knowledge_sha256: str
    base_candidate_id: str
    base_candidate_sha256: str
    base_knowledge_sha256: str
    phase4k_evaluation_sha256: str
    production_skill_name: str
    production_skill_sha256: str
    revision_skill_name: str
    revision_skill_sha256: str
    production_subject_sha256: str
    revision_subject_sha256: str
    benchmark_id: str
    benchmark_sha256: str
    baseline_run_sha256: str
    revision_run_sha256: str
    comparison_sha256: str
    total_cases: int
    revision_pass_count: int
    regression_count: int
    strict_release_passed: bool
    authority: str = AUTHORITY
    schema_version: str = SCHEMA_VERSION

    def validate(self) -> "HeldOutSupersessionGateProof":
        if self.schema_version != SCHEMA_VERSION or self.authority != AUTHORITY:
            raise HeldOutSupersessionGateError("HELDOUT_GATE_HEADER_INVALID")
        for value in (self.item_id, self.candidate_id, self.base_candidate_id, self.benchmark_id):
            if not _ID.fullmatch(value):
                raise HeldOutSupersessionGateError("HELDOUT_GATE_IDENTITY_INVALID")
        if not _SKILL.fullmatch(self.production_skill_name) or not _SKILL.fullmatch(self.revision_skill_name):
            raise HeldOutSupersessionGateError("HELDOUT_GATE_SKILL_NAME_INVALID")
        for value in (
            self.candidate_sha256,
            self.candidate_knowledge_sha256,
            self.base_candidate_sha256,
            self.base_knowledge_sha256,
            self.phase4k_evaluation_sha256,
            self.production_skill_sha256,
            self.revision_skill_sha256,
            self.production_subject_sha256,
            self.revision_subject_sha256,
            self.benchmark_sha256,
            self.baseline_run_sha256,
            self.revision_run_sha256,
            self.comparison_sha256,
        ):
            _require_sha(value, "HELDOUT_GATE_SHA_INVALID")
        if (
            not isinstance(self.total_cases, int)
            or isinstance(self.total_cases, bool)
            or not 1 <= self.total_cases <= 128
            or not isinstance(self.revision_pass_count, int)
            or isinstance(self.revision_pass_count, bool)
            or not isinstance(self.regression_count, int)
            or isinstance(self.regression_count, bool)
        ):
            raise HeldOutSupersessionGateError("HELDOUT_GATE_COUNT_INVALID")
        if self.revision_pass_count != self.total_cases or self.regression_count != 0 or self.strict_release_passed is not True:
            raise HeldOutSupersessionGateError("HELDOUT_GATE_STRICT_PASS_REQUIRED")
        if self.production_subject_sha256 == self.revision_subject_sha256:
            raise HeldOutSupersessionGateError("HELDOUT_GATE_SUBJECTS_IDENTICAL")
        return self

    @property
    def gate_sha256(self) -> str:
        self.validate()
        return _sha(asdict(self))

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["gate_sha256"] = self.gate_sha256
        return payload

    @classmethod
    def from_proofs(
        cls,
        *,
        package: RevisionEvaluationPackage,
        production_subject: Mapping[str, Any],
        candidate_subject: Mapping[str, Any],
        comparison: Mapping[str, Any],
    ) -> "HeldOutSupersessionGateProof":
        try:
            package.validate()
        except Exception as exc:
            raise HeldOutSupersessionGateError("HELDOUT_GATE_PHASE4K_INVALID") from exc
        if package.result != "PASS" or package.kind != "skill":
            raise HeldOutSupersessionGateError("HELDOUT_GATE_PHASE4K_PASS_REQUIRED")

        production = _verified_payload(
            production_subject,
            _PRODUCTION_KEYS,
            "subject_sha256",
            "HELDOUT_GATE_PRODUCTION_PROOF_INVALID",
        )
        candidate = _verified_payload(
            candidate_subject,
            _CANDIDATE_KEYS,
            "subject_sha256",
            "HELDOUT_GATE_CANDIDATE_PROOF_INVALID",
        )
        compared = _verified_payload(
            comparison,
            _COMPARISON_KEYS,
            "comparison_sha256",
            "HELDOUT_GATE_COMPARISON_PROOF_INVALID",
        )

        if production.get("schema_version") != "workspace-heldout-production-skill-subject/v1":
            raise HeldOutSupersessionGateError("HELDOUT_GATE_PRODUCTION_PROOF_INVALID")
        if candidate.get("schema_version") != "workspace-heldout-candidate-skill-subject/v1":
            raise HeldOutSupersessionGateError("HELDOUT_GATE_CANDIDATE_PROOF_INVALID")
        if compared.get("schema_version") != "workspace-heldout-regression-comparison/v1":
            raise HeldOutSupersessionGateError("HELDOUT_GATE_COMPARISON_PROOF_INVALID")
        if production.get("source_candidate_bound") is not True:
            raise HeldOutSupersessionGateError("HELDOUT_GATE_BASE_CANDIDATE_REQUIRED")
        if (
            production.get("source_candidate_id") != package.base_candidate_id
            or production.get("source_candidate_sha256") != package.base_candidate_sha256
        ):
            raise HeldOutSupersessionGateError("HELDOUT_GATE_BASE_BINDING_MISMATCH")
        if (
            candidate.get("candidate_id") != package.candidate_id
            or candidate.get("candidate_sha256") != package.candidate_sha256
            or candidate.get("candidate_knowledge_sha256") != package.candidate_knowledge_sha256
            or candidate.get("item_id") != package.item_id
            or candidate.get("base_knowledge_sha256") != package.base_knowledge_sha256
            or candidate.get("domain") != package.domain
            or candidate.get("revision_evaluation_sha256") != package.evaluation_sha256
        ):
            raise HeldOutSupersessionGateError("HELDOUT_GATE_REVISION_BINDING_MISMATCH")
        if (
            compared.get("baseline_subject_sha256") != production["subject_sha256"]
            or compared.get("revision_subject_sha256") != candidate["subject_sha256"]
        ):
            raise HeldOutSupersessionGateError("HELDOUT_GATE_COMPARISON_SUBJECT_MISMATCH")
        total = compared.get("total_cases")
        revision_pass = compared.get("revision_pass_count")
        regressions = compared.get("regression_count")
        if (
            not isinstance(total, int)
            or isinstance(total, bool)
            or not 1 <= total <= 128
            or not isinstance(revision_pass, int)
            or isinstance(revision_pass, bool)
            or not isinstance(regressions, int)
            or isinstance(regressions, bool)
            or compared.get("strict_release_passed") is not True
            or regressions != 0
            or revision_pass != total
            or tuple(compared.get("reason_codes") or ()) != ()
            or tuple(compared.get("regressed_case_ids") or ()) != ()
        ):
            raise HeldOutSupersessionGateError("HELDOUT_GATE_STRICT_PASS_REQUIRED")

        return cls(
            item_id=package.item_id,
            candidate_id=package.candidate_id,
            candidate_sha256=package.candidate_sha256,
            candidate_knowledge_sha256=package.candidate_knowledge_sha256,
            base_candidate_id=package.base_candidate_id,
            base_candidate_sha256=package.base_candidate_sha256,
            base_knowledge_sha256=package.base_knowledge_sha256,
            phase4k_evaluation_sha256=package.evaluation_sha256,
            production_skill_name=str(production["skill_name"]),
            production_skill_sha256=_require_sha(production["skill_sha256"], "HELDOUT_GATE_PRODUCTION_PROOF_INVALID"),
            revision_skill_name=str(candidate["skill_name"]),
            revision_skill_sha256=_require_sha(candidate["skill_sha256"], "HELDOUT_GATE_CANDIDATE_PROOF_INVALID"),
            production_subject_sha256=str(production["subject_sha256"]),
            revision_subject_sha256=str(candidate["subject_sha256"]),
            benchmark_id=str(compared["benchmark_id"]),
            benchmark_sha256=_require_sha(compared["benchmark_sha256"], "HELDOUT_GATE_COMPARISON_PROOF_INVALID"),
            baseline_run_sha256=_require_sha(compared["baseline_run_sha256"], "HELDOUT_GATE_COMPARISON_PROOF_INVALID"),
            revision_run_sha256=_require_sha(compared["revision_run_sha256"], "HELDOUT_GATE_COMPARISON_PROOF_INVALID"),
            comparison_sha256=str(compared["comparison_sha256"]),
            total_cases=total,
            revision_pass_count=revision_pass,
            regression_count=regressions,
            strict_release_passed=True,
        ).validate()
