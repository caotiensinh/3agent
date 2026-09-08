"""Content-addressed held-out benchmark contract for adaptive-learning skills.

This module defines benchmark identity and candidate-to-benchmark separation only.
It does not execute a benchmark, score a candidate, grant promotion authority, or
mutate learning/production state.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable

from .adaptive_learning_contract import DOMAINS, KINDS, KnowledgeCandidate, LearningContractError

HELDOUT_CASE_SCHEMA = "workspace-learning-heldout-case-ref/v1"
HELDOUT_BENCHMARK_SCHEMA = "workspace-learning-heldout-benchmark/v1"
HELDOUT_BINDING_SCHEMA = "workspace-learning-heldout-binding/v1"
HELDOUT_SELECTION_POLICY = "precommitted_content_addressed_before_candidate_evaluation"
HELDOUT_AUTHORITY = "evaluation_contract_only_no_learning_or_runtime_mutation"

_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
_MAX_CASES = 128
_MAX_SOURCE_IDENTIFIERS = 128


class HeldOutBenchmarkError(ValueError):
    """Held-out benchmark input is malformed, overlapping, or untrusted."""


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _id(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not _ID.fullmatch(text):
        raise HeldOutBenchmarkError(f"invalid {field}")
    return text


def _sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise HeldOutBenchmarkError(f"invalid {field}")
    return text


def _unique(values: Iterable[str], *, field: str, limit: int = _MAX_SOURCE_IDENTIFIERS) -> tuple[str, ...]:
    result = tuple(str(value or "").strip() for value in values)
    if len(result) > limit or any(not value for value in result) or len(set(result)) != len(result):
        raise HeldOutBenchmarkError(f"invalid {field}")
    return result


@dataclass(frozen=True)
class HeldOutBenchmarkCaseRef:
    """Metadata-only reference to one immutable benchmark case."""

    case_id: str
    case_sha256: str
    source_task_id: str
    domain: str
    kind: str
    schema_version: str = HELDOUT_CASE_SCHEMA

    def validate(self) -> "HeldOutBenchmarkCaseRef":
        if self.schema_version != HELDOUT_CASE_SCHEMA:
            raise HeldOutBenchmarkError("HELDOUT_CASE_SCHEMA_INVALID")
        _id(self.case_id, "case_id")
        _sha(self.case_sha256, "case_sha256")
        _id(self.source_task_id, "source_task_id")
        if self.domain not in DOMAINS:
            raise HeldOutBenchmarkError("HELDOUT_CASE_DOMAIN_INVALID")
        if self.kind not in KINDS:
            raise HeldOutBenchmarkError("HELDOUT_CASE_KIND_INVALID")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class HeldOutSkillBenchmark:
    """Precommitted immutable set of case references for one skill domain/kind."""

    benchmark_id: str
    source_ref: str
    domain: str
    kind: str
    cases: tuple[HeldOutBenchmarkCaseRef, ...]
    selection_policy: str = HELDOUT_SELECTION_POLICY
    authority: str = HELDOUT_AUTHORITY
    schema_version: str = HELDOUT_BENCHMARK_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "authority": self.authority,
            "benchmark_id": self.benchmark_id,
            "source_ref": self.source_ref,
            "domain": self.domain,
            "kind": self.kind,
            "selection_policy": self.selection_policy,
            "cases": [case.to_payload() for case in self.cases],
        }

    def validate(self) -> "HeldOutSkillBenchmark":
        if self.schema_version != HELDOUT_BENCHMARK_SCHEMA:
            raise HeldOutBenchmarkError("HELDOUT_BENCHMARK_SCHEMA_INVALID")
        if self.authority != HELDOUT_AUTHORITY:
            raise HeldOutBenchmarkError("HELDOUT_BENCHMARK_AUTHORITY_INVALID")
        if self.selection_policy != HELDOUT_SELECTION_POLICY:
            raise HeldOutBenchmarkError("HELDOUT_BENCHMARK_SELECTION_POLICY_INVALID")
        _id(self.benchmark_id, "benchmark_id")
        if not _GIT_SHA.fullmatch(str(self.source_ref or "").strip().lower()):
            raise HeldOutBenchmarkError("HELDOUT_BENCHMARK_SOURCE_REF_INVALID")
        if self.domain not in DOMAINS:
            raise HeldOutBenchmarkError("HELDOUT_BENCHMARK_DOMAIN_INVALID")
        if self.kind not in KINDS:
            raise HeldOutBenchmarkError("HELDOUT_BENCHMARK_KIND_INVALID")
        if not 1 <= len(self.cases) <= _MAX_CASES:
            raise HeldOutBenchmarkError("HELDOUT_BENCHMARK_CASE_COUNT_INVALID")
        case_ids: list[str] = []
        case_hashes: list[str] = []
        task_ids: list[str] = []
        for case in self.cases:
            case.validate()
            if case.domain != self.domain or case.kind != self.kind:
                raise HeldOutBenchmarkError("HELDOUT_BENCHMARK_CASE_SCOPE_MISMATCH")
            case_ids.append(case.case_id)
            case_hashes.append(case.case_sha256)
            task_ids.append(case.source_task_id)
        if len(case_ids) != len(set(case_ids)):
            raise HeldOutBenchmarkError("HELDOUT_BENCHMARK_CASE_ID_DUPLICATE")
        if len(case_hashes) != len(set(case_hashes)):
            raise HeldOutBenchmarkError("HELDOUT_BENCHMARK_CASE_SHA_DUPLICATE")
        if len(task_ids) != len(set(task_ids)):
            raise HeldOutBenchmarkError("HELDOUT_BENCHMARK_TASK_ID_DUPLICATE")
        return self

    @property
    def benchmark_sha256(self) -> str:
        self.validate()
        return _digest(self._base_payload())

    def to_payload(self) -> dict[str, Any]:
        return {**self._base_payload(), "benchmark_sha256": self.benchmark_sha256}


@dataclass(frozen=True)
class HeldOutSkillBenchmarkBinding:
    """Proof that one exact candidate is separated from one exact benchmark set."""

    benchmark_id: str
    benchmark_sha256: str
    candidate_id: str
    candidate_sha256: str
    target_item_id: str | None
    base_item_sha256: str | None
    domain: str
    kind: str
    candidate_source_task_ids: tuple[str, ...]
    candidate_source_experience_hashes: tuple[str, ...]
    candidate_evidence_hashes: tuple[str, ...]
    heldout_task_ids: tuple[str, ...]
    heldout_case_hashes: tuple[str, ...]
    source_overlap_count: int
    authority: str = HELDOUT_AUTHORITY
    schema_version: str = HELDOUT_BINDING_SCHEMA

    @classmethod
    def bind(
        cls,
        benchmark: HeldOutSkillBenchmark,
        candidate: KnowledgeCandidate,
    ) -> "HeldOutSkillBenchmarkBinding":
        benchmark.validate()
        try:
            candidate.validate()
        except LearningContractError as exc:
            raise HeldOutBenchmarkError("HELDOUT_CANDIDATE_INVALID") from exc
        if candidate.kind != "skill":
            raise HeldOutBenchmarkError("HELDOUT_CANDIDATE_NOT_SKILL")
        if candidate.domain != benchmark.domain or candidate.kind != benchmark.kind:
            raise HeldOutBenchmarkError("HELDOUT_CANDIDATE_SCOPE_MISMATCH")

        source_tasks = _unique(candidate.source_task_ids, field="candidate_source_task_ids")
        experience_hashes = tuple(_sha(value, "candidate_source_experience_hash") for value in _unique(
            candidate.source_experience_hashes, field="candidate_source_experience_hashes"
        ))
        evidence_hashes = tuple(_sha(value, "candidate_evidence_hash") for value in _unique(
            candidate.evidence_hashes, field="candidate_evidence_hashes"
        ))
        heldout_tasks = tuple(case.source_task_id for case in benchmark.cases)
        heldout_hashes = tuple(case.case_sha256 for case in benchmark.cases)

        overlap = set(source_tasks).intersection(heldout_tasks)
        overlap.update(set(experience_hashes).intersection(heldout_hashes))
        overlap.update(set(evidence_hashes).intersection(heldout_hashes))
        if overlap:
            raise HeldOutBenchmarkError("HELDOUT_SOURCE_OVERLAP")

        return cls(
            benchmark_id=benchmark.benchmark_id,
            benchmark_sha256=benchmark.benchmark_sha256,
            candidate_id=candidate.candidate_id,
            candidate_sha256=candidate.sha256,
            target_item_id=candidate.target_item_id,
            base_item_sha256=candidate.base_item_sha256,
            domain=candidate.domain,
            kind=candidate.kind,
            candidate_source_task_ids=source_tasks,
            candidate_source_experience_hashes=experience_hashes,
            candidate_evidence_hashes=evidence_hashes,
            heldout_task_ids=heldout_tasks,
            heldout_case_hashes=heldout_hashes,
            source_overlap_count=0,
        ).validate()

    def validate(self) -> "HeldOutSkillBenchmarkBinding":
        if self.schema_version != HELDOUT_BINDING_SCHEMA or self.authority != HELDOUT_AUTHORITY:
            raise HeldOutBenchmarkError("HELDOUT_BINDING_HEADER_INVALID")
        _id(self.benchmark_id, "benchmark_id")
        _sha(self.benchmark_sha256, "benchmark_sha256")
        _id(self.candidate_id, "candidate_id")
        _sha(self.candidate_sha256, "candidate_sha256")
        if self.target_item_id is not None:
            _id(self.target_item_id, "target_item_id")
        if self.base_item_sha256 is not None:
            _sha(self.base_item_sha256, "base_item_sha256")
        if self.domain not in DOMAINS or self.kind != "skill":
            raise HeldOutBenchmarkError("HELDOUT_BINDING_SCOPE_INVALID")
        source_tasks = _unique(self.candidate_source_task_ids, field="candidate_source_task_ids")
        heldout_tasks = _unique(self.heldout_task_ids, field="heldout_task_ids")
        experience_hashes = tuple(_sha(value, "candidate_source_experience_hash") for value in _unique(
            self.candidate_source_experience_hashes, field="candidate_source_experience_hashes"
        ))
        evidence_hashes = tuple(_sha(value, "candidate_evidence_hash") for value in _unique(
            self.candidate_evidence_hashes, field="candidate_evidence_hashes"
        ))
        heldout_hashes = tuple(_sha(value, "heldout_case_hash") for value in _unique(
            self.heldout_case_hashes, field="heldout_case_hashes", limit=_MAX_CASES
        ))
        if len(heldout_tasks) != len(heldout_hashes) or not heldout_tasks:
            raise HeldOutBenchmarkError("HELDOUT_BINDING_CASE_SET_INVALID")
        overlap = set(source_tasks).intersection(heldout_tasks)
        overlap.update(set(experience_hashes).intersection(heldout_hashes))
        overlap.update(set(evidence_hashes).intersection(heldout_hashes))
        if self.source_overlap_count != len(overlap) or self.source_overlap_count != 0:
            raise HeldOutBenchmarkError("HELDOUT_BINDING_OVERLAP_INVALID")
        return self

    def _base_payload(self) -> dict[str, Any]:
        self.validate()
        payload = asdict(self)
        payload["candidate_source_task_ids"] = list(self.candidate_source_task_ids)
        payload["candidate_source_experience_hashes"] = list(self.candidate_source_experience_hashes)
        payload["candidate_evidence_hashes"] = list(self.candidate_evidence_hashes)
        payload["heldout_task_ids"] = list(self.heldout_task_ids)
        payload["heldout_case_hashes"] = list(self.heldout_case_hashes)
        return payload

    @property
    def binding_sha256(self) -> str:
        return _digest(self._base_payload())

    def to_payload(self) -> dict[str, Any]:
        return {**self._base_payload(), "binding_sha256": self.binding_sha256}
