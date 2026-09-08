"""Deterministic same-benchmark baseline-vs-revision regression policy.

This module consumes immutable metadata references to case outcomes. It performs no
model/tool execution and grants no learning or runtime authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass
from typing import Any, Iterable

OUTCOME_SCHEMA = "workspace-heldout-case-outcome-ref/v1"
RUN_SCHEMA = "workspace-heldout-benchmark-run-ref/v1"
COMPARISON_SCHEMA = "workspace-heldout-regression-comparison/v1"
AUTHORITY = "evaluation_decision_only_no_stage_promotion_or_runtime_mutation"
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_CASES = 128


class HeldOutRegressionError(ValueError):
    def __init__(self, reason_code: str):
        self.reason_code = str(reason_code)
        super().__init__(self.reason_code)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(value)).hexdigest()


def _valid_sha(value: str) -> bool:
    return bool(_SHA.fullmatch(str(value or "")))


@dataclass(frozen=True)
class HeldOutCaseOutcomeRef:
    case_id: str
    case_sha256: str
    subject_sha256: str
    executor_sha256: str
    result_sha256: str
    passed: bool
    schema_version: str = OUTCOME_SCHEMA

    def validate(self) -> "HeldOutCaseOutcomeRef":
        if self.schema_version != OUTCOME_SCHEMA or not _ID.fullmatch(self.case_id):
            raise HeldOutRegressionError("HELDOUT_OUTCOME_IDENTITY_INVALID")
        for value in (
            self.case_sha256,
            self.subject_sha256,
            self.executor_sha256,
            self.result_sha256,
        ):
            if not _valid_sha(value):
                raise HeldOutRegressionError("HELDOUT_OUTCOME_SHA_INVALID")
        if not isinstance(self.passed, bool):
            raise HeldOutRegressionError("HELDOUT_OUTCOME_VERDICT_INVALID")
        return self

    @property
    def outcome_ref_sha256(self) -> str:
        self.validate()
        return _sha(asdict(self))


@dataclass(frozen=True)
class HeldOutBenchmarkRunRef:
    benchmark_id: str
    benchmark_sha256: str
    subject_id: str
    subject_sha256: str
    outcomes: tuple[HeldOutCaseOutcomeRef, ...]
    schema_version: str = RUN_SCHEMA

    def validate(self) -> "HeldOutBenchmarkRunRef":
        if self.schema_version != RUN_SCHEMA:
            raise HeldOutRegressionError("HELDOUT_RUN_SCHEMA_INVALID")
        if not _ID.fullmatch(self.benchmark_id) or not _ID.fullmatch(self.subject_id):
            raise HeldOutRegressionError("HELDOUT_RUN_IDENTITY_INVALID")
        if not _valid_sha(self.benchmark_sha256) or not _valid_sha(self.subject_sha256):
            raise HeldOutRegressionError("HELDOUT_RUN_SHA_INVALID")
        if not 1 <= len(self.outcomes) <= _MAX_CASES:
            raise HeldOutRegressionError("HELDOUT_RUN_CASE_COUNT_INVALID")
        case_ids = set()
        case_hashes = set()
        for outcome in self.outcomes:
            outcome.validate()
            if outcome.subject_sha256 != self.subject_sha256:
                raise HeldOutRegressionError("HELDOUT_RUN_SUBJECT_MISMATCH")
            if outcome.case_id in case_ids or outcome.case_sha256 in case_hashes:
                raise HeldOutRegressionError("HELDOUT_RUN_CASE_DUPLICATE")
            case_ids.add(outcome.case_id)
            case_hashes.add(outcome.case_sha256)
        return self

    @property
    def run_sha256(self) -> str:
        self.validate()
        return _sha(
            {
                "schema_version": self.schema_version,
                "benchmark_id": self.benchmark_id,
                "benchmark_sha256": self.benchmark_sha256,
                "subject_id": self.subject_id,
                "subject_sha256": self.subject_sha256,
                "outcomes": [
                    {
                        "case_id": item.case_id,
                        "outcome_ref_sha256": item.outcome_ref_sha256,
                    }
                    for item in sorted(self.outcomes, key=lambda item: item.case_id)
                ],
            }
        )


@dataclass(frozen=True)
class HeldOutRegressionComparison:
    benchmark_id: str
    benchmark_sha256: str
    baseline_run_sha256: str
    revision_run_sha256: str
    baseline_subject_sha256: str
    revision_subject_sha256: str
    total_cases: int
    baseline_pass_count: int
    revision_pass_count: int
    regression_count: int
    improvement_count: int
    unchanged_pass_count: int
    unchanged_fail_count: int
    regressed_case_ids: tuple[str, ...]
    improved_case_ids: tuple[str, ...]
    strict_release_passed: bool
    reason_codes: tuple[str, ...]
    authority: str = AUTHORITY
    schema_version: str = COMPARISON_SCHEMA

    def validate(self) -> "HeldOutRegressionComparison":
        if self.schema_version != COMPARISON_SCHEMA or self.authority != AUTHORITY:
            raise HeldOutRegressionError("HELDOUT_COMPARISON_HEADER_INVALID")
        if not _ID.fullmatch(self.benchmark_id):
            raise HeldOutRegressionError("HELDOUT_COMPARISON_BENCHMARK_INVALID")
        for value in (
            self.benchmark_sha256,
            self.baseline_run_sha256,
            self.revision_run_sha256,
            self.baseline_subject_sha256,
            self.revision_subject_sha256,
        ):
            if not _valid_sha(value):
                raise HeldOutRegressionError("HELDOUT_COMPARISON_SHA_INVALID")
        counts = (
            self.total_cases,
            self.baseline_pass_count,
            self.revision_pass_count,
            self.regression_count,
            self.improvement_count,
            self.unchanged_pass_count,
            self.unchanged_fail_count,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
            raise HeldOutRegressionError("HELDOUT_COMPARISON_COUNT_INVALID")
        if self.total_cases != (
            self.regression_count
            + self.improvement_count
            + self.unchanged_pass_count
            + self.unchanged_fail_count
        ):
            raise HeldOutRegressionError("HELDOUT_COMPARISON_COUNT_INVALID")
        expected_pass = self.regression_count == 0 and self.revision_pass_count == self.total_cases
        if self.strict_release_passed != expected_pass:
            raise HeldOutRegressionError("HELDOUT_COMPARISON_DECISION_INVALID")
        expected_reasons = []
        if self.regression_count:
            expected_reasons.append("HELDOUT_REGRESSION_DETECTED")
        if self.revision_pass_count != self.total_cases:
            expected_reasons.append("HELDOUT_REVISION_NOT_ALL_CASES_PASS")
        if self.reason_codes != tuple(expected_reasons):
            raise HeldOutRegressionError("HELDOUT_COMPARISON_REASONS_INVALID")
        return self

    @property
    def comparison_sha256(self) -> str:
        self.validate()
        return _sha(asdict(self))

    def to_payload(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["regressed_case_ids"] = list(self.regressed_case_ids)
        payload["improved_case_ids"] = list(self.improved_case_ids)
        payload["reason_codes"] = list(self.reason_codes)
        payload["comparison_sha256"] = self.comparison_sha256
        return payload


def compare_heldout_runs(
    baseline: HeldOutBenchmarkRunRef,
    revision: HeldOutBenchmarkRunRef,
) -> HeldOutRegressionComparison:
    baseline.validate()
    revision.validate()
    if baseline.benchmark_id != revision.benchmark_id or baseline.benchmark_sha256 != revision.benchmark_sha256:
        raise HeldOutRegressionError("HELDOUT_COMPARISON_BENCHMARK_MISMATCH")
    if baseline.subject_sha256 == revision.subject_sha256:
        raise HeldOutRegressionError("HELDOUT_COMPARISON_SUBJECTS_IDENTICAL")

    left = {item.case_id: item for item in baseline.outcomes}
    right = {item.case_id: item for item in revision.outcomes}
    if set(left) != set(right):
        raise HeldOutRegressionError("HELDOUT_COMPARISON_CASE_SET_MISMATCH")

    regressed = []
    improved = []
    unchanged_pass = 0
    unchanged_fail = 0
    for case_id in sorted(left):
        base = left[case_id]
        rev = right[case_id]
        if base.case_sha256 != rev.case_sha256:
            raise HeldOutRegressionError("HELDOUT_COMPARISON_CASE_SHA_MISMATCH")
        if base.executor_sha256 != rev.executor_sha256:
            raise HeldOutRegressionError("HELDOUT_COMPARISON_EXECUTOR_MISMATCH")
        if base.passed and not rev.passed:
            regressed.append(case_id)
        elif not base.passed and rev.passed:
            improved.append(case_id)
        elif base.passed:
            unchanged_pass += 1
        else:
            unchanged_fail += 1

    baseline_pass = sum(1 for item in left.values() if item.passed)
    revision_pass = sum(1 for item in right.values() if item.passed)
    strict_pass = not regressed and revision_pass == len(right)
    reasons = []
    if regressed:
        reasons.append("HELDOUT_REGRESSION_DETECTED")
    if revision_pass != len(right):
        reasons.append("HELDOUT_REVISION_NOT_ALL_CASES_PASS")
    return HeldOutRegressionComparison(
        benchmark_id=baseline.benchmark_id,
        benchmark_sha256=baseline.benchmark_sha256,
        baseline_run_sha256=baseline.run_sha256,
        revision_run_sha256=revision.run_sha256,
        baseline_subject_sha256=baseline.subject_sha256,
        revision_subject_sha256=revision.subject_sha256,
        total_cases=len(right),
        baseline_pass_count=baseline_pass,
        revision_pass_count=revision_pass,
        regression_count=len(regressed),
        improvement_count=len(improved),
        unchanged_pass_count=unchanged_pass,
        unchanged_fail_count=unchanged_fail,
        regressed_case_ids=tuple(regressed),
        improved_case_ids=tuple(improved),
        strict_release_passed=strict_pass,
        reason_codes=tuple(reasons),
    ).validate()
