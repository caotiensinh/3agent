from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from typing import Iterable

ACCEPTANCE_CONTRACT_SCHEMA = "workspace-harness-acceptance/v1"
ACCEPTANCE_EVALUATION_SCHEMA = "workspace-harness-acceptance-evaluation/v1"

_CRITERION_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_RESULT_STATES = frozenset({"PASS", "FAIL", "BLOCKED", "NOT_RUN"})
_TERMINAL_OVERRIDES = frozenset({"IMPOSSIBLE", "FAILED_SAFE", "ABORTED"})


class HarnessAcceptanceError(ValueError):
    """Harness acceptance input is invalid or cannot be evaluated safely."""


def _compact_text(value: str, field_name: str, *, max_len: int) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or "\n" in text or "\r" in text:
        raise HarnessAcceptanceError(
            f"{field_name} is required, single-line, and must be <= {max_len} characters"
        )
    return text


def _unique_evidence(values: Iterable[str]) -> tuple[str, ...]:
    items: list[str] = []
    seen: set[str] = set()
    for value in values:
        item = _compact_text(value, "evidence_ref", max_len=256)
        if item not in seen:
            seen.add(item)
            items.append(item)
    return tuple(items)


@dataclass(frozen=True)
class AcceptanceCriterion:
    criterion_id: str
    statement: str
    verifier: str
    required: bool = True
    weight: float = 1.0

    def validate(self) -> "AcceptanceCriterion":
        criterion_id = str(self.criterion_id or "").strip()
        if not _CRITERION_ID_RE.fullmatch(criterion_id):
            raise HarnessAcceptanceError("criterion_id must be a compact identifier")
        _compact_text(self.statement, "statement", max_len=2048)
        _compact_text(self.verifier, "verifier", max_len=128)
        if not isinstance(self.required, bool):
            raise HarnessAcceptanceError("required must be boolean")
        if not isinstance(self.weight, (int, float)) or isinstance(self.weight, bool):
            raise HarnessAcceptanceError("weight must be numeric")
        if not 0.0 < float(self.weight) <= 1_000_000.0:
            raise HarnessAcceptanceError("weight must be within (0, 1000000]")
        return self

    def canonical_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "criterion_id": self.criterion_id,
            "statement": self.statement,
            "verifier": self.verifier,
            "required": self.required,
            "weight": float(self.weight),
        }


@dataclass(frozen=True)
class AcceptanceContract:
    task_id: str
    criteria: tuple[AcceptanceCriterion, ...]
    schema_version: str = ACCEPTANCE_CONTRACT_SCHEMA

    def validate(self) -> "AcceptanceContract":
        _compact_text(self.task_id, "task_id", max_len=128)
        if not self.criteria:
            raise HarnessAcceptanceError("acceptance contract requires at least one criterion")
        seen: set[str] = set()
        for criterion in self.criteria:
            criterion.validate()
            if criterion.criterion_id in seen:
                raise HarnessAcceptanceError(
                    f"duplicate criterion_id: {criterion.criterion_id}"
                )
            seen.add(criterion.criterion_id)
        if not any(criterion.required for criterion in self.criteria):
            raise HarnessAcceptanceError(
                "acceptance contract requires at least one mandatory criterion"
            )
        return self

    def canonical_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "criteria": [criterion.canonical_dict() for criterion in self.criteria],
        }

    def canonical_json(self) -> str:
        return json.dumps(
            self.canonical_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()
        return "sha256:" + digest


@dataclass(frozen=True)
class CriterionResult:
    criterion_id: str
    status: str
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    reason_code: str = ""

    def validate(self) -> "CriterionResult":
        criterion_id = str(self.criterion_id or "").strip()
        if not _CRITERION_ID_RE.fullmatch(criterion_id):
            raise HarnessAcceptanceError("criterion result has invalid criterion_id")
        status = str(self.status or "").strip().upper()
        if status not in _RESULT_STATES:
            raise HarnessAcceptanceError(f"unsupported criterion status: {self.status}")
        evidence = _unique_evidence(self.evidence_refs)
        if status in {"PASS", "FAIL", "BLOCKED"} and not evidence:
            raise HarnessAcceptanceError(
                f"{status} criterion result requires evidence"
            )
        if self.reason_code:
            _compact_text(self.reason_code, "reason_code", max_len=128)
        return self

    def canonical_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "criterion_id": self.criterion_id,
            "status": self.status.upper(),
            "evidence_refs": list(_unique_evidence(self.evidence_refs)),
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True)
class AcceptanceEvaluation:
    task_id: str
    state: str
    completion_percent: float
    remaining_percent: float
    passed_criteria: tuple[str, ...]
    failed_criteria: tuple[str, ...]
    blocked_criteria: tuple[str, ...]
    not_run_criteria: tuple[str, ...]
    missing_criteria: tuple[str, ...]
    acceptance_fingerprint: str
    schema_version: str = ACCEPTANCE_EVALUATION_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


class AcceptanceEvaluator:
    """Deterministic hard-gate evaluator.

    Mandatory criteria decide SUCCESS. Optional criteria may contribute verified
    progress, but they can never compensate for a failed, blocked, missing, or
    unevaluated mandatory criterion.
    """

    @staticmethod
    def evaluate(
        contract: AcceptanceContract,
        results: Iterable[CriterionResult],
        *,
        terminal_state: str | None = None,
        terminal_evidence_refs: Iterable[str] = (),
    ) -> AcceptanceEvaluation:
        contract.validate()
        by_id: dict[str, CriterionResult] = {}
        criteria_by_id = {criterion.criterion_id: criterion for criterion in contract.criteria}

        for result in results:
            result.validate()
            if result.criterion_id not in criteria_by_id:
                raise HarnessAcceptanceError(
                    f"unknown criterion result: {result.criterion_id}"
                )
            if result.criterion_id in by_id:
                raise HarnessAcceptanceError(
                    f"duplicate criterion result: {result.criterion_id}"
                )
            by_id[result.criterion_id] = result

        override = str(terminal_state or "").strip().upper()
        if override and override not in _TERMINAL_OVERRIDES:
            raise HarnessAcceptanceError(
                "terminal_state override must be IMPOSSIBLE, FAILED_SAFE, or ABORTED"
            )
        if override and not _unique_evidence(terminal_evidence_refs):
            raise HarnessAcceptanceError(
                f"{override} terminal state requires evidence"
            )

        passed: list[str] = []
        failed: list[str] = []
        blocked: list[str] = []
        not_run: list[str] = []
        missing: list[str] = []
        verified_weight = 0.0
        total_weight = sum(float(criterion.weight) for criterion in contract.criteria)

        for criterion in contract.criteria:
            result = by_id.get(criterion.criterion_id)
            if result is None:
                missing.append(criterion.criterion_id)
                continue
            status = result.status.upper()
            if status == "PASS":
                passed.append(criterion.criterion_id)
                verified_weight += float(criterion.weight)
            elif status == "FAIL":
                failed.append(criterion.criterion_id)
            elif status == "BLOCKED":
                blocked.append(criterion.criterion_id)
            else:
                not_run.append(criterion.criterion_id)

        required_ids = {
            criterion.criterion_id for criterion in contract.criteria if criterion.required
        }
        required_passed = required_ids.issubset(set(passed))
        required_blocked = bool(required_ids.intersection(blocked))

        if override:
            state = override
        elif required_passed:
            state = "SUCCESS"
        elif required_blocked:
            state = "BLOCKED"
        else:
            state = "PARTIAL"

        completion = 0.0 if total_weight <= 0 else (verified_weight / total_weight) * 100.0
        completion = round(min(100.0, max(0.0, completion)), 3)
        remaining = round(100.0 - completion, 3)

        return AcceptanceEvaluation(
            task_id=contract.task_id,
            state=state,
            completion_percent=completion,
            remaining_percent=remaining,
            passed_criteria=tuple(passed),
            failed_criteria=tuple(failed),
            blocked_criteria=tuple(blocked),
            not_run_criteria=tuple(not_run),
            missing_criteria=tuple(missing),
            acceptance_fingerprint=contract.fingerprint,
        )
