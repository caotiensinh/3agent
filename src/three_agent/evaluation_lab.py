from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .route_planner import DeterministicRoutePlanner
from .task_contract import TaskContractCompiler, TaskContractError

CORPUS_SCHEMA = "workspace-evaluation-corpus/v1"
REPLAY_SCHEMA = "workspace-evaluation-replay/v1"
CORPUS_CLASSES = ("golden", "regression", "adversarial_security")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_SOURCE_REF_RE = re.compile(r"^[0-9a-f]{40}$")
_ALLOWED_EXPECTED_KEYS = {
    "accepted",
    "task_type",
    "sensitivity",
    "risk_level",
    "allowed_sources",
    "write_scope",
    "network_scope",
    "allowed_tools",
    "validators",
    "evidence_required",
    "route",
    "route_reason_code",
    "initial_model_tier",
    "max_model_tier",
    "escalation_allowed",
    "model_trusted_local_only",
    "max_steps",
    "max_tool_calls",
    "max_retries",
    "max_escalations",
    "max_wall_time_ms",
    "cache_mode",
    "semantic_cache_allowed",
    "logging_raw_prompt",
    "logging_raw_tool_output",
}


class EvaluationCorpusError(ValueError):
    pass


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class EvaluationCase:
    case_id: str
    inputs: dict[str, Any]
    expected: dict[str, Any]

    def to_payload(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "inputs": self.inputs,
            "expected": self.expected,
        }


@dataclass(frozen=True)
class EvaluationCorpus:
    corpus_id: str
    cases: tuple[EvaluationCase, ...]
    source_path: Path
    declared_corpus_class: str | None = None

    @property
    def corpus_class(self) -> str:
        # D7-01 corpora predate the explicit class field. Treat that exact legacy
        # shape as golden without rewriting its canonical payload/hash.
        return self.declared_corpus_class or "golden"

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "schema_version": CORPUS_SCHEMA,
            "corpus_id": self.corpus_id,
            "cases": [case.to_payload() for case in self.cases],
        }
        if self.declared_corpus_class is not None:
            payload["corpus_class"] = self.declared_corpus_class
        return payload

    @property
    def sha256(self) -> str:
        return _canonical_sha256(self.to_payload())

    @classmethod
    def load(cls, path: Path) -> "EvaluationCorpus":
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != CORPUS_SCHEMA:
            raise EvaluationCorpusError(f"corpus schema must be {CORPUS_SCHEMA}")
        corpus_id = str(payload.get("corpus_id") or "").strip()
        if not _ID_RE.fullmatch(corpus_id):
            raise EvaluationCorpusError("corpus_id must be a compact stable identifier")
        declared_class = payload.get("corpus_class")
        if declared_class is not None:
            declared_class = str(declared_class).strip()
            if declared_class not in CORPUS_CLASSES:
                raise EvaluationCorpusError(
                    f"corpus_class must be one of {list(CORPUS_CLASSES)}"
                )
        raw_cases = payload.get("cases")
        if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= 128:
            raise EvaluationCorpusError("corpus must contain between 1 and 128 cases")

        seen: set[str] = set()
        cases: list[EvaluationCase] = []
        for raw in raw_cases:
            if not isinstance(raw, dict):
                raise EvaluationCorpusError("every evaluation case must be an object")
            case_id = str(raw.get("case_id") or "").strip()
            if not _ID_RE.fullmatch(case_id) or case_id in seen:
                raise EvaluationCorpusError("case_id values must be unique compact identifiers")
            seen.add(case_id)
            inputs = raw.get("inputs")
            expected = raw.get("expected")
            if not isinstance(inputs, dict) or not isinstance(expected, dict) or not expected:
                raise EvaluationCorpusError(f"{case_id} requires object inputs and non-empty expected")
            unknown = set(expected) - _ALLOWED_EXPECTED_KEYS
            if unknown:
                raise EvaluationCorpusError(
                    f"{case_id} contains unsupported expected keys: {sorted(unknown)}"
                )
            accepted = expected.get("accepted")
            if not isinstance(accepted, bool):
                raise EvaluationCorpusError(f"{case_id} expected.accepted must be boolean")
            cases.append(EvaluationCase(case_id, dict(inputs), dict(expected)))
        return cls(
            corpus_id=corpus_id,
            cases=tuple(cases),
            source_path=source,
            declared_corpus_class=declared_class,
        )


class EvaluationReplay:
    """Deterministic control-plane replay with exact versioned expectations.

    No model, network, tool gateway, task database or business data is required.
    D7-03/D7-04 reuse the same production TaskContractCompiler and route planner as
    the golden lane, while extending checks to capability/write/cache/logging,
    model-locality and the complete immutable execution-budget boundary. Rejected
    security-policy cases are expected results, not replay errors.
    """

    def __init__(self, compiler: TaskContractCompiler | None = None):
        self.compiler = compiler or TaskContractCompiler()

    @staticmethod
    def _actual(contract) -> dict[str, Any]:
        route = DeterministicRoutePlanner.plan(contract)
        write_scope: str | list[str]
        if isinstance(contract.write_scope, tuple):
            write_scope = list(contract.write_scope)
        else:
            write_scope = contract.write_scope
        return {
            "accepted": True,
            "task_type": contract.task_type,
            "sensitivity": contract.sensitivity,
            "risk_level": contract.risk_level,
            "allowed_sources": list(contract.allowed_sources),
            "write_scope": write_scope,
            "network_scope": contract.network_scope,
            "allowed_tools": list(contract.allowed_tools),
            "validators": list(contract.validators),
            "evidence_required": contract.evidence_required,
            "route": route.route,
            "route_reason_code": route.reason_code,
            "initial_model_tier": route.initial_model_tier,
            "max_model_tier": route.max_model_tier,
            "escalation_allowed": route.escalation_allowed,
            "model_trusted_local_only": contract.model_policy.trusted_local_only,
            "max_steps": contract.execution_budget.max_steps,
            "max_tool_calls": contract.execution_budget.max_tool_calls,
            "max_retries": contract.execution_budget.max_retries,
            "max_escalations": contract.execution_budget.max_escalations,
            "max_wall_time_ms": contract.execution_budget.max_wall_time_ms,
            "cache_mode": contract.cache_policy.mode,
            "semantic_cache_allowed": contract.cache_policy.semantic_cache_allowed,
            "logging_raw_prompt": contract.logging_policy.raw_prompt,
            "logging_raw_tool_output": contract.logging_policy.raw_tool_output,
        }

    @staticmethod
    def _matches(expected: dict[str, Any], actual: dict[str, Any]) -> tuple[bool, list[str]]:
        mismatches: list[str] = []
        for key, expected_value in expected.items():
            actual_value = actual.get(key)
            if actual_value != expected_value:
                mismatches.append(key)
        return not mismatches, mismatches

    def replay_case(self, case: EvaluationCase) -> dict[str, Any]:
        task_id = f"EVAL-{case.case_id}"
        kwargs = dict(case.inputs)
        kwargs["task_id"] = task_id
        try:
            contract = self.compiler.compile(**kwargs)
        except TaskContractError:
            actual = {"accepted": False}
        else:
            actual = self._actual(contract)
        passed, mismatches = self._matches(case.expected, actual)
        return {
            "case_id": case.case_id,
            "passed": passed,
            "mismatch_keys": mismatches,
            "actual": actual,
        }

    def replay(self, corpus: EvaluationCorpus, *, source_ref: str) -> dict[str, Any]:
        source = str(source_ref or "").strip().lower()
        if not _SOURCE_REF_RE.fullmatch(source):
            raise EvaluationCorpusError("source_ref must be an exact 40-hex Git commit SHA")
        cases = [self.replay_case(case) for case in corpus.cases]
        passed_count = sum(1 for item in cases if item["passed"])
        return {
            "schema_version": REPLAY_SCHEMA,
            "corpus_id": corpus.corpus_id,
            "corpus_class": corpus.corpus_class,
            "corpus_sha256": corpus.sha256,
            "source_ref": source,
            "case_count": len(cases),
            "passed_count": passed_count,
            "failed_count": len(cases) - passed_count,
            "passed": passed_count == len(cases),
            "cases": cases,
        }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-eval",
        description="Replay versioned WorkSpace deterministic evaluation corpora",
    )
    parser.add_argument("--corpus", required=True)
    parser.add_argument("--source-ref", required=True, help="Exact 40-hex Git commit SHA")
    parser.add_argument("--output", help="Optional replay JSON output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        corpus = EvaluationCorpus.load(Path(args.corpus))
        report = EvaluationReplay().replay(corpus, source_ref=args.source_ref)
        if args.output:
            path = Path(args.output)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, EvaluationCorpusError, TypeError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": REPLAY_SCHEMA,
                    "passed": False,
                    "error": f"{type(exc).__name__}: {exc}",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
