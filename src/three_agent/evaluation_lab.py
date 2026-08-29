from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

CORPUS_SCHEMA = "workspace-evaluation-corpus/v1"
EVIDENCE_SCHEMA = "workspace-evaluation-evidence/v1"
PROMOTION_SCHEMA = "workspace-promotion-receipt/v1"
METRIC_SCHEMA = "workspace-evaluation-metrics/v1"

CORPUS_CLASSES = (
    "golden",
    "replay",
    "regression",
    "adversarial_security",
    "edge_large_context",
    "efficiency_cache_concurrency",
)

HARD_QUALITY_CHECKS = (
    "VERIFIED_TASK_SUCCESS_NON_DECREASE",
    "FIRST_PASS_VERIFIED_SUCCESS_NON_DECREASE",
    "EVIDENCE_COVERAGE_NON_DECREASE",
    "REQUIRED_VALIDATOR_SUCCESS_NON_DECREASE",
)

METRIC_DEFINITIONS: dict[str, dict[str, str]] = {
    "verified_task_success_rate": {
        "direction": "higher_or_equal",
        "meaning": "verified tasks divided by bound tasks",
    },
    "first_pass_verified_success_rate": {
        "direction": "higher_or_equal",
        "meaning": "first-pass verified tasks divided by bound tasks",
    },
    "evidence_coverage": {
        "direction": "higher_or_equal",
        "meaning": "source-bounded evidence coverage metric",
    },
    "required_validator_success": {
        "direction": "higher_or_equal",
        "meaning": "required validators present and passing on the fixed scope",
    },
    "tokens_per_verified_task": {
        "direction": "lower_after_quality",
        "meaning": "total model tokens divided by verified tasks",
    },
    "context_precision_proxy": {
        "direction": "diagnostic",
        "meaning": "deterministic context precision proxy",
    },
    "context_recall_proxy": {
        "direction": "higher_or_equal",
        "meaning": "deterministic context recall proxy",
    },
    "latency_ms": {
        "direction": "lower_after_quality",
        "meaning": "representative elapsed latency in milliseconds",
    },
    "model_retries": {
        "direction": "lower_after_quality",
        "meaning": "actual failure-driven model retries",
    },
    "model_escalations": {
        "direction": "lower_after_quality",
        "meaning": "actual failure-driven stronger-model escalations",
    },
    "tool_calls": {
        "direction": "lower_after_quality",
        "meaning": "actual top-level tool invocations",
    },
}

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_REF_RE = re.compile(r"^(?:sha256:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255})$")
_CHECK_RE = re.compile(r"^[A-Z0-9][A-Z0-9_]{0,95}$")


class EvaluationLabError(ValueError):
    """Evaluation or promotion evidence is incomplete, inconsistent, or unsafe."""


def _canonical_hash(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def metric_definitions_sha256() -> str:
    return _canonical_hash(
        {
            "schema_version": METRIC_SCHEMA,
            "metrics": METRIC_DEFINITIONS,
        }
    )


def _compact_id(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not _ID_RE.fullmatch(text):
        raise EvaluationLabError(f"{field} must be a compact stable identifier")
    return text


def _git_sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA_RE.fullmatch(text):
        raise EvaluationLabError(f"{field} must be an exact 40-hex Git SHA")
    return text


def _sha256(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _HASH_RE.fullmatch(text):
        raise EvaluationLabError(f"{field} must be a sha256:<64-hex> value")
    return text


def _safe_refs(values: Any) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise EvaluationLabError("evidence_refs must be a non-empty sequence")
    result: list[str] = []
    for raw in values:
        ref = str(raw or "").strip()
        if not _EVIDENCE_REF_RE.fullmatch(ref):
            raise EvaluationLabError(
                "evidence_refs must contain compact IDs/hashes/paths, not raw content"
            )
        if ref not in result:
            result.append(ref)
        if len(result) > 32:
            raise EvaluationLabError("at most 32 evidence_refs are allowed")
    return tuple(result)


@dataclass(frozen=True)
class CorpusClassSpec:
    class_id: str
    source_kind: str
    source_ref: str | None
    label_policy: str
    required_checks: tuple[str, ...]
    required_for_promotion: bool

    @classmethod
    def from_payload(cls, class_id: str, payload: Any) -> "CorpusClassSpec":
        if class_id not in CORPUS_CLASSES:
            raise EvaluationLabError(f"unsupported corpus class: {class_id}")
        if not isinstance(payload, dict):
            raise EvaluationLabError(f"corpus class {class_id} must be an object")
        source_kind = str(payload.get("source_kind") or "").strip()
        if source_kind not in {
            "fixed_task_set",
            "external_replay",
            "ci_regression",
            "ci_adversarial",
            "external_large_context",
            "benchmark_suite",
        }:
            raise EvaluationLabError(f"unsupported source_kind for {class_id}")
        source_ref_raw = payload.get("source_ref")
        source_ref = None if source_ref_raw is None else str(source_ref_raw).strip().replace("\\", "/")
        if source_ref is not None:
            candidate = Path(source_ref)
            if (
                not source_ref
                or candidate.is_absolute()
                or ".." in candidate.parts
                or len(source_ref) > 240
            ):
                raise EvaluationLabError(f"unsafe source_ref for {class_id}")
        if source_kind in {"fixed_task_set", "benchmark_suite"} and source_ref is None:
            raise EvaluationLabError(f"{class_id} requires source_ref")
        if source_kind not in {"fixed_task_set", "benchmark_suite"} and source_ref is not None:
            raise EvaluationLabError(f"{class_id} external/CI source must not embed a local source_ref")

        label_policy = str(payload.get("label_policy") or "").strip()
        if label_policy not in {"external_holdout_required", "labels_not_required"}:
            raise EvaluationLabError(f"invalid label_policy for {class_id}")
        raw_checks = payload.get("required_checks")
        if not isinstance(raw_checks, list) or not raw_checks:
            raise EvaluationLabError(f"{class_id} must declare required_checks")
        checks: list[str] = []
        for raw in raw_checks:
            check = str(raw or "").strip().upper()
            if not _CHECK_RE.fullmatch(check):
                raise EvaluationLabError(f"invalid required check for {class_id}: {check}")
            if check not in checks:
                checks.append(check)
        required = payload.get("required_for_promotion") is True
        if not required:
            raise EvaluationLabError(
                f"all v1 corpus classes must be required_for_promotion=true: {class_id}"
            )
        return cls(
            class_id=class_id,
            source_kind=source_kind,
            source_ref=source_ref,
            label_policy=label_policy,
            required_checks=tuple(checks),
            required_for_promotion=True,
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "source_kind": self.source_kind,
            "source_ref": self.source_ref,
            "label_policy": self.label_policy,
            "required_checks": list(self.required_checks),
            "required_for_promotion": self.required_for_promotion,
        }


@dataclass(frozen=True)
class EvaluationCorpus:
    corpus_id: str
    metric_schema_version: str
    classes: tuple[CorpusClassSpec, ...]

    @classmethod
    def load(cls, path: Path) -> "EvaluationCorpus":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != CORPUS_SCHEMA:
            raise EvaluationLabError(f"corpus schema must be {CORPUS_SCHEMA}")
        corpus_id = _compact_id(payload.get("corpus_id"), "corpus_id")
        metric_schema = str(payload.get("metric_schema_version") or "").strip()
        if metric_schema != METRIC_SCHEMA:
            raise EvaluationLabError(
                f"metric_schema_version must be {METRIC_SCHEMA}"
            )
        raw_classes = payload.get("classes")
        if not isinstance(raw_classes, dict) or set(raw_classes) != set(CORPUS_CLASSES):
            raise EvaluationLabError(
                "corpus manifest must declare exactly all required v1 corpus classes"
            )
        return cls(
            corpus_id,
            metric_schema,
            tuple(
                CorpusClassSpec.from_payload(class_id, raw_classes[class_id])
                for class_id in CORPUS_CLASSES
            ),
        ).validate()

    def validate(self) -> "EvaluationCorpus":
        _compact_id(self.corpus_id, "corpus_id")
        if self.metric_schema_version != METRIC_SCHEMA:
            raise EvaluationLabError("corpus metric schema version mismatch")
        if tuple(item.class_id for item in self.classes) != CORPUS_CLASSES:
            raise EvaluationLabError("corpus classes must exactly match the v1 required order")
        if not all(item.required_for_promotion for item in self.classes):
            raise EvaluationLabError("every v1 corpus class is mandatory for promotion")
        return self

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": CORPUS_SCHEMA,
            "corpus_id": self.corpus_id,
            "metric_schema_version": self.metric_schema_version,
            "classes": {
                item.class_id: item.to_payload()
                for item in self.classes
            },
        }

    @property
    def sha256(self) -> str:
        return _canonical_hash(self.to_payload())

    def optimizer_view(self) -> dict[str, Any]:
        """Expose corpus routing without holdout labels, commitments, or checks."""
        return {
            "schema_version": "workspace-evaluation-optimizer-view/v1",
            "corpus_id": self.corpus_id,
            "corpus_sha256": self.sha256,
            "metric_schema_version": self.metric_schema_version,
            "metric_definitions_sha256": metric_definitions_sha256(),
            "classes": {
                item.class_id: {
                    "source_kind": item.source_kind,
                    "source_ref": item.source_ref,
                    "holdout_labels_available_to_optimizer": False,
                    "required_for_promotion": item.required_for_promotion,
                }
                for item in self.classes
            },
        }

    def by_id(self) -> dict[str, CorpusClassSpec]:
        return {item.class_id: item for item in self.classes}


@dataclass(frozen=True)
class EvaluationEvidence:
    evidence_id: str
    corpus_id: str
    corpus_sha256: str
    corpus_class: str
    metric_schema_version: str
    metric_definitions_sha256: str
    baseline_ref: str
    candidate_ref: str
    checks: dict[str, bool]
    security_passed: bool
    evidence_refs: tuple[str, ...]
    label_commitment_sha256: str | None
    holdout_evaluator: bool

    @classmethod
    def load(cls, path: Path) -> "EvaluationEvidence":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != EVIDENCE_SCHEMA:
            raise EvaluationLabError(f"evidence schema must be {EVIDENCE_SCHEMA}")
        raw_checks = payload.get("checks")
        if not isinstance(raw_checks, dict):
            raise EvaluationLabError("checks must be an object")
        return cls(
            evidence_id=str(payload.get("evidence_id") or "").strip(),
            corpus_id=str(payload.get("corpus_id") or "").strip(),
            corpus_sha256=str(payload.get("corpus_sha256") or "").strip().lower(),
            corpus_class=str(payload.get("corpus_class") or "").strip(),
            metric_schema_version=str(payload.get("metric_schema_version") or "").strip(),
            metric_definitions_sha256=str(payload.get("metric_definitions_sha256") or "").strip().lower(),
            baseline_ref=str(payload.get("baseline_ref") or "").strip().lower(),
            candidate_ref=str(payload.get("candidate_ref") or "").strip().lower(),
            checks={str(key).strip().upper(): value for key, value in raw_checks.items()},
            security_passed=payload.get("security_passed") is True,
            evidence_refs=tuple(payload.get("evidence_refs") or ()),
            label_commitment_sha256=(
                None
                if payload.get("label_commitment_sha256") is None
                else str(payload.get("label_commitment_sha256")).strip().lower()
            ),
            holdout_evaluator=payload.get("holdout_evaluator") is True,
        ).validate()

    def validate(self) -> "EvaluationEvidence":
        _compact_id(self.evidence_id, "evidence_id")
        _compact_id(self.corpus_id, "corpus_id")
        _sha256(self.corpus_sha256, "corpus_sha256")
        if self.corpus_class not in CORPUS_CLASSES:
            raise EvaluationLabError("evidence corpus_class is invalid")
        if self.metric_schema_version != METRIC_SCHEMA:
            raise EvaluationLabError("evidence metric schema version mismatch")
        if _sha256(
            self.metric_definitions_sha256,
            "metric_definitions_sha256",
        ) != metric_definitions_sha256():
            raise EvaluationLabError("metric definition fingerprint mismatch")
        baseline = _git_sha(self.baseline_ref, "baseline_ref")
        candidate = _git_sha(self.candidate_ref, "candidate_ref")
        if baseline == candidate:
            raise EvaluationLabError("candidate_ref must differ from baseline_ref")
        if not isinstance(self.checks, dict):
            raise EvaluationLabError("checks must be an object")
        for name, value in self.checks.items():
            if not _CHECK_RE.fullmatch(str(name).strip().upper()):
                raise EvaluationLabError("check names must be compact identifiers")
            if not isinstance(value, bool):
                raise EvaluationLabError(f"check {name} must be boolean")
        _safe_refs(self.evidence_refs)
        if self.label_commitment_sha256 is not None:
            _sha256(self.label_commitment_sha256, "label_commitment_sha256")
        if not isinstance(self.security_passed, bool) or not isinstance(self.holdout_evaluator, bool):
            raise EvaluationLabError("security/holdout evaluator flags must be boolean")
        return self


class PromotionPipeline:
    """Fail-closed v1 production promotion admission over versioned corpus evidence."""

    @staticmethod
    def evaluate(
        corpus: EvaluationCorpus,
        evidence: Iterable[EvaluationEvidence],
        *,
        baseline_ref: str,
        candidate_ref: str,
        rollback_ref: str,
    ) -> dict[str, Any]:
        corpus.validate()
        baseline = _git_sha(baseline_ref, "baseline_ref")
        candidate = _git_sha(candidate_ref, "candidate_ref")
        rollback = _git_sha(rollback_ref, "rollback_ref")
        if baseline == candidate:
            raise EvaluationLabError("candidate_ref must differ from baseline_ref")
        if rollback != baseline:
            raise EvaluationLabError(
                "v1 rollback_ref must exactly equal the evaluated baseline_ref"
            )

        rows = [row.validate() for row in evidence]
        by_class: dict[str, EvaluationEvidence] = {}
        failures: list[str] = []
        for row in rows:
            if row.corpus_class in by_class:
                failures.append(f"DUPLICATE_EVIDENCE:{row.corpus_class}")
                continue
            by_class[row.corpus_class] = row

        class_results: dict[str, Any] = {}
        specs = corpus.by_id()
        for class_id in CORPUS_CLASSES:
            spec = specs[class_id]
            row = by_class.get(class_id)
            class_failures: list[str] = []
            if row is None:
                class_failures.append("EVIDENCE_MISSING")
            else:
                if row.corpus_id != corpus.corpus_id or row.corpus_sha256 != corpus.sha256:
                    class_failures.append("CORPUS_LINEAGE_MISMATCH")
                if row.metric_schema_version != corpus.metric_schema_version:
                    class_failures.append("METRIC_SCHEMA_MISMATCH")
                if row.baseline_ref != baseline or row.candidate_ref != candidate:
                    class_failures.append("SOURCE_LINEAGE_MISMATCH")
                if not row.security_passed:
                    class_failures.append("SECURITY_GATE_FAILED")
                missing_checks = [
                    check for check in spec.required_checks
                    if row.checks.get(check) is not True
                ]
                class_failures.extend(
                    f"REQUIRED_CHECK_FAILED:{check}" for check in missing_checks
                )
                for check in HARD_QUALITY_CHECKS:
                    if check in spec.required_checks and row.checks.get(check) is not True:
                        marker = f"QUALITY_REGRESSION:{check}"
                        if marker not in class_failures:
                            class_failures.append(marker)
                if spec.label_policy == "external_holdout_required":
                    if row.label_commitment_sha256 is None:
                        class_failures.append("HOLDOUT_LABEL_COMMITMENT_MISSING")
                    if not row.holdout_evaluator:
                        class_failures.append("HOLDOUT_EVALUATOR_NOT_ATTESTED")
            if class_failures:
                failures.extend(f"{class_id}:{item}" for item in class_failures)
            class_results[class_id] = {
                "passed": not class_failures,
                "failures": class_failures,
                "evidence_id": row.evidence_id if row is not None else None,
                "evidence_refs": list(row.evidence_refs) if row is not None else [],
                "label_commitment_sha256": (
                    row.label_commitment_sha256 if row is not None else None
                ),
            }

        accepted = not failures and len(by_class) == len(CORPUS_CLASSES)
        receipt = {
            "schema_version": PROMOTION_SCHEMA,
            "accepted": accepted,
            "baseline_ref": baseline,
            "candidate_ref": candidate,
            "rollback_ref": rollback,
            "corpus_id": corpus.corpus_id,
            "corpus_sha256": corpus.sha256,
            "metric_schema_version": corpus.metric_schema_version,
            "metric_definitions_sha256": metric_definitions_sha256(),
            "classes": class_results,
            "failures": failures,
            "security": {
                "holdout_labels_embedded": False,
                "raw_prompts_embedded": False,
                "raw_evidence_embedded": False,
                "rollback_lineage_required": True,
                "all_corpus_classes_required": True,
            },
        }
        receipt["receipt_sha256"] = _canonical_hash(receipt)
        return receipt


def _write_json(path: Path, payload: dict[str, Any], *, force: bool) -> Path:
    target = Path(path)
    if target.exists() and not force:
        raise FileExistsError(f"output already exists: {target}")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(target)
    return target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-eval",
        description="WorkSpace versioned evaluation corpus and fail-closed promotion gate",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate-corpus")
    validate.add_argument("--corpus", required=True)

    promote = sub.add_parser("promotion-check")
    promote.add_argument("--corpus", required=True)
    promote.add_argument("--baseline-ref", required=True)
    promote.add_argument("--candidate-ref", required=True)
    promote.add_argument("--rollback-ref", required=True)
    promote.add_argument("--evidence", action="append", required=True)
    promote.add_argument("--output")
    promote.add_argument("--force", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        corpus = EvaluationCorpus.load(Path(args.corpus))
        if args.command == "validate-corpus":
            print(json.dumps(corpus.optimizer_view(), ensure_ascii=False, indent=2))
            return 0

        evidence = [EvaluationEvidence.load(Path(path)) for path in args.evidence]
        receipt = PromotionPipeline.evaluate(
            corpus,
            evidence,
            baseline_ref=args.baseline_ref,
            candidate_ref=args.candidate_ref,
            rollback_ref=args.rollback_ref,
        )
        if args.output:
            _write_json(Path(args.output), receipt, force=args.force)
        print(json.dumps(receipt, ensure_ascii=False, indent=2))
        return 0 if receipt["accepted"] else 3
    except (OSError, json.JSONDecodeError, EvaluationLabError, FileExistsError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": PROMOTION_SCHEMA,
                    "accepted": False,
                    "error": f"{type(exc).__name__}: {exc}",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
