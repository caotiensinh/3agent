from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .metric_registry import DEFAULT_METRIC_REGISTRY, METRIC_REGISTRY_ID
from .promotion_gate import PromotionEvidence, PROMOTION_EVIDENCE_SCHEMA

PROFILE_SCHEMA = "workspace-evaluation-profile/v1"
PROFILE_RESULT_SCHEMA = "workspace-evaluation-profile-result/v1"
PROFILE_CLASSES = ("edge_large_context", "efficiency_cache_concurrency")
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$")
_CHECK_RE = re.compile(r"^[A-Z0-9][A-Z0-9_]{0,95}$")
_DIMENSION_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_EVIDENCE_REF_RE = re.compile(
    r"^(?:sha256:[0-9a-f]{64}|[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255})$"
)


class EvaluationProfileError(ValueError):
    """A D7 external evaluation profile/result is incomplete or unsafe."""


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _compact(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not _ID_RE.fullmatch(text):
        raise EvaluationProfileError(f"{field} must be a compact stable identifier")
    return text


def _git_sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _GIT_SHA_RE.fullmatch(text):
        raise EvaluationProfileError(f"{field} must be an exact 40-hex Git SHA")
    return text


def _sha256(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise EvaluationProfileError(f"{field} must be sha256:<64-hex>")
    return text


def _checks(values: Any, field: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise EvaluationProfileError(f"{field} must be a non-empty sequence")
    result: list[str] = []
    for raw in values:
        item = str(raw or "").strip().upper()
        if not _CHECK_RE.fullmatch(item):
            raise EvaluationProfileError(f"invalid check in {field}: {item}")
        if item not in result:
            result.append(item)
    return tuple(result)


def _dimensions(values: Any, field: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise EvaluationProfileError(f"{field} must be a non-empty sequence")
    result: list[str] = []
    for raw in values:
        item = str(raw or "").strip().lower()
        if not _DIMENSION_RE.fullmatch(item):
            raise EvaluationProfileError(f"invalid dimension in {field}: {item}")
        if item not in result:
            result.append(item)
    return tuple(result)


def _evidence_refs(values: Any, field: str) -> tuple[str, ...]:
    if not isinstance(values, (list, tuple)) or not values:
        raise EvaluationProfileError(f"{field} must be a non-empty sequence")
    result: list[str] = []
    for raw in values:
        item = str(raw or "").strip()
        if not _EVIDENCE_REF_RE.fullmatch(item):
            raise EvaluationProfileError(
                f"{field} accepts compact IDs/hashes only; raw content is forbidden"
            )
        if item not in result:
            result.append(item)
        if len(result) > 32:
            raise EvaluationProfileError(f"{field} supports at most 32 refs")
    return tuple(result)


@dataclass(frozen=True)
class EvaluationProfileCase:
    case_id: str
    dimensions: tuple[str, ...]
    required_checks: tuple[str, ...]

    @classmethod
    def from_payload(cls, payload: Any) -> "EvaluationProfileCase":
        if not isinstance(payload, dict) or set(payload) != {
            "case_id",
            "dimensions",
            "required_checks",
        }:
            raise EvaluationProfileError("profile case contains unsupported fields")
        return cls(
            case_id=_compact(payload.get("case_id"), "case_id"),
            dimensions=_dimensions(payload.get("dimensions"), "dimensions"),
            required_checks=_checks(payload.get("required_checks"), "required_checks"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "dimensions": list(self.dimensions),
            "required_checks": list(self.required_checks),
        }


@dataclass(frozen=True)
class EvaluationProfile:
    profile_id: str
    corpus_class: str
    metric_registry_id: str
    holdout_labels_external: bool
    cases: tuple[EvaluationProfileCase, ...]
    source_path: Path

    @classmethod
    def load(cls, path: Path) -> "EvaluationProfile":
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != PROFILE_SCHEMA:
            raise EvaluationProfileError(f"profile schema must be {PROFILE_SCHEMA}")
        if set(payload) != {
            "schema_version",
            "profile_id",
            "corpus_class",
            "metric_registry_id",
            "holdout_labels_external",
            "cases",
        }:
            raise EvaluationProfileError("profile contains unsupported fields")
        raw_cases = payload.get("cases")
        if not isinstance(raw_cases, list) or not 1 <= len(raw_cases) <= 64:
            raise EvaluationProfileError("profile must contain between 1 and 64 cases")
        cases = tuple(EvaluationProfileCase.from_payload(item) for item in raw_cases)
        profile = cls(
            profile_id=_compact(payload.get("profile_id"), "profile_id"),
            corpus_class=str(payload.get("corpus_class") or "").strip(),
            metric_registry_id=str(payload.get("metric_registry_id") or "").strip(),
            holdout_labels_external=payload.get("holdout_labels_external"),
            cases=cases,
            source_path=source,
        )
        return profile.validate()

    def validate(self) -> "EvaluationProfile":
        _compact(self.profile_id, "profile_id")
        if self.corpus_class not in PROFILE_CLASSES:
            raise EvaluationProfileError("profile corpus_class is not supported")
        if self.metric_registry_id != METRIC_REGISTRY_ID:
            raise EvaluationProfileError("profile metric registry is not current")
        if not isinstance(self.holdout_labels_external, bool):
            raise EvaluationProfileError("holdout_labels_external must be boolean")
        if self.corpus_class == "edge_large_context" and not self.holdout_labels_external:
            raise EvaluationProfileError("edge/large-context profile requires external holdout labels")
        if self.corpus_class == "efficiency_cache_concurrency" and self.holdout_labels_external:
            raise EvaluationProfileError("efficiency profile must not claim hidden holdout labels")
        if not self.cases:
            raise EvaluationProfileError("profile must contain cases")
        ids = [case.case_id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise EvaluationProfileError("profile case_id values must be unique")
        for case in self.cases:
            _compact(case.case_id, "case_id")
            _dimensions(case.dimensions, "dimensions")
            _checks(case.required_checks, "required_checks")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": PROFILE_SCHEMA,
            "profile_id": self.profile_id,
            "corpus_class": self.corpus_class,
            "metric_registry_id": self.metric_registry_id,
            "holdout_labels_external": self.holdout_labels_external,
            "cases": [case.to_payload() for case in self.cases],
        }

    @property
    def sha256(self) -> str:
        return _canonical_sha256(self.to_payload())

    @property
    def required_checks(self) -> tuple[str, ...]:
        result: list[str] = []
        for case in self.cases:
            for check in case.required_checks:
                if check not in result:
                    result.append(check)
        return tuple(result)

    def optimizer_view(self) -> dict[str, Any]:
        return {
            "schema_version": "workspace-evaluation-profile-optimizer-view/v1",
            "profile_id": self.profile_id,
            "profile_sha256": self.sha256,
            "corpus_class": self.corpus_class,
            "metric_registry_id": self.metric_registry_id,
            "metric_registry_sha256": DEFAULT_METRIC_REGISTRY.sha256,
            "holdout_labels_embedded": False,
            "holdout_label_commitment_embedded": False,
            "cases": [
                {
                    "case_id": case.case_id,
                    "dimensions": list(case.dimensions),
                    "required_checks": list(case.required_checks),
                }
                for case in self.cases
            ],
        }


@dataclass(frozen=True)
class EvaluationProfileCaseResult:
    case_id: str
    checks: dict[str, bool]
    evidence_refs: tuple[str, ...]

    @classmethod
    def from_payload(cls, payload: Any) -> "EvaluationProfileCaseResult":
        if not isinstance(payload, dict) or set(payload) != {
            "case_id",
            "checks",
            "evidence_refs",
        }:
            raise EvaluationProfileError("profile result case contains unsupported fields")
        raw_checks = payload.get("checks")
        if not isinstance(raw_checks, dict) or not raw_checks:
            raise EvaluationProfileError("profile result checks must be a non-empty object")
        checks: dict[str, bool] = {}
        for raw_name, value in raw_checks.items():
            name = str(raw_name or "").strip().upper()
            if not _CHECK_RE.fullmatch(name) or not isinstance(value, bool):
                raise EvaluationProfileError("profile result checks must be boolean compact IDs")
            checks[name] = value
        return cls(
            case_id=_compact(payload.get("case_id"), "result.case_id"),
            checks=checks,
            evidence_refs=_evidence_refs(payload.get("evidence_refs"), "result.evidence_refs"),
        )


@dataclass(frozen=True)
class EvaluationProfileResult:
    profile_id: str
    profile_sha256: str
    corpus_class: str
    metric_registry_id: str
    metric_registry_sha256: str
    baseline_ref: str
    candidate_ref: str
    security_passed: bool
    evaluator_attested: bool
    evaluator_ref: str
    label_commitment_sha256: str | None
    cases: tuple[EvaluationProfileCaseResult, ...]

    @classmethod
    def load(cls, path: Path) -> "EvaluationProfileResult":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != PROFILE_RESULT_SCHEMA:
            raise EvaluationProfileError(f"profile result schema must be {PROFILE_RESULT_SCHEMA}")
        if set(payload) != {
            "schema_version",
            "profile_id",
            "profile_sha256",
            "corpus_class",
            "metric_registry_id",
            "metric_registry_sha256",
            "baseline_ref",
            "candidate_ref",
            "security_passed",
            "evaluator_attested",
            "evaluator_ref",
            "label_commitment_sha256",
            "cases",
        }:
            raise EvaluationProfileError("profile result contains unsupported fields")
        raw_cases = payload.get("cases")
        if not isinstance(raw_cases, list) or not raw_cases:
            raise EvaluationProfileError("profile result must contain cases")
        label_raw = payload.get("label_commitment_sha256")
        return cls(
            profile_id=_compact(payload.get("profile_id"), "result.profile_id"),
            profile_sha256=_sha256(payload.get("profile_sha256"), "result.profile_sha256"),
            corpus_class=str(payload.get("corpus_class") or "").strip(),
            metric_registry_id=str(payload.get("metric_registry_id") or "").strip(),
            metric_registry_sha256=_sha256(
                payload.get("metric_registry_sha256"), "result.metric_registry_sha256"
            ),
            baseline_ref=_git_sha(payload.get("baseline_ref"), "result.baseline_ref"),
            candidate_ref=_git_sha(payload.get("candidate_ref"), "result.candidate_ref"),
            security_passed=payload.get("security_passed"),
            evaluator_attested=payload.get("evaluator_attested"),
            evaluator_ref=_evidence_refs([payload.get("evaluator_ref")], "result.evaluator_ref")[0],
            label_commitment_sha256=(
                None
                if label_raw is None
                else _sha256(label_raw, "result.label_commitment_sha256")
            ),
            cases=tuple(EvaluationProfileCaseResult.from_payload(item) for item in raw_cases),
        ).validate()

    def validate(self) -> "EvaluationProfileResult":
        _compact(self.profile_id, "result.profile_id")
        _sha256(self.profile_sha256, "result.profile_sha256")
        if self.corpus_class not in PROFILE_CLASSES:
            raise EvaluationProfileError("result corpus_class is not supported")
        if self.metric_registry_id != METRIC_REGISTRY_ID:
            raise EvaluationProfileError("result metric registry id mismatch")
        if self.metric_registry_sha256 != DEFAULT_METRIC_REGISTRY.sha256:
            raise EvaluationProfileError("result metric registry fingerprint mismatch")
        baseline = _git_sha(self.baseline_ref, "result.baseline_ref")
        candidate = _git_sha(self.candidate_ref, "result.candidate_ref")
        if baseline == candidate:
            raise EvaluationProfileError("result candidate_ref must differ from baseline_ref")
        if self.security_passed is not True:
            raise EvaluationProfileError("result security_passed must be true")
        if self.evaluator_attested is not True:
            raise EvaluationProfileError("result evaluator_attested must be true")
        _evidence_refs([self.evaluator_ref], "result.evaluator_ref")
        if self.label_commitment_sha256 is not None:
            _sha256(self.label_commitment_sha256, "result.label_commitment_sha256")
        ids = [case.case_id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise EvaluationProfileError("result case_id values must be unique")
        return self


def build_profile_promotion_evidence(
    profile: EvaluationProfile,
    result: EvaluationProfileResult,
    *,
    evidence_id: str,
) -> PromotionEvidence:
    profile.validate()
    result.validate()
    if result.profile_id != profile.profile_id or result.profile_sha256 != profile.sha256:
        raise EvaluationProfileError("result profile lineage does not match repository profile")
    if result.corpus_class != profile.corpus_class:
        raise EvaluationProfileError("result corpus_class does not match profile")
    if profile.corpus_class == "edge_large_context" and result.label_commitment_sha256 is None:
        raise EvaluationProfileError("edge/large-context result requires label commitment SHA-256")
    if profile.corpus_class == "efficiency_cache_concurrency" and result.label_commitment_sha256 is not None:
        raise EvaluationProfileError("efficiency result must not attach holdout label commitment")

    expected = {case.case_id: case for case in profile.cases}
    actual = {case.case_id: case for case in result.cases}
    if set(expected) != set(actual):
        raise EvaluationProfileError("result case set must exactly match profile case set")

    aggregate_checks: dict[str, bool] = {}
    refs: list[str] = [result.evaluator_ref]
    for case_id, spec in expected.items():
        row = actual[case_id]
        for check in spec.required_checks:
            if row.checks.get(check) is not True:
                raise EvaluationProfileError(
                    f"required profile check failed: {case_id}:{check}"
                )
            aggregate_checks[check] = True
        for ref in row.evidence_refs:
            if ref not in refs:
                refs.append(ref)
    if len(refs) > 32:
        raise EvaluationProfileError("aggregated evidence_refs exceed 32")

    payload = {
        "schema_version": PROMOTION_EVIDENCE_SCHEMA,
        "evidence_id": _compact(evidence_id, "evidence_id"),
        "corpus_class": profile.corpus_class,
        "corpus_id": profile.profile_id,
        "corpus_sha256": profile.sha256,
        "metric_registry_id": METRIC_REGISTRY_ID,
        "metric_registry_sha256": DEFAULT_METRIC_REGISTRY.sha256,
        "baseline_ref": result.baseline_ref,
        "candidate_ref": result.candidate_ref,
        "checks": aggregate_checks,
        "security_passed": True,
        "evidence_refs": refs,
        "label_commitment_sha256": result.label_commitment_sha256,
        "evaluator_attested": True,
    }
    return PromotionEvidence.from_payload(payload)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-eval-profile",
        description="Validate D7 edge/efficiency external results and emit promotion evidence",
    )
    parser.add_argument("--profile", required=True)
    parser.add_argument("--result")
    parser.add_argument("--evidence-id")
    parser.add_argument("--output")
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = EvaluationProfile.load(Path(args.profile))
        if not args.result:
            print(json.dumps(profile.optimizer_view(), ensure_ascii=False, indent=2))
            return 0
        if not args.evidence_id or not args.output:
            raise EvaluationProfileError(
                "--evidence-id and --output are required when --result is provided"
            )
        result = EvaluationProfileResult.load(Path(args.result))
        evidence = build_profile_promotion_evidence(
            profile,
            result,
            evidence_id=args.evidence_id,
        )
        destination = Path(args.output)
        if destination.exists() and not args.force:
            raise FileExistsError(f"output already exists: {destination}")
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".tmp")
        temporary.write_text(
            json.dumps(evidence.to_payload(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(destination)
        print(json.dumps(evidence.to_payload(), ensure_ascii=False, indent=2))
        return 0
    except (
        OSError,
        json.JSONDecodeError,
        EvaluationProfileError,
        FileExistsError,
        ValueError,
    ) as exc:
        print(
            json.dumps(
                {
                    "schema_version": PROFILE_RESULT_SCHEMA,
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
