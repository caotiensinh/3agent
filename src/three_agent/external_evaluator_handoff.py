from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .evaluation_profiles import (
    EvaluationProfile,
    EvaluationProfileError,
    EvaluationProfileResult,
    PROFILE_RESULT_SCHEMA,
)
from .metric_registry import DEFAULT_METRIC_REGISTRY, METRIC_REGISTRY_ID

EXTERNAL_EVALUATOR_HANDOFF_SCHEMA = "workspace-external-evaluator-handoff/v1"
EDGE_LARGE_CONTEXT_PROFILE_ID = "workspace-edge-large-context-v1"

_D705_REQUIREMENTS = {
    "security_pass": "required-external-true",
    "evaluator_identity_reference": "required-external",
    "evaluator_attestation": "required-external-true",
    "holdout_label_commitment": "required-external-sha256",
    "case_coverage": "exact-profile-case-set",
    "required_checks": "all-required-true",
    "evidence": "compact-metadata-refs-only",
    "unknown_fields": "reject",
}


@dataclass(frozen=True)
class ExternalEvaluatorHandoffCase:
    case_id: str
    required_checks: tuple[str, ...]

    @classmethod
    def from_payload(cls, payload: Any) -> "ExternalEvaluatorHandoffCase":
        if not isinstance(payload, dict) or set(payload) != {
            "case_id",
            "required_checks",
        }:
            raise EvaluationProfileError(
                "external evaluator handoff case contains unsupported fields"
            )
        case_id = str(payload.get("case_id") or "").strip()
        raw_checks = payload.get("required_checks")
        if not case_id or not isinstance(raw_checks, list) or not raw_checks:
            raise EvaluationProfileError(
                "external evaluator handoff case is incomplete"
            )
        checks: list[str] = []
        for raw in raw_checks:
            check = str(raw or "").strip()
            if not check or check in checks:
                raise EvaluationProfileError(
                    "external evaluator handoff required_checks must be unique non-empty IDs"
                )
            checks.append(check)
        return cls(case_id=case_id, required_checks=tuple(checks))

    def to_payload(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "required_checks": list(self.required_checks),
        }


@dataclass(frozen=True)
class ExternalEvaluatorHandoff:
    profile_id: str
    profile_sha256: str
    corpus_class: str
    metric_registry_id: str
    metric_registry_sha256: str
    baseline_ref: str
    candidate_ref: str
    external_result_schema: str
    requirements: dict[str, str]
    cases: tuple[ExternalEvaluatorHandoffCase, ...]

    @classmethod
    def from_payload(
        cls,
        payload: Any,
        *,
        profile: EvaluationProfile,
    ) -> "ExternalEvaluatorHandoff":
        if not isinstance(payload, dict):
            raise EvaluationProfileError(
                "external evaluator handoff must be an object"
            )
        if payload.get("schema_version") != EXTERNAL_EVALUATOR_HANDOFF_SCHEMA:
            raise EvaluationProfileError(
                f"external evaluator handoff schema must be "
                f"{EXTERNAL_EVALUATOR_HANDOFF_SCHEMA}"
            )
        allowed = {
            "schema_version",
            "profile_id",
            "profile_sha256",
            "corpus_class",
            "metric_registry_id",
            "metric_registry_sha256",
            "baseline_ref",
            "candidate_ref",
            "external_result_schema",
            "requirements",
            "cases",
        }
        if set(payload) != allowed:
            raise EvaluationProfileError(
                "external evaluator handoff contains unsupported fields"
            )
        raw_requirements = payload.get("requirements")
        if not isinstance(raw_requirements, dict):
            raise EvaluationProfileError(
                "external evaluator handoff requirements must be an object"
            )
        if raw_requirements != _D705_REQUIREMENTS:
            raise EvaluationProfileError(
                "external evaluator handoff requirements are not the fail-closed D7-05 contract"
            )
        raw_cases = payload.get("cases")
        if not isinstance(raw_cases, list) or not raw_cases:
            raise EvaluationProfileError(
                "external evaluator handoff must contain cases"
            )
        handoff = cls(
            profile_id=str(payload.get("profile_id") or "").strip(),
            profile_sha256=str(payload.get("profile_sha256") or "").strip(),
            corpus_class=str(payload.get("corpus_class") or "").strip(),
            metric_registry_id=str(
                payload.get("metric_registry_id") or ""
            ).strip(),
            metric_registry_sha256=str(
                payload.get("metric_registry_sha256") or ""
            ).strip(),
            baseline_ref=str(payload.get("baseline_ref") or "").strip(),
            candidate_ref=str(payload.get("candidate_ref") or "").strip(),
            external_result_schema=str(
                payload.get("external_result_schema") or ""
            ).strip(),
            requirements=dict(raw_requirements),
            cases=tuple(
                ExternalEvaluatorHandoffCase.from_payload(item)
                for item in raw_cases
            ),
        )
        return handoff.validate(profile)

    @classmethod
    def load(
        cls,
        path: Path,
        *,
        profile: EvaluationProfile,
    ) -> "ExternalEvaluatorHandoff":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_payload(payload, profile=profile)

    def validate(
        self,
        profile: EvaluationProfile,
    ) -> "ExternalEvaluatorHandoff":
        profile.validate()
        if profile.profile_id != EDGE_LARGE_CONTEXT_PROFILE_ID:
            raise EvaluationProfileError(
                "D7-05 handoff supports only workspace-edge-large-context-v1"
            )
        if self.profile_id != profile.profile_id:
            raise EvaluationProfileError(
                "handoff profile_id does not match repository profile"
            )
        if self.profile_sha256 != profile.sha256:
            raise EvaluationProfileError(
                "handoff profile SHA-256 does not match repository profile"
            )
        if self.corpus_class != "edge_large_context":
            raise EvaluationProfileError(
                "D7-05 handoff corpus_class must be edge_large_context"
            )
        if self.corpus_class != profile.corpus_class:
            raise EvaluationProfileError(
                "handoff corpus_class does not match repository profile"
            )
        if self.metric_registry_id != METRIC_REGISTRY_ID:
            raise EvaluationProfileError(
                "handoff metric registry id mismatch"
            )
        if self.metric_registry_sha256 != DEFAULT_METRIC_REGISTRY.sha256:
            raise EvaluationProfileError(
                "handoff metric registry fingerprint mismatch"
            )
        if not _is_git_sha(self.baseline_ref):
            raise EvaluationProfileError(
                "handoff baseline_ref must be an exact 40-hex Git SHA"
            )
        if not _is_git_sha(self.candidate_ref):
            raise EvaluationProfileError(
                "handoff candidate_ref must be an exact 40-hex Git SHA"
            )
        if self.baseline_ref == self.candidate_ref:
            raise EvaluationProfileError(
                "handoff candidate_ref must differ from baseline_ref"
            )
        if self.external_result_schema != PROFILE_RESULT_SCHEMA:
            raise EvaluationProfileError(
                "handoff external_result_schema is not current"
            )
        if self.requirements != _D705_REQUIREMENTS:
            raise EvaluationProfileError(
                "handoff external requirements are not the fail-closed D7-05 contract"
            )

        expected = {
            case.case_id: tuple(case.required_checks)
            for case in profile.cases
        }
        actual = {
            case.case_id: tuple(case.required_checks)
            for case in self.cases
        }
        if len(actual) != len(self.cases):
            raise EvaluationProfileError(
                "handoff case_id values must be unique"
            )
        if actual != expected:
            raise EvaluationProfileError(
                "handoff case/check contract must exactly match repository profile"
            )
        return self

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": EXTERNAL_EVALUATOR_HANDOFF_SCHEMA,
            "profile_id": self.profile_id,
            "profile_sha256": self.profile_sha256,
            "corpus_class": self.corpus_class,
            "metric_registry_id": self.metric_registry_id,
            "metric_registry_sha256": self.metric_registry_sha256,
            "baseline_ref": self.baseline_ref,
            "candidate_ref": self.candidate_ref,
            "external_result_schema": self.external_result_schema,
            "requirements": dict(self.requirements),
            "cases": [case.to_payload() for case in self.cases],
        }


def _is_git_sha(value: str) -> bool:
    return (
        len(value) == 40
        and value == value.lower()
        and all(ch in "0123456789abcdef" for ch in value)
    )


def build_external_evaluator_handoff(
    profile: EvaluationProfile,
    *,
    baseline_ref: str,
    candidate_ref: str,
) -> ExternalEvaluatorHandoff:
    profile.validate()
    if profile.profile_id != EDGE_LARGE_CONTEXT_PROFILE_ID:
        raise EvaluationProfileError(
            "D7-05 handoff supports only workspace-edge-large-context-v1"
        )
    handoff = ExternalEvaluatorHandoff(
        profile_id=profile.profile_id,
        profile_sha256=profile.sha256,
        corpus_class=profile.corpus_class,
        metric_registry_id=METRIC_REGISTRY_ID,
        metric_registry_sha256=DEFAULT_METRIC_REGISTRY.sha256,
        baseline_ref=str(baseline_ref or "").strip().lower(),
        candidate_ref=str(candidate_ref or "").strip().lower(),
        external_result_schema=PROFILE_RESULT_SCHEMA,
        requirements=dict(_D705_REQUIREMENTS),
        cases=tuple(
            ExternalEvaluatorHandoffCase(
                case_id=case.case_id,
                required_checks=tuple(case.required_checks),
            )
            for case in profile.cases
        ),
    )
    return handoff.validate(profile)


def validate_external_result_against_handoff(
    profile: EvaluationProfile,
    handoff: ExternalEvaluatorHandoff,
    result: EvaluationProfileResult,
) -> EvaluationProfileResult:
    """Validate exact D7-05 handoff lineage before the existing result adapter."""
    handoff.validate(profile)
    result.validate()
    if result.profile_id != handoff.profile_id:
        raise EvaluationProfileError(
            "external result profile_id does not match handoff"
        )
    if result.profile_sha256 != handoff.profile_sha256:
        raise EvaluationProfileError(
            "external result profile SHA-256 does not match handoff"
        )
    if result.corpus_class != handoff.corpus_class:
        raise EvaluationProfileError(
            "external result corpus_class does not match handoff"
        )
    if result.metric_registry_id != handoff.metric_registry_id:
        raise EvaluationProfileError(
            "external result metric registry id does not match handoff"
        )
    if result.metric_registry_sha256 != handoff.metric_registry_sha256:
        raise EvaluationProfileError(
            "external result metric registry SHA-256 does not match handoff"
        )
    if result.baseline_ref != handoff.baseline_ref:
        raise EvaluationProfileError(
            "external result baseline_ref does not match handoff"
        )
    if result.candidate_ref != handoff.candidate_ref:
        raise EvaluationProfileError(
            "external result candidate_ref does not match handoff"
        )
    if result.evaluator_attested is not True:
        raise EvaluationProfileError(
            "external evaluator attestation is required"
        )
    if result.label_commitment_sha256 is None:
        raise EvaluationProfileError(
            "external holdout label commitment is required"
        )

    expected = {
        case.case_id: tuple(case.required_checks)
        for case in profile.cases
    }
    actual = {case.case_id: case for case in result.cases}
    if set(actual) != set(expected):
        raise EvaluationProfileError(
            "external result case set must exactly match handoff profile"
        )
    for case_id, required_checks in expected.items():
        row = actual[case_id]
        for check in required_checks:
            if row.checks.get(check) is not True:
                raise EvaluationProfileError(
                    f"external result required check failed: {case_id}:{check}"
                )
    return result


def _write_json_atomic(
    path: Path,
    payload: dict[str, Any],
    *,
    force: bool,
) -> None:
    destination = Path(path)
    if destination.exists() and not force:
        raise FileExistsError(f"output already exists: {destination}")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-eval-handoff",
        description=(
            "Create or validate the fail-closed metadata-only D7-05 external "
            "evaluator handoff. This command does not emit promotion evidence."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--profile", required=True)
    create.add_argument("--baseline-ref", required=True)
    create.add_argument("--candidate-ref", required=True)
    create.add_argument("--output", required=True)
    create.add_argument("--force", action="store_true")

    validate = subparsers.add_parser("validate-result")
    validate.add_argument("--profile", required=True)
    validate.add_argument("--handoff", required=True)
    validate.add_argument("--result", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        profile = EvaluationProfile.load(Path(args.profile))
        if args.command == "create":
            handoff = build_external_evaluator_handoff(
                profile,
                baseline_ref=args.baseline_ref,
                candidate_ref=args.candidate_ref,
            )
            payload = handoff.to_payload()
            _write_json_atomic(
                Path(args.output),
                payload,
                force=args.force,
            )
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0

        handoff = ExternalEvaluatorHandoff.load(
            Path(args.handoff),
            profile=profile,
        )
        result = EvaluationProfileResult.load(Path(args.result))
        validate_external_result_against_handoff(
            profile,
            handoff,
            result,
        )
        print(
            json.dumps(
                {
                    "schema_version": EXTERNAL_EVALUATOR_HANDOFF_SCHEMA,
                    "accepted_for_profile_adapter": True,
                    "profile_id": profile.profile_id,
                    "profile_sha256": profile.sha256,
                    "metric_registry_id": METRIC_REGISTRY_ID,
                    "metric_registry_sha256": DEFAULT_METRIC_REGISTRY.sha256,
                    "baseline_ref": handoff.baseline_ref,
                    "candidate_ref": handoff.candidate_ref,
                    "next_adapter": "workspace-eval-profile",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
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
                    "schema_version": EXTERNAL_EVALUATOR_HANDOFF_SCHEMA,
                    "accepted_for_profile_adapter": False,
                    "error": f"{type(exc).__name__}: {exc}",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
