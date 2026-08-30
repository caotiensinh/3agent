from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .benchmark_snapshot import unpack_metrics_payload
from .efficiency_concurrency_observer import PROFILE_ID, validate_observation_receipt
from .evaluation_profiles import (
    EvaluationProfile,
    EvaluationProfileError,
    EvaluationProfileResult,
    PROFILE_RESULT_SCHEMA,
)
from .metric_registry import DEFAULT_METRIC_REGISTRY, METRIC_REGISTRY_ID
from .resource_benefit_observer import validate_receipt as validate_resource_receipt

SCHEMA = "workspace-efficiency-evaluator-handoff/v1"
PROFILE = PROFILE_ID
_SHA = re.compile(r"^[0-9a-f]{40}$")
_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")

REQUIREMENTS = {
    "security_pass": "required-external-true",
    "evaluator_attestation": "required-external-true",
    "label_commitment": "forbidden-null",
    "case_coverage": "exact-profile-case-set",
    "required_checks": "all-required-true",
    "local_evidence": "bound-by-sha256",
    "backend_cache_isolation": "required-external-independent-evidence",
    "evidence": "compact-metadata-refs-only",
    "unknown_fields": "reject",
}
CASE_BINDINGS = {
    "fixed-task-quality-before-efficiency": ("baseline_benchmark", "candidate_benchmark"),
    "structured-output-under-concurrency": ("baseline_observation", "candidate_observation"),
    "measured-resource-benefit": (
        "baseline_benchmark", "candidate_benchmark",
        "baseline_resource_benefit", "candidate_resource_benefit",
    ),
    "cache-trust-domain-isolation": (),
    "retry-budget-under-concurrency": (
        "baseline_benchmark", "candidate_benchmark",
        "baseline_observation", "candidate_observation",
    ),
    "cache-claim-measurement-honesty": (
        "baseline_observation", "candidate_observation",
        "baseline_resource_benefit", "candidate_resource_benefit",
    ),
}


class EfficiencyEvaluatorHandoffError(ValueError):
    pass


def canonical_hash(value: Any) -> str:
    raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _git(value: Any, field: str) -> str:
    value = str(value or "").strip().lower()
    if not _SHA.fullmatch(value):
        raise EfficiencyEvaluatorHandoffError(f"{field} must be an exact 40-hex Git SHA")
    return value


def _hash(value: Any, field: str) -> str:
    value = str(value or "").strip().lower()
    if not _HASH.fullmatch(value):
        raise EfficiencyEvaluatorHandoffError(f"{field} must be sha256:<64-hex>")
    return value


def _json(path: Path) -> dict[str, Any]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise EfficiencyEvaluatorHandoffError(f"{path} must contain a JSON object")
    return value


def _num(value: Any, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EfficiencyEvaluatorHandoffError(f"{field} must be numeric")
    return float(value)


def _benchmark(path: Path, ref: str):
    payload = _json(path)
    try:
        metrics, lineage = unpack_metrics_payload(payload)
    except ValueError as exc:
        raise EfficiencyEvaluatorHandoffError(str(exc)) from exc
    if lineage is None:
        raise EfficiencyEvaluatorHandoffError("D7-06 requires lineage-bound benchmark manifests")
    if str(lineage.get("source_ref") or "").lower() != ref:
        raise EfficiencyEvaluatorHandoffError("benchmark source_ref mismatch")
    if lineage.get("metric_registry_sha256") != DEFAULT_METRIC_REGISTRY.sha256:
        raise EfficiencyEvaluatorHandoffError("benchmark metric registry is not current")
    return metrics, lineage, {
        "manifest_sha256": canonical_hash(payload),
        "metrics_sha256": _hash(lineage.get("metrics_sha256"), "metrics_sha256"),
        "task_scope_sha256": _hash(lineage.get("task_scope_sha256"), "task_scope_sha256"),
        "configuration_sha256": _hash(lineage.get("configuration_sha256"), "configuration_sha256"),
    }


def _quality(metrics: dict[str, Any]) -> dict[str, float]:
    verified = metrics.get("verified_work")
    evidence = metrics.get("evidence_coverage")
    if not isinstance(verified, dict) or not isinstance(evidence, dict):
        raise EfficiencyEvaluatorHandoffError("required quality metrics are missing")
    return {
        "verified_task_success_rate": _num(verified.get("verified_task_success_rate"), "verified_task_success_rate"),
        "first_pass_verified_success_rate": _num(verified.get("first_pass_verified_success_rate"), "first_pass_verified_success_rate"),
        "verified_tasks": _num(verified.get("verified_tasks"), "verified_tasks"),
        "evidence_coverage": _num(evidence.get("evidence_coverage"), "evidence_coverage"),
    }


def _quality_gate(before: dict[str, Any], after: dict[str, Any]) -> dict[str, Any]:
    b, a = _quality(before), _quality(after)
    report = {}
    for key in b:
        passed = a[key] + 1e-9 >= b[key]
        report[key] = {
            "baseline": b[key], "candidate": a[key],
            "delta": round(a[key] - b[key], 6), "passed": passed,
        }
        if not passed:
            raise EfficiencyEvaluatorHandoffError(f"fixed-task quality regression: {key}")
    return report


def _observation(path: Path, ref: str):
    payload = _json(path)
    try:
        validate_observation_receipt(payload, expected_source_ref=ref, require_complete=True)
    except ValueError as exc:
        raise EfficiencyEvaluatorHandoffError(str(exc)) from exc
    s = payload.get("structured_output_concurrency")
    b = payload.get("execution_budget_concurrency")
    r = payload.get("prefix_reuse_trust_isolation")
    u = payload.get("inference_usage")
    if not all(isinstance(x, dict) for x in (s, b, r, u)):
        raise EfficiencyEvaluatorHandoffError("concurrency receipt sections are incomplete")
    attempted = s.get("attempted")
    structured = (
        s.get("passed") is True and isinstance(attempted, int) and not isinstance(attempted, bool)
        and attempted >= 2 and s.get("succeeded") == attempted
        and s.get("semantic_match_count") == attempted
        and s.get("concurrency_observed") is True
        and isinstance(s.get("max_in_flight_observed"), int)
        and s.get("max_in_flight_observed") >= 2
        and u.get("event_count") == attempted
        and u.get("successful_event_count") == attempted
    )
    budget = b.get("passed") is True
    reuse = (
        r.get("passed") is True
        and r.get("cross_domain_reuse_candidate") is False
        and r.get("same_domain_repeat_reuse_candidate") is True
        and r.get("backend_cache_hit_claim_present") is False
        and r.get("backend_cache_isolation_measured") is False
    )
    if not structured or not budget or not reuse:
        raise EfficiencyEvaluatorHandoffError("concurrency receipt PASS cannot be re-derived")
    return payload, {
        "structured_output_non_regression_observed": True,
        "execution_budget_concurrency_observed": True,
        "workspace_reuse_opportunity_isolation_observed": True,
        "backend_cache_isolation_measured": False,
        "backend_cache_hit_claimed": False,
    }


def _resource(path: Path, ref: str):
    payload = _json(path)
    try:
        validate_resource_receipt(payload, expected_source_ref=ref, require_complete=True)
    except ValueError as exc:
        raise EfficiencyEvaluatorHandoffError(str(exc)) from exc
    claims = payload.get("claims")
    if not isinstance(claims, dict) or claims.get("resource_benefit_measured") is not True:
        raise EfficiencyEvaluatorHandoffError("resource benefit measurement is incomplete")
    for key in (
        "gpu_active_time_measured", "backend_cache_isolation_measured",
        "backend_cache_hit_claimed", "evaluator_attested", "promotion_evidence_emitted",
    ):
        if claims.get(key) is not False:
            raise EfficiencyEvaluatorHandoffError(f"resource receipt cannot claim {key}")
    return payload


def _model(payload: dict[str, Any]) -> str:
    env = payload.get("environment")
    if not isinstance(env, dict) or not str(env.get("model") or "").strip():
        raise EfficiencyEvaluatorHandoffError("measurement model metadata is missing")
    return str(env["model"]).strip()


def _cross(b_obs, c_obs, b_res, c_res):
    models = [_model(x) for x in (b_obs, c_obs, b_res, c_res)]
    if len(set(models)) != 1:
        raise EfficiencyEvaluatorHandoffError("all measurements must use the same model")
    be, ce = b_res.get("experiment"), c_res.get("experiment")
    if not isinstance(be, dict) or be != ce:
        raise EfficiencyEvaluatorHandoffError("baseline/candidate resource experiments must be identical")
    for label, obs in (("baseline", b_obs), ("candidate", c_obs)):
        s = obs.get("structured_output_concurrency")
        if not isinstance(s, dict):
            raise EfficiencyEvaluatorHandoffError(f"{label} structured observation missing")
        if s.get("attempted") != be.get("samples_per_mode"):
            raise EfficiencyEvaluatorHandoffError(f"{label} sample count mismatch")
        if s.get("concurrency_requested") != be.get("candidate_concurrency"):
            raise EfficiencyEvaluatorHandoffError(f"{label} concurrency mismatch")
    return {
        "model": models[0],
        "samples_per_mode": be.get("samples_per_mode"),
        "candidate_concurrency": be.get("candidate_concurrency"),
        "same_model": True,
        "same_experiment": True,
    }


def build_handoff(
    profile: EvaluationProfile, *, baseline_ref: str, candidate_ref: str,
    baseline_benchmark: Path, candidate_benchmark: Path,
    baseline_observation: Path, candidate_observation: Path,
    baseline_resource: Path, candidate_resource: Path,
) -> dict[str, Any]:
    profile.validate()
    if profile.profile_id != PROFILE or profile.corpus_class != "efficiency_cache_concurrency":
        raise EfficiencyEvaluatorHandoffError("D7-06 supports only the current efficiency profile")
    if profile.holdout_labels_external is not False:
        raise EfficiencyEvaluatorHandoffError("efficiency profile must not use holdout labels")
    base, cand = _git(baseline_ref, "baseline_ref"), _git(candidate_ref, "candidate_ref")
    if base == cand:
        raise EfficiencyEvaluatorHandoffError("candidate_ref must differ from baseline_ref")

    bm, bl, bb = _benchmark(baseline_benchmark, base)
    cm, cl, cb = _benchmark(candidate_benchmark, cand)
    if bl["task_scope_sha256"] != cl["task_scope_sha256"]:
        raise EfficiencyEvaluatorHandoffError("benchmark task scopes must match exactly")
    quality = _quality_gate(bm, cm)

    bo, bop = _observation(baseline_observation, base)
    co, cop = _observation(candidate_observation, cand)
    br, cr = _resource(baseline_resource, base), _resource(candidate_resource, cand)
    experiment = _cross(bo, co, br, cr)

    bindings = {
        "baseline_benchmark": bb["manifest_sha256"],
        "candidate_benchmark": cb["manifest_sha256"],
        "baseline_observation": _hash(bo.get("observation_sha256"), "baseline_observation"),
        "candidate_observation": _hash(co.get("observation_sha256"), "candidate_observation"),
        "baseline_resource_benefit": _hash(br.get("observation_sha256"), "baseline_resource"),
        "candidate_resource_benefit": _hash(cr.get("observation_sha256"), "candidate_resource"),
    }
    payload = {
        "schema_version": SCHEMA,
        "profile_id": profile.profile_id,
        "profile_sha256": profile.sha256,
        "corpus_class": profile.corpus_class,
        "metric_registry_id": METRIC_REGISTRY_ID,
        "metric_registry_sha256": DEFAULT_METRIC_REGISTRY.sha256,
        "baseline_ref": base,
        "candidate_ref": cand,
        "external_result_schema": PROFILE_RESULT_SCHEMA,
        "evidence_bindings": bindings,
        "benchmark_lineage": {
            "task_scope_sha256": bl["task_scope_sha256"],
            "baseline_configuration_sha256": bb["configuration_sha256"],
            "candidate_configuration_sha256": cb["configuration_sha256"],
            "baseline_metrics_sha256": bb["metrics_sha256"],
            "candidate_metrics_sha256": cb["metrics_sha256"],
        },
        "deterministic_prechecks": {
            "fixed_task_quality": quality,
            "baseline_observation": bop,
            "candidate_observation": cop,
            "resource_measurements_complete": True,
            "backend_cache_isolation_measured": False,
            "backend_cache_hit_claimed": False,
        },
        "experiment": experiment,
        "requirements": dict(REQUIREMENTS),
        "cases": [{
            "case_id": case.case_id,
            "required_checks": list(case.required_checks),
            "required_local_bindings": list(CASE_BINDINGS.get(case.case_id, ())),
            "external_independent_evidence_required": case.case_id == "cache-trust-domain-isolation",
        } for case in profile.cases],
    }
    payload["handoff_sha256"] = canonical_hash(payload)
    return validate_handoff(payload, profile=profile)


def validate_handoff(payload: Any, *, profile: EvaluationProfile) -> dict[str, Any]:
    keys = {
        "schema_version", "profile_id", "profile_sha256", "corpus_class",
        "metric_registry_id", "metric_registry_sha256", "baseline_ref", "candidate_ref",
        "external_result_schema", "evidence_bindings", "benchmark_lineage",
        "deterministic_prechecks", "experiment", "requirements", "cases", "handoff_sha256",
    }
    if not isinstance(payload, dict) or set(payload) != keys:
        raise EfficiencyEvaluatorHandoffError("handoff contains unsupported or missing fields")
    profile.validate()
    if payload.get("schema_version") != SCHEMA:
        raise EfficiencyEvaluatorHandoffError("handoff schema mismatch")
    if profile.profile_id != PROFILE or payload.get("profile_id") != profile.profile_id:
        raise EfficiencyEvaluatorHandoffError("handoff profile mismatch")
    if payload.get("profile_sha256") != profile.sha256:
        raise EfficiencyEvaluatorHandoffError("handoff profile fingerprint mismatch")
    if payload.get("corpus_class") != "efficiency_cache_concurrency":
        raise EfficiencyEvaluatorHandoffError("handoff corpus_class mismatch")
    if payload.get("metric_registry_id") != METRIC_REGISTRY_ID or payload.get("metric_registry_sha256") != DEFAULT_METRIC_REGISTRY.sha256:
        raise EfficiencyEvaluatorHandoffError("handoff metric registry mismatch")
    if _git(payload.get("baseline_ref"), "baseline_ref") == _git(payload.get("candidate_ref"), "candidate_ref"):
        raise EfficiencyEvaluatorHandoffError("candidate_ref must differ from baseline_ref")
    if payload.get("external_result_schema") != PROFILE_RESULT_SCHEMA or payload.get("requirements") != REQUIREMENTS:
        raise EfficiencyEvaluatorHandoffError("handoff evaluator contract mismatch")

    bindings = payload.get("evidence_bindings")
    expected_bindings = {
        "baseline_benchmark", "candidate_benchmark", "baseline_observation",
        "candidate_observation", "baseline_resource_benefit", "candidate_resource_benefit",
    }
    if not isinstance(bindings, dict) or set(bindings) != expected_bindings:
        raise EfficiencyEvaluatorHandoffError("handoff evidence bindings invalid")
    for key, value in bindings.items():
        _hash(value, f"evidence_bindings.{key}")

    lineage = payload.get("benchmark_lineage")
    if not isinstance(lineage, dict) or set(lineage) != {
        "task_scope_sha256", "baseline_configuration_sha256",
        "candidate_configuration_sha256", "baseline_metrics_sha256", "candidate_metrics_sha256",
    }:
        raise EfficiencyEvaluatorHandoffError("benchmark lineage invalid")
    for key, value in lineage.items():
        _hash(value, f"benchmark_lineage.{key}")

    pre = payload.get("deterministic_prechecks")
    if not isinstance(pre, dict) or set(pre) != {
        "fixed_task_quality", "baseline_observation", "candidate_observation",
        "resource_measurements_complete", "backend_cache_isolation_measured",
        "backend_cache_hit_claimed",
    }:
        raise EfficiencyEvaluatorHandoffError("deterministic prechecks invalid")
    quality = pre.get("fixed_task_quality")
    if not isinstance(quality, dict) or set(quality) != {
        "verified_task_success_rate", "first_pass_verified_success_rate",
        "verified_tasks", "evidence_coverage",
    } or any(not isinstance(row, dict) or row.get("passed") is not True for row in quality.values()):
        raise EfficiencyEvaluatorHandoffError("fixed-task quality prechecks invalid")
    expected_obs = {
        "structured_output_non_regression_observed": True,
        "execution_budget_concurrency_observed": True,
        "workspace_reuse_opportunity_isolation_observed": True,
        "backend_cache_isolation_measured": False,
        "backend_cache_hit_claimed": False,
    }
    if pre.get("baseline_observation") != expected_obs or pre.get("candidate_observation") != expected_obs:
        raise EfficiencyEvaluatorHandoffError("concurrency prechecks invalid")
    if pre.get("resource_measurements_complete") is not True:
        raise EfficiencyEvaluatorHandoffError("resource measurements incomplete")
    if pre.get("backend_cache_isolation_measured") is not False:
        raise EfficiencyEvaluatorHandoffError("local evidence cannot claim backend cache isolation")
    if pre.get("backend_cache_hit_claimed") is not False:
        raise EfficiencyEvaluatorHandoffError("local evidence cannot claim backend cache hit")
    exp = payload.get("experiment")
    if not isinstance(exp, dict) or exp.get("same_model") is not True or exp.get("same_experiment") is not True:
        raise EfficiencyEvaluatorHandoffError("experiment binding invalid")

    actual = payload.get("cases")
    if not isinstance(actual, list) or len(actual) != len(profile.cases):
        raise EfficiencyEvaluatorHandoffError("handoff case set invalid")
    specs = {case.case_id: case for case in profile.cases}
    seen = set()
    for row in actual:
        if not isinstance(row, dict) or set(row) != {
            "case_id", "required_checks", "required_local_bindings",
            "external_independent_evidence_required",
        }:
            raise EfficiencyEvaluatorHandoffError("handoff case fields invalid")
        case_id = row.get("case_id")
        if case_id in seen or case_id not in specs:
            raise EfficiencyEvaluatorHandoffError("handoff case set mismatch")
        seen.add(case_id)
        if row.get("required_checks") != list(specs[case_id].required_checks):
            raise EfficiencyEvaluatorHandoffError("handoff required checks mismatch")
        if row.get("required_local_bindings") != list(CASE_BINDINGS.get(case_id, ())):
            raise EfficiencyEvaluatorHandoffError("handoff local binding policy mismatch")
        if row.get("external_independent_evidence_required") is not (case_id == "cache-trust-domain-isolation"):
            raise EfficiencyEvaluatorHandoffError("handoff external evidence policy mismatch")

    claim = _hash(payload.get("handoff_sha256"), "handoff_sha256")
    unsigned = dict(payload)
    unsigned.pop("handoff_sha256")
    if canonical_hash(unsigned) != claim:
        raise EfficiencyEvaluatorHandoffError("handoff fingerprint mismatch")
    return payload


def validate_external_result(
    profile: EvaluationProfile,
    handoff: dict[str, Any],
    result: EvaluationProfileResult,
) -> EvaluationProfileResult:
    validate_handoff(handoff, profile=profile)
    result.validate()
    for field in ("profile_id", "profile_sha256", "corpus_class", "metric_registry_id",
                  "metric_registry_sha256", "baseline_ref", "candidate_ref"):
        if getattr(result, field) != handoff[field]:
            raise EvaluationProfileError(f"external result {field} does not match D7-06 handoff")
    if result.evaluator_attested is not True or result.security_passed is not True:
        raise EvaluationProfileError("external evaluator security/attestation is required")
    if result.label_commitment_sha256 is not None:
        raise EvaluationProfileError("efficiency result must not attach holdout label commitment")

    specs = {case.case_id: case for case in profile.cases}
    rows = {case.case_id: case for case in result.cases}
    if set(rows) != set(specs):
        raise EvaluationProfileError("external result case set must exactly match D7-06 profile")
    local = set(handoff["evidence_bindings"].values())
    for case_id, spec in specs.items():
        row = rows[case_id]
        if set(row.checks) != set(spec.required_checks) or any(
            row.checks.get(check) is not True for check in spec.required_checks
        ):
            raise EvaluationProfileError(f"external result required checks invalid: {case_id}")
        required = {handoff["handoff_sha256"]}
        required.update(handoff["evidence_bindings"][key] for key in CASE_BINDINGS.get(case_id, ()))
        if not required.issubset(set(row.evidence_refs)):
            raise EvaluationProfileError(f"external result missing bound evidence: {case_id}")
        if case_id == "cache-trust-domain-isolation":
            independent = [
                ref for ref in row.evidence_refs
                if ref not in local and ref not in {handoff["handoff_sha256"], result.evaluator_ref}
            ]
            if not independent:
                raise EvaluationProfileError("backend cache isolation requires independent external evidence")
    return result


def _write(path: Path, payload: dict[str, Any], force: bool):
    if path.exists() and not force:
        raise FileExistsError(f"output already exists: {path}")
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="workspace-eval-efficiency-handoff",
        description="Bind exact D7-06 evidence for an independent evaluator; never emits promotion evidence.",
    )
    sub = p.add_subparsers(dest="command", required=True)
    c = sub.add_parser("create")
    for name in (
        "profile", "baseline-ref", "candidate-ref", "baseline-benchmark",
        "candidate-benchmark", "baseline-observation", "candidate-observation",
        "baseline-resource", "candidate-resource", "output",
    ):
        c.add_argument("--" + name, required=True)
    c.add_argument("--force", action="store_true")
    v = sub.add_parser("validate-result")
    for name in ("profile", "handoff", "result"):
        v.add_argument("--" + name, required=True)
    return p


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        profile = EvaluationProfile.load(Path(args.profile))
        if args.command == "create":
            payload = build_handoff(
                profile,
                baseline_ref=args.baseline_ref, candidate_ref=args.candidate_ref,
                baseline_benchmark=Path(args.baseline_benchmark),
                candidate_benchmark=Path(args.candidate_benchmark),
                baseline_observation=Path(args.baseline_observation),
                candidate_observation=Path(args.candidate_observation),
                baseline_resource=Path(args.baseline_resource),
                candidate_resource=Path(args.candidate_resource),
            )
            _write(Path(args.output), payload, args.force)
            print(json.dumps(payload, ensure_ascii=False, indent=2))
            return 0
        handoff = validate_handoff(_json(Path(args.handoff)), profile=profile)
        result = EvaluationProfileResult.load(Path(args.result))
        validate_external_result(profile, handoff, result)
        print(json.dumps({
            "schema_version": SCHEMA, "accepted_for_profile_adapter": True,
            "profile_id": profile.profile_id, "profile_sha256": profile.sha256,
            "baseline_ref": handoff["baseline_ref"], "candidate_ref": handoff["candidate_ref"],
            "handoff_sha256": handoff["handoff_sha256"], "next_adapter": "workspace-eval-profile",
        }, ensure_ascii=False, indent=2))
        return 0
    except (OSError, json.JSONDecodeError, EfficiencyEvaluatorHandoffError,
            EvaluationProfileError, FileExistsError, ValueError) as exc:
        print(json.dumps({
            "schema_version": SCHEMA, "accepted_for_profile_adapter": False,
            "error": f"{type(exc).__name__}: {exc}",
        }, ensure_ascii=False, indent=2))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
