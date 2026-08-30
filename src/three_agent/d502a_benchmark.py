from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .benchmark_isolation import BENCHMARK_ISOLATION_SCHEMA, BenchmarkVariantSpec
from .benchmark_snapshot import unpack_metrics_payload
from .benchmark_suite import (
    SUITE_SCHEMA,
    FixedBenchmarkTaskSet,
    FixedTaskBenchmarkSuite,
    VariantExecution,
)
from .config import load_config
from .evidence_packing import LEGACY_PACKING_MODE
from .optimization_gate import OptimizationAcceptanceGate, OptimizationGateError


D502A_DECISION_SCHEMA = "workspace-d502a-benchmark-decision/v1"
D502A_VERIFICATION_SCHEMA = "workspace-d502a-benchmark-verification/v1"
D502A_PROFILE_ID = "d502a-exact-body-dedupe-v1"
D502A_TASK_SET = "benchmarks/d502a_exact_body_dedupe_task_set_v1.json"
D502A_MIRROR_A = "benchmarks/fixtures/d502a_exact_mirror_a.md"
D502A_MIRROR_B = "benchmarks/fixtures/d502a_exact_mirror_b.md"
D502A_BASELINE_LABEL = "baseline-legacy-48k"
D502A_CANDIDATE_LABEL = "exact-dedupe-legacy-48k"
_SOURCE_REF_RE = re.compile(r"^[0-9a-f]{40}$")

D502A_VARIANTS = (
    BenchmarkVariantSpec(
        D502A_BASELINE_LABEL,
        evidence_packing_mode=LEGACY_PACKING_MODE,
        synthesis_context_budget_chars=48000,
        exact_body_dedupe=False,
    ),
    BenchmarkVariantSpec(
        D502A_CANDIDATE_LABEL,
        evidence_packing_mode=LEGACY_PACKING_MODE,
        synthesis_context_budget_chars=48000,
        exact_body_dedupe=True,
    ),
)


class D502ABenchmarkError(ValueError):
    """D5-02a representative benchmark evidence is incomplete or inconsistent."""


def _load_json(path: Path) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise D502ABenchmarkError(f"JSON_OBJECT_REQUIRED:{path}")
    return payload


def _write_json(path: Path, payload: dict[str, Any]) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    temporary.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    temporary.replace(destination)


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _source_ref(value: str) -> str:
    source = str(value or "").strip().lower()
    if not _SOURCE_REF_RE.fullmatch(source):
        raise D502ABenchmarkError("SOURCE_REF_INVALID")
    return source


def _mirror_fixture_sha256(task_set: FixedBenchmarkTaskSet, repo_root: Path) -> str:
    root = Path(repo_root).expanduser().resolve()
    first = (root / D502A_MIRROR_A).resolve()
    second = (root / D502A_MIRROR_B).resolve()
    if not first.is_relative_to(root) or not second.is_relative_to(root):
        raise D502ABenchmarkError("MIRROR_FIXTURE_PATH_INVALID")
    if not first.is_file() or not second.is_file():
        raise D502ABenchmarkError("MIRROR_FIXTURE_MISSING")
    left = first.read_bytes()
    right = second.read_bytes()
    if left != right:
        raise D502ABenchmarkError("MIRROR_FIXTURE_BYTES_DIFFER")
    if len(left) < 1024:
        raise D502ABenchmarkError("MIRROR_FIXTURE_TOO_SMALL_FOR_REPRESENTATIVE_MEASUREMENT")
    for case in task_set.cases:
        fixtures = set(case.fixtures)
        if D502A_MIRROR_A not in fixtures or D502A_MIRROR_B not in fixtures:
            raise D502ABenchmarkError(
                f"MIRROR_PAIR_NOT_PRESENT_IN_CASE:{case.case_id}"
            )
    return "sha256:" + hashlib.sha256(left).hexdigest()


def _quality_checks_passed(report: dict[str, Any]) -> bool:
    checks = report.get("quality_checks")
    return isinstance(checks, dict) and bool(checks) and all(
        isinstance(value, dict) and value.get("passed") is True
        for value in checks.values()
    )


def _recomputed_comparison(
    baseline: VariantExecution,
    candidate: VariantExecution,
    baseline_manifest: dict[str, Any],
    candidate_manifest: dict[str, Any],
) -> dict[str, Any]:
    validator = FixedTaskBenchmarkSuite._validator_gate(baseline, candidate)
    try:
        optimization = OptimizationAcceptanceGate().evaluate(
            baseline_manifest,
            candidate_manifest,
        )
    except (OptimizationGateError, ValueError) as exc:
        raise D502ABenchmarkError("OPTIMIZATION_RECOMPUTE_FAILED") from exc
    quality_preserved = validator["passed"] and _quality_checks_passed(optimization)
    efficiency_evaluated = bool(quality_preserved)
    accepted = bool(quality_preserved and optimization.get("accepted") is True)
    latency = None
    if efficiency_evaluated:
        before = baseline.elapsed_ms
        after = candidate.elapsed_ms
        latency = {
            "baseline_elapsed_ms": before,
            "candidate_elapsed_ms": after,
            "delta_ms": after - before,
            "change_pct": (
                0.0
                if before == 0 and after == 0
                else None
                if before == 0
                else round(((after - before) / before) * 100.0, 6)
            ),
        }
    return {
        "schema_version": "workspace-fixed-benchmark-comparison/v1",
        "quality_preserved": quality_preserved,
        "required_validator_acceptance": validator,
        "optimization_acceptance": optimization,
        "efficiency_evaluated": efficiency_evaluated,
        "latency": latency,
        "promotion_eligible": accepted,
    }


def _decision(
    *,
    source_ref: str,
    task_set: FixedBenchmarkTaskSet,
    mirror_sha256: str,
    comparison: dict[str, Any],
) -> dict[str, Any]:
    optimization = comparison.get("optimization_acceptance")
    if not isinstance(optimization, dict):
        raise D502ABenchmarkError("OPTIMIZATION_REPORT_MISSING")
    token = optimization.get("token_efficiency")
    if not isinstance(token, dict):
        raise D502ABenchmarkError("TOKEN_EFFICIENCY_REPORT_MISSING")
    reduction_raw = token.get("reduction_pct")
    if isinstance(reduction_raw, bool) or not isinstance(reduction_raw, (int, float)):
        raise D502ABenchmarkError("TOKEN_REDUCTION_INVALID")
    reduction = float(reduction_raw)
    measurable = reduction > 0.0
    validator = comparison.get("required_validator_acceptance")
    validator_passed = isinstance(validator, dict) and validator.get("passed") is True
    quality_preserved = comparison.get("quality_preserved") is True
    generic_accepted = optimization.get("accepted") is True
    promotion_eligible = bool(
        validator_passed and quality_preserved and generic_accepted and measurable
    )

    failures: list[str] = []
    for value in optimization.get("failures") or []:
        text = str(value or "").strip()
        if text and text not in failures:
            failures.append(text)
    if isinstance(validator, dict):
        for value in validator.get("failures") or []:
            text = str(value or "").strip()
            if text and text not in failures:
                failures.append(text)
    if not measurable:
        failures.append("D502A_MEASURABLE_TOKEN_BENEFIT_MISSING")

    return {
        "schema_version": D502A_DECISION_SCHEMA,
        "profile_id": D502A_PROFILE_ID,
        "source_ref": source_ref,
        "task_set_id": task_set.task_set_id,
        "task_set_sha256": task_set.sha256,
        "mirror_fixture_sha256": mirror_sha256,
        "baseline_label": D502A_BASELINE_LABEL,
        "candidate_label": D502A_CANDIDATE_LABEL,
        "baseline_exact_body_dedupe": False,
        "candidate_exact_body_dedupe": True,
        "quality_preserved": quality_preserved,
        "required_validators_passed": validator_passed,
        "optimization_gate_accepted": generic_accepted,
        "token_reduction_pct": reduction,
        "measurable_token_benefit": measurable,
        "promotion_eligible": promotion_eligible,
        "failures": failures,
        "raw_prompt_logged": False,
        "raw_evidence_logged": False,
    }


def _canonicalize_manifest_paths(root: Path, suite: dict[str, Any]) -> dict[str, Any]:
    variants = suite.get("variants")
    expected = {spec.label for spec in D502A_VARIANTS}
    if not isinstance(variants, dict) or set(variants) != expected:
        raise D502ABenchmarkError("VARIANT_SET_MISMATCH")
    for label in sorted(expected):
        row = variants.get(label)
        if not isinstance(row, dict):
            raise D502ABenchmarkError("VARIANT_ROW_INVALID")
        supplied = Path(str(row.get("manifest_path") or ""))
        expected_file = (root / label / "benchmark.json").resolve()
        resolved = supplied.resolve() if supplied.is_absolute() else (root / supplied).resolve()
        if resolved != expected_file or not expected_file.is_file():
            raise D502ABenchmarkError("MANIFEST_PATH_OUTSIDE_EXPECTED_FILE")
        row["manifest_path"] = f"{label}/benchmark.json"
    _write_json(root / "suite.json", suite)
    return suite


def run_d502a_benchmark(
    *,
    root: Path,
    repo_root: Path,
    task_set_path: Path,
    source_ref: str,
    config_path: str | None = None,
) -> dict[str, Any]:
    source = _source_ref(source_ref)
    output_root = Path(root).expanduser().resolve()
    repository = Path(repo_root).expanduser().resolve()
    task_set = FixedBenchmarkTaskSet.load(task_set_path)
    mirror_sha = _mirror_fixture_sha256(task_set, repository)
    suite = FixedTaskBenchmarkSuite(
        load_config(config_path),
        output_root,
        repository,
        variants=D502A_VARIANTS,
    ).run(task_set_path, source_ref=source)
    suite = _canonicalize_manifest_paths(output_root, suite)
    comparison = suite.get("comparisons", {}).get(D502A_CANDIDATE_LABEL)
    if not isinstance(comparison, dict):
        raise D502ABenchmarkError("D502A_COMPARISON_MISSING")
    decision = _decision(
        source_ref=source,
        task_set=task_set,
        mirror_sha256=mirror_sha,
        comparison=comparison,
    )
    _write_json(output_root / "d502a-decision.json", decision)
    return decision


def _load_variant_execution(
    root: Path,
    suite: dict[str, Any],
    spec: BenchmarkVariantSpec,
    *,
    source_ref: str,
    expected_case_ids: tuple[str, ...],
) -> tuple[VariantExecution, dict[str, Any], str]:
    variants = suite.get("variants")
    if not isinstance(variants, dict):
        raise D502ABenchmarkError("VARIANTS_MISSING")
    row = variants.get(spec.label)
    if not isinstance(row, dict):
        raise D502ABenchmarkError(f"VARIANT_MISSING:{spec.label}")
    if row.get("packing_mode") != spec.evidence_packing_mode:
        raise D502ABenchmarkError(f"PACKING_MODE_MISMATCH:{spec.label}")
    if row.get("context_budget_chars") != spec.synthesis_context_budget_chars:
        raise D502ABenchmarkError(f"CONTEXT_BUDGET_MISMATCH:{spec.label}")
    expected_manifest = f"{spec.label}/benchmark.json"
    if str(row.get("manifest_path") or "").replace("\\", "/") != expected_manifest:
        raise D502ABenchmarkError(f"MANIFEST_PATH_NOT_CANONICAL:{spec.label}")

    isolation = _load_json(root / spec.label / "isolation.json")
    if isolation.get("schema_version") != BENCHMARK_ISOLATION_SCHEMA:
        raise D502ABenchmarkError(f"ISOLATION_SCHEMA_INVALID:{spec.label}")
    if isolation.get("variant_label") != spec.label:
        raise D502ABenchmarkError(f"ISOLATION_LABEL_MISMATCH:{spec.label}")
    if isolation.get("evidence_packing") != spec.policy().to_fingerprint_dict():
        raise D502ABenchmarkError(f"ISOLATION_POLICY_MISMATCH:{spec.label}")
    storage = isolation.get("storage")
    if not isinstance(storage, dict) or not storage or any(value is not True for value in storage.values()):
        raise D502ABenchmarkError(f"ISOLATION_STORAGE_INVALID:{spec.label}")
    if isolation.get("raw_prompt_logged") is not False or isolation.get("raw_evidence_logged") is not False:
        raise D502ABenchmarkError(f"ISOLATION_RAW_CONTENT_POLICY_INVALID:{spec.label}")

    manifest = _load_json(root / spec.label / "benchmark.json")
    metrics, lineage = unpack_metrics_payload(manifest)
    if lineage is None or lineage.get("source_ref") != source_ref:
        raise D502ABenchmarkError(f"MANIFEST_LINEAGE_INVALID:{spec.label}")
    if row.get("configuration_sha256") != lineage.get("configuration_sha256"):
        raise D502ABenchmarkError(f"CONFIGURATION_FINGERPRINT_MISMATCH:{spec.label}")
    if row.get("metrics_sha256") != lineage.get("metrics_sha256"):
        raise D502ABenchmarkError(f"METRICS_FINGERPRINT_MISMATCH:{spec.label}")

    cases = row.get("cases")
    if not isinstance(cases, list) or len(cases) != len(expected_case_ids):
        raise D502ABenchmarkError(f"CASE_SET_INVALID:{spec.label}")
    if tuple(str(item.get("case_id") or "") for item in cases if isinstance(item, dict)) != expected_case_ids:
        raise D502ABenchmarkError(f"CASE_ORDER_INVALID:{spec.label}")
    elapsed = row.get("elapsed_ms")
    if isinstance(elapsed, bool) or not isinstance(elapsed, int) or elapsed < 0:
        raise D502ABenchmarkError(f"ELAPSED_INVALID:{spec.label}")
    corpus = str(row.get("corpus_sha256") or "")
    if not corpus.startswith("sha256:"):
        raise D502ABenchmarkError(f"CORPUS_FINGERPRINT_INVALID:{spec.label}")
    return (
        VariantExecution(
            metrics=metrics,
            cases=tuple(dict(item) for item in cases),
            elapsed_ms=elapsed,
            corpus_sha256=corpus,
        ),
        manifest,
        lineage["configuration_sha256"],
    )


def verify_d502a_benchmark(
    *,
    root: Path,
    repo_root: Path,
    task_set_path: Path,
    source_ref: str,
) -> dict[str, Any]:
    source = _source_ref(source_ref)
    output_root = Path(root).expanduser().resolve()
    repository = Path(repo_root).expanduser().resolve()
    task_set = FixedBenchmarkTaskSet.load(task_set_path)
    mirror_sha = _mirror_fixture_sha256(task_set, repository)
    suite = _load_json(output_root / "suite.json")
    if suite.get("schema_version") != SUITE_SCHEMA or suite.get("source_ref") != source:
        raise D502ABenchmarkError("SUITE_LINEAGE_INVALID")
    task_info = suite.get("task_set")
    if not isinstance(task_info, dict):
        raise D502ABenchmarkError("SUITE_TASK_SET_INVALID")
    if task_info.get("task_set_id") != task_set.task_set_id or task_info.get("task_set_sha256") != task_set.sha256:
        raise D502ABenchmarkError("TASK_SET_FINGERPRINT_MISMATCH")
    expected_case_ids = tuple(case.case_id for case in task_set.cases)
    if tuple(task_info.get("case_ids") or ()) != expected_case_ids:
        raise D502ABenchmarkError("TASK_SET_CASES_MISMATCH")
    if task_info.get("raw_task_text_embedded_in_suite") is not False:
        raise D502ABenchmarkError("SUITE_RAW_TASK_TEXT_POLICY_INVALID")

    variants = suite.get("variants")
    expected_labels = {spec.label for spec in D502A_VARIANTS}
    if not isinstance(variants, dict) or set(variants) != expected_labels:
        raise D502ABenchmarkError("VARIANT_SET_MISMATCH")
    comparisons = suite.get("comparisons")
    if not isinstance(comparisons, dict) or set(comparisons) != {D502A_CANDIDATE_LABEL}:
        raise D502ABenchmarkError("COMPARISON_SET_MISMATCH")

    baseline, baseline_manifest, baseline_config = _load_variant_execution(
        output_root,
        suite,
        D502A_VARIANTS[0],
        source_ref=source,
        expected_case_ids=expected_case_ids,
    )
    candidate, candidate_manifest, candidate_config = _load_variant_execution(
        output_root,
        suite,
        D502A_VARIANTS[1],
        source_ref=source,
        expected_case_ids=expected_case_ids,
    )
    if baseline.corpus_sha256 != candidate.corpus_sha256:
        raise D502ABenchmarkError("FIXTURE_CORPUS_CHANGED_BETWEEN_VARIANTS")
    baseline_task_ids = tuple(str(item.get("task_id") or "") for item in baseline.cases)
    candidate_task_ids = tuple(str(item.get("task_id") or "") for item in candidate.cases)
    if baseline_task_ids != candidate_task_ids:
        raise D502ABenchmarkError("TASK_SCOPE_CHANGED_BETWEEN_VARIANTS")
    if baseline_config == candidate_config:
        raise D502ABenchmarkError("DEDUPE_CONFIGURATION_NOT_FINGERPRINTED")

    recomputed = _recomputed_comparison(
        baseline,
        candidate,
        baseline_manifest,
        candidate_manifest,
    )
    if comparisons[D502A_CANDIDATE_LABEL] != recomputed:
        raise D502ABenchmarkError("COMPARISON_RECOMPUTE_MISMATCH")
    expected_decision = _decision(
        source_ref=source,
        task_set=task_set,
        mirror_sha256=mirror_sha,
        comparison=recomputed,
    )
    persisted_decision = _load_json(output_root / "d502a-decision.json")
    if persisted_decision != expected_decision:
        raise D502ABenchmarkError("D502A_DECISION_RECOMPUTE_MISMATCH")

    verification = {
        "schema_version": D502A_VERIFICATION_SCHEMA,
        "completed": True,
        "profile_id": D502A_PROFILE_ID,
        "source_ref": source,
        "task_set_sha256": task_set.sha256,
        "mirror_fixture_sha256": mirror_sha,
        "suite_sha256": _file_sha256(output_root / "suite.json"),
        "decision_sha256": _file_sha256(output_root / "d502a-decision.json"),
        "baseline_manifest_sha256": _file_sha256(
            output_root / D502A_BASELINE_LABEL / "benchmark.json"
        ),
        "candidate_manifest_sha256": _file_sha256(
            output_root / D502A_CANDIDATE_LABEL / "benchmark.json"
        ),
        "promotion_eligible": expected_decision["promotion_eligible"],
        "token_reduction_pct": expected_decision["token_reduction_pct"],
        "raw_prompt_logged": False,
        "raw_evidence_logged": False,
    }
    _write_json(output_root / "d502a-verification.json", verification)
    return verification


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m three_agent.d502a_benchmark",
        description="Run or independently verify the D5-02a exact-body dedupe benchmark.",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("run", "verify"):
        command = sub.add_parser(name)
        command.add_argument("--root", required=True)
        command.add_argument("--source-ref", required=True)
        command.add_argument("--repo-root", default=".")
        command.add_argument("--task-set", default=D502A_TASK_SET)
        if name == "run":
            command.add_argument("--config")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "run":
            payload = run_d502a_benchmark(
                root=Path(args.root),
                repo_root=Path(args.repo_root),
                task_set_path=Path(args.task_set),
                source_ref=args.source_ref,
                config_path=args.config,
            )
        else:
            payload = verify_d502a_benchmark(
                root=Path(args.root),
                repo_root=Path(args.repo_root),
                task_set_path=Path(args.task_set),
                source_ref=args.source_ref,
            )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": (
                        D502A_VERIFICATION_SCHEMA
                        if args.command == "verify"
                        else D502A_DECISION_SCHEMA
                    ),
                    "completed": False,
                    "error": f"{type(exc).__name__}: {exc}",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
