from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path, PurePosixPath
from typing import Any

from .benchmark_isolation import BENCHMARK_ISOLATION_SCHEMA
from .benchmark_readiness import load_readiness_receipt
from .benchmark_snapshot import BENCHMARK_SCHEMA, unpack_metrics_payload
from .benchmark_suite import (
    DEFAULT_VARIANTS,
    SUITE_SCHEMA,
    BenchmarkSuiteError,
    FixedBenchmarkTaskSet,
    FixedTaskBenchmarkSuite,
    VariantExecution,
)
from .metric_registry import DEFAULT_METRIC_REGISTRY
from .optimization_gate import OptimizationAcceptanceGate, OptimizationGateError

VERIFICATION_SCHEMA = "workspace-benchmark-evidence-verification/v1"
_VARIANT_SCHEMA = "workspace-fixed-benchmark-variant/v1"
_COMPARISON_SCHEMA = "workspace-fixed-benchmark-comparison/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SOURCE_REF_RE = re.compile(r"^[0-9a-f]{40}$")
_REASON_RE = re.compile(r"^[A-Z0-9][A-Z0-9_]{0,95}$")
_ALLOWED_FIXTURE_SUFFIXES = {".txt", ".md", ".markdown", ".html", ".htm"}


class BenchmarkEvidenceError(ValueError):
    """The benchmark artifact set cannot be independently trusted."""

    def __init__(self, reason_code: str):
        code = str(reason_code or "").strip().upper()
        if not _REASON_RE.fullmatch(code):
            code = "BENCHMARK_EVIDENCE_INVALID"
        self.reason_code = code
        super().__init__(code)


def _fail(code: str) -> None:
    raise BenchmarkEvidenceError(code)


def _require(condition: bool, code: str) -> None:
    if not condition:
        _fail(code)


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _file_sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _load_json(path: Path, missing_code: str, invalid_code: str) -> dict[str, Any]:
    source = Path(path)
    if not source.is_file():
        _fail(missing_code)
    try:
        payload = json.loads(source.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        _fail(invalid_code)
    if not isinstance(payload, dict):
        _fail(invalid_code)
    return payload


def _source_ref(value: str) -> str:
    source = str(value or "").strip().lower()
    if not _SOURCE_REF_RE.fullmatch(source):
        _fail("SOURCE_REF_INVALID")
    return source


def _sha(value: Any, code: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        _fail(code)
    return text


def _safe_relative_artifact_path(value: Any, expected: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    path = PurePosixPath(text)
    if not text or path.is_absolute() or ".." in path.parts or text != expected:
        _fail("MANIFEST_PATH_NOT_CANONICAL")
    return text


def _stable_upload_id(task_set_id: str, relative: str, data: bytes) -> str:
    seed = (
        task_set_id.encode("utf-8")
        + b"\0"
        + relative.encode("utf-8")
        + b"\0"
        + hashlib.sha256(data).digest()
    )
    return hashlib.sha256(seed).hexdigest()[:16]


def _expected_fixture_corpus(task_set: FixedBenchmarkTaskSet, repo_root: Path) -> str:
    root = Path(repo_root).expanduser().resolve()
    rows: list[dict[str, str]] = []
    ordered = list(dict.fromkeys(path for case in task_set.cases for path in case.fixtures))
    for relative in ordered:
        path = (root / relative).resolve()
        if (
            not path.is_relative_to(root)
            or not path.is_file()
            or path.suffix.casefold() not in _ALLOWED_FIXTURE_SUFFIXES
        ):
            _fail("FIXTURE_CORPUS_UNAVAILABLE")
        data = path.read_bytes()
        rows.append(
            {
                "path": relative,
                "content_sha256": "sha256:" + hashlib.sha256(data).hexdigest(),
                "upload_id": _stable_upload_id(task_set.task_set_id, relative, data),
            }
        )
    return _canonical_sha256(rows)


def _validate_case_rows(
    rows: Any,
    *,
    expected_case_ids: tuple[str, ...],
) -> tuple[dict[str, Any], ...]:
    if not isinstance(rows, list) or len(rows) != len(expected_case_ids):
        _fail("VARIANT_CASE_SET_INVALID")
    expected_keys = {
        "case_id",
        "task_id",
        "workflow_status",
        "task_status",
        "elapsed_ms",
        "contract_bound",
        "required_validators",
        "passed_validators",
        "failed_validators",
        "missing_validators",
        "verified",
        "first_pass_verified",
    }
    parsed: list[dict[str, Any]] = []
    for index, raw in enumerate(rows):
        if not isinstance(raw, dict) or set(raw) != expected_keys:
            _fail("VARIANT_CASE_ROW_INVALID")
        if str(raw.get("case_id") or "") != expected_case_ids[index]:
            _fail("VARIANT_CASE_ORDER_CHANGED")
        task_id = str(raw.get("task_id") or "").strip()
        if not task_id or len(task_id) > 128:
            _fail("VARIANT_TASK_ID_INVALID")
        elapsed = raw.get("elapsed_ms")
        if isinstance(elapsed, bool) or not isinstance(elapsed, int) or elapsed < 0:
            _fail("VARIANT_CASE_LATENCY_INVALID")
        for key in ("contract_bound", "verified", "first_pass_verified"):
            if not isinstance(raw.get(key), bool):
                _fail("VARIANT_CASE_BOOLEAN_INVALID")
        lists: dict[str, tuple[str, ...]] = {}
        for key in (
            "required_validators",
            "passed_validators",
            "failed_validators",
            "missing_validators",
        ):
            value = raw.get(key)
            if not isinstance(value, list) or any(
                not isinstance(item, str) or not item.strip() for item in value
            ):
                _fail("VARIANT_VALIDATOR_LIST_INVALID")
            normalized = tuple(item.strip() for item in value)
            if len(normalized) != len(set(normalized)):
                _fail("VARIANT_VALIDATOR_LIST_INVALID")
            lists[key] = normalized
        required = set(lists["required_validators"])
        passed = set(lists["passed_validators"])
        failed = set(lists["failed_validators"])
        missing = set(lists["missing_validators"])
        consistent_verified = (
            raw["contract_bound"]
            and not failed
            and not missing
            and required.issubset(passed)
        )
        if raw["verified"] != consistent_verified:
            _fail("VARIANT_VERIFICATION_STATE_INCONSISTENT")
        parsed.append(dict(raw))
    return tuple(parsed)


def _validate_isolation(payload: dict[str, Any], *, spec) -> None:
    expected_keys = {
        "schema_version",
        "variant_label",
        "evidence_packing",
        "storage",
        "raw_prompt_logged",
        "raw_evidence_logged",
    }
    _require(set(payload) == expected_keys, "ISOLATION_FIELDS_INVALID")
    _require(
        payload.get("schema_version") == BENCHMARK_ISOLATION_SCHEMA,
        "ISOLATION_SCHEMA_INVALID",
    )
    _require(payload.get("variant_label") == spec.label, "ISOLATION_VARIANT_MISMATCH")
    _require(
        payload.get("evidence_packing") == spec.policy().to_fingerprint_dict(),
        "ISOLATION_PACKING_POLICY_MISMATCH",
    )
    storage = payload.get("storage")
    required_storage = {
        "database_isolated",
        "artifacts_isolated",
        "inference_telemetry_isolated",
        "resource_telemetry_isolated",
        "internet_audit_isolated",
        "execution_audit_isolated",
    }
    _require(
        isinstance(storage, dict)
        and set(storage) == required_storage
        and all(value is True for value in storage.values()),
        "ISOLATION_STORAGE_BOUNDARY_INVALID",
    )
    _require(payload.get("raw_prompt_logged") is False, "ISOLATION_RAW_PROMPT_POLICY_INVALID")
    _require(payload.get("raw_evidence_logged") is False, "ISOLATION_RAW_EVIDENCE_POLICY_INVALID")


def _quality_checks_passed(report: dict[str, Any]) -> bool:
    checks = report.get("quality_checks")
    return isinstance(checks, dict) and bool(checks) and all(
        isinstance(value, dict) and value.get("passed") is True for value in checks.values()
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
            baseline_manifest, candidate_manifest
        )
    except (OptimizationGateError, ValueError):
        _fail("OPTIMIZATION_RECOMPUTE_FAILED")
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
        "schema_version": _COMPARISON_SCHEMA,
        "quality_preserved": quality_preserved,
        "required_validator_acceptance": validator,
        "optimization_acceptance": optimization,
        "efficiency_evaluated": efficiency_evaluated,
        "latency": latency,
        "promotion_eligible": accepted,
    }


class BenchmarkEvidenceVerifier:
    """Independently recompute trust-critical fixed benchmark artifact claims."""

    def __init__(self, artifact_root: Path, repo_root: Path):
        self.artifact_root = Path(artifact_root).expanduser().resolve()
        self.repo_root = Path(repo_root).expanduser().resolve()

    def verify(
        self,
        *,
        source_ref: str,
        task_set_path: Path,
    ) -> dict[str, Any]:
        source = _source_ref(source_ref)
        root = self.artifact_root
        if not root.is_dir():
            _fail("ARTIFACT_ROOT_MISSING")

        environment_path = root / "environment.json"
        suite_path = root / "suite.json"
        try:
            readiness = load_readiness_receipt(
                environment_path,
                expected_source_ref=source,
                require_ready=True,
            )
        except (OSError, json.JSONDecodeError, ValueError):
            _fail("READINESS_RECEIPT_INVALID")

        try:
            task_set = FixedBenchmarkTaskSet.load(Path(task_set_path))
        except (OSError, json.JSONDecodeError, ValueError):
            _fail("TASK_SET_INVALID")
        expected_case_ids = tuple(case.case_id for case in task_set.cases)
        expected_corpus = _expected_fixture_corpus(task_set, self.repo_root)

        suite = _load_json(suite_path, "SUITE_MISSING", "SUITE_JSON_INVALID")
        _require(suite.get("schema_version") == SUITE_SCHEMA, "SUITE_SCHEMA_INVALID")
        _require(suite.get("source_ref") == source, "SUITE_SOURCE_REF_MISMATCH")
        task_info = suite.get("task_set")
        _require(isinstance(task_info, dict), "SUITE_TASK_SET_INVALID")
        _require(
            set(task_info)
            == {
                "task_set_id",
                "task_set_sha256",
                "case_ids",
                "case_count",
                "raw_task_text_embedded_in_suite",
            },
            "SUITE_TASK_SET_INVALID",
        )
        _require(task_info.get("task_set_id") == task_set.task_set_id, "TASK_SET_ID_MISMATCH")
        _require(task_info.get("task_set_sha256") == task_set.sha256, "TASK_SET_SHA_MISMATCH")
        _require(tuple(task_info.get("case_ids") or ()) == expected_case_ids, "TASK_SET_CASES_MISMATCH")
        _require(task_info.get("case_count") == len(expected_case_ids), "TASK_SET_COUNT_MISMATCH")
        _require(task_info.get("raw_task_text_embedded_in_suite") is False, "SUITE_RAW_TASK_TEXT_POLICY_INVALID")
        _require(suite.get("fixture_corpus_sha256") == expected_corpus, "FIXTURE_CORPUS_MISMATCH")

        security = suite.get("security")
        expected_security = {
            "local_fixture_only": True,
            "public_internet_required": False,
            "public_internet_authority_added": False,
            "raw_prompt_logged": False,
            "raw_evidence_logged": False,
            "daily_report_excluded_from_task_level_efficiency_measurement": True,
        }
        _require(security == expected_security, "SUITE_SECURITY_BOUNDARY_INVALID")

        raw_variants = suite.get("variants")
        specs = {spec.label: spec for spec in DEFAULT_VARIANTS}
        _require(
            isinstance(raw_variants, dict) and set(raw_variants) == set(specs),
            "VARIANT_SET_MISMATCH",
        )
        raw_comparisons = suite.get("comparisons")
        candidate_labels = tuple(spec.label for spec in DEFAULT_VARIANTS[1:])
        _require(
            isinstance(raw_comparisons, dict) and set(raw_comparisons) == set(candidate_labels),
            "COMPARISON_SET_MISMATCH",
        )

        executions: dict[str, VariantExecution] = {}
        manifests: dict[str, dict[str, Any]] = {}
        artifact_hashes: dict[str, str] = {
            "environment.json": _file_sha256(environment_path),
            "suite.json": _file_sha256(suite_path),
        }
        baseline_task_ids: tuple[str, ...] | None = None

        expected_variant_keys = {
            "schema_version",
            "packing_mode",
            "context_budget_chars",
            "elapsed_ms",
            "corpus_sha256",
            "manifest_path",
            "configuration_sha256",
            "metrics_sha256",
            "cases",
        }
        for spec in DEFAULT_VARIANTS:
            row = raw_variants[spec.label]
            if not isinstance(row, dict) or set(row) != expected_variant_keys:
                _fail("VARIANT_ROW_INVALID")
            _require(row.get("schema_version") == _VARIANT_SCHEMA, "VARIANT_SCHEMA_INVALID")
            _require(row.get("packing_mode") == spec.evidence_packing_mode, "VARIANT_PACKING_MODE_MISMATCH")
            _require(
                row.get("context_budget_chars") == spec.synthesis_context_budget_chars,
                "VARIANT_CONTEXT_BUDGET_MISMATCH",
            )
            elapsed = row.get("elapsed_ms")
            if isinstance(elapsed, bool) or not isinstance(elapsed, int) or elapsed < 0:
                _fail("VARIANT_LATENCY_INVALID")
            _require(row.get("corpus_sha256") == expected_corpus, "VARIANT_CORPUS_MISMATCH")
            relative_manifest = f"{spec.label}/benchmark.json"
            _safe_relative_artifact_path(row.get("manifest_path"), relative_manifest)

            manifest_path = root / spec.label / "benchmark.json"
            isolation_path = root / spec.label / "isolation.json"
            manifest = _load_json(
                manifest_path,
                "BENCHMARK_MANIFEST_MISSING",
                "BENCHMARK_MANIFEST_JSON_INVALID",
            )
            _require(manifest.get("schema_version") == BENCHMARK_SCHEMA, "BENCHMARK_MANIFEST_SCHEMA_INVALID")
            try:
                metrics, lineage = unpack_metrics_payload(manifest)
            except ValueError:
                _fail("BENCHMARK_MANIFEST_LINEAGE_INVALID")
            _require(lineage is not None, "BENCHMARK_MANIFEST_LINEAGE_MISSING")
            _require(lineage.get("variant_label") == spec.label, "BENCHMARK_VARIANT_LINEAGE_MISMATCH")
            _require(lineage.get("source_ref") == source, "BENCHMARK_SOURCE_LINEAGE_MISMATCH")
            _require(
                lineage.get("metric_registry_sha256") == DEFAULT_METRIC_REGISTRY.sha256,
                "METRIC_REGISTRY_LINEAGE_MISMATCH",
            )
            _require(
                row.get("configuration_sha256") == lineage.get("configuration_sha256"),
                "CONFIGURATION_LINEAGE_MISMATCH",
            )
            _require(
                row.get("metrics_sha256") == lineage.get("metrics_sha256"),
                "METRICS_LINEAGE_MISMATCH",
            )
            cases = _validate_case_rows(row.get("cases"), expected_case_ids=expected_case_ids)
            task_ids = tuple(str(item["task_id"]) for item in cases)
            metric_scope = metrics.get("scope") if isinstance(metrics, dict) else None
            metric_ids = tuple((metric_scope or {}).get("task_ids") or ())
            _require(tuple(sorted(metric_ids)) == tuple(sorted(task_ids)), "METRICS_TASK_SCOPE_MISMATCH")
            if baseline_task_ids is None:
                baseline_task_ids = task_ids
            else:
                _require(task_ids == baseline_task_ids, "VARIANT_TASK_SCOPE_DRIFT")

            isolation = _load_json(
                isolation_path,
                "ISOLATION_RECEIPT_MISSING",
                "ISOLATION_RECEIPT_JSON_INVALID",
            )
            _validate_isolation(isolation, spec=spec)
            artifact_hashes[relative_manifest] = _file_sha256(manifest_path)
            artifact_hashes[f"{spec.label}/isolation.json"] = _file_sha256(isolation_path)
            manifests[spec.label] = manifest
            executions[spec.label] = VariantExecution(
                metrics=metrics,
                cases=cases,
                elapsed_ms=elapsed,
                corpus_sha256=expected_corpus,
            )

        baseline_label = DEFAULT_VARIANTS[0].label
        recomputed: dict[str, dict[str, Any]] = {}
        promotion: dict[str, bool] = {}
        for label in candidate_labels:
            report = _recomputed_comparison(
                executions[baseline_label],
                executions[label],
                manifests[baseline_label],
                manifests[label],
            )
            _require(raw_comparisons[label] == report, "SUITE_COMPARISON_RECOMPUTE_MISMATCH")
            recomputed[label] = report
            promotion[label] = bool(report["promotion_eligible"])

        checks = {
            "READINESS_RECEIPT_PASS": True,
            "ARTIFACT_SET_PASS": True,
            "TASK_SET_LINEAGE_PASS": True,
            "FIXTURE_CORPUS_RECOMPUTE_PASS": True,
            "METRIC_REGISTRY_LINEAGE_PASS": True,
            "VARIANT_ISOLATION_PASS": True,
            "REQUIRED_VALIDATOR_RECOMPUTE_PASS": True,
            "OPTIMIZATION_RECOMPUTE_PASS": True,
            "METADATA_PRIVACY_BOUNDARY_PASS": True,
        }
        payload: dict[str, Any] = {
            "schema_version": VERIFICATION_SCHEMA,
            "source_ref": source,
            "passed": True,
            "task_set": {
                "task_set_id": task_set.task_set_id,
                "task_set_sha256": task_set.sha256,
                "case_count": len(expected_case_ids),
            },
            "fixture_corpus_sha256": expected_corpus,
            "metric_registry_sha256": DEFAULT_METRIC_REGISTRY.sha256,
            "environment": {
                "environment_sha256": readiness["environment_sha256"],
                "receipt_sha256": readiness["receipt_sha256"],
            },
            "checks": checks,
            "variant_labels": [spec.label for spec in DEFAULT_VARIANTS],
            "promotion_eligible": promotion,
            "artifact_sha256": dict(sorted(artifact_hashes.items())),
            "privacy": {
                "absolute_runner_paths_recorded": False,
                "raw_prompt_recorded": False,
                "raw_evidence_recorded": False,
                "raw_model_output_recorded": False,
            },
        }
        payload["verification_sha256"] = _canonical_sha256(payload)
        return payload


def validate_verification_receipt(payload: Any, *, expected_source_ref: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != VERIFICATION_SCHEMA:
        _fail("VERIFICATION_SCHEMA_INVALID")
    required = {
        "schema_version",
        "source_ref",
        "passed",
        "task_set",
        "fixture_corpus_sha256",
        "metric_registry_sha256",
        "environment",
        "checks",
        "variant_labels",
        "promotion_eligible",
        "artifact_sha256",
        "privacy",
        "verification_sha256",
    }
    _require(set(payload) == required, "VERIFICATION_FIELDS_INVALID")
    source = _source_ref(payload.get("source_ref"))
    if expected_source_ref is not None:
        _require(source == _source_ref(expected_source_ref), "VERIFICATION_SOURCE_REF_MISMATCH")
    _require(payload.get("passed") is True, "VERIFICATION_NOT_PASSED")
    _sha(payload.get("fixture_corpus_sha256"), "VERIFICATION_FIXTURE_SHA_INVALID")
    _require(
        payload.get("metric_registry_sha256") == DEFAULT_METRIC_REGISTRY.sha256,
        "VERIFICATION_METRIC_REGISTRY_MISMATCH",
    )
    checks = payload.get("checks")
    _require(
        isinstance(checks, dict) and bool(checks) and all(value is True for value in checks.values()),
        "VERIFICATION_CHECKS_INVALID",
    )
    privacy = payload.get("privacy")
    _require(
        isinstance(privacy, dict) and bool(privacy) and all(value is False for value in privacy.values()),
        "VERIFICATION_PRIVACY_INVALID",
    )
    claim = _sha(payload.get("verification_sha256"), "VERIFICATION_SHA_INVALID")
    unsigned = dict(payload)
    unsigned.pop("verification_sha256", None)
    _require(_canonical_sha256(unsigned) == claim, "VERIFICATION_SHA_MISMATCH")
    return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-benchmark-verify",
        description="Independently recompute trust-critical fixed benchmark artifact claims.",
    )
    parser.add_argument("--root", required=True, help="Extracted benchmark artifact root")
    parser.add_argument("--repo-root", default=".", help="Exact source checkout containing benchmark fixtures")
    parser.add_argument("--task-set", default="benchmarks/fixed_task_set_v1.json")
    parser.add_argument("--source-ref", required=True, help="Exact 40-hex benchmark source SHA")
    parser.add_argument("--output", required=True, help="Verification receipt JSON path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output = Path(args.output)
    try:
        report = BenchmarkEvidenceVerifier(Path(args.root), Path(args.repo_root)).verify(
            source_ref=args.source_ref,
            task_set_path=Path(args.task_set),
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        temporary = output.with_name(output.name + ".tmp")
        temporary.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(output)
    except (OSError, json.JSONDecodeError, BenchmarkSuiteError, BenchmarkEvidenceError, ValueError) as exc:
        code = exc.reason_code if isinstance(exc, BenchmarkEvidenceError) else "BENCHMARK_EVIDENCE_INVALID"
        print(
            json.dumps(
                {
                    "schema_version": VERIFICATION_SCHEMA,
                    "passed": False,
                    "failure_code": code,
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
