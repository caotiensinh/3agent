from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .benchmark_isolation import (
    BenchmarkIsolation,
    BenchmarkVariantSpec,
    PreparedBenchmarkVariant,
)
from .benchmark_snapshot import build_benchmark_manifest, write_benchmark_manifest
from .config import AppConfig, load_config
from .evidence_packing import LEGACY_PACKING_MODE, QUALITY_RANKED_PACKING_MODE
from .metrics_snapshot import MetricsSnapshotService
from .optimization_gate import OptimizationAcceptanceGate, OptimizationGateError
from .orchestrator import Orchestrator
from .validator_ledger import ValidatorLedger

TASKSET_SCHEMA = "workspace-benchmark-taskset/v1"
SUITE_SCHEMA = "workspace-fixed-benchmark-suite/v1"
_VARIANT_SCHEMA = "workspace-fixed-benchmark-variant/v1"
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
_SOURCE_REF_RE = re.compile(r"^[0-9a-f]{40}$")
_ALLOWED_FIXTURE_SUFFIXES = {".txt", ".md", ".markdown", ".html", ".htm"}

DEFAULT_VARIANTS = (
    BenchmarkVariantSpec(
        "baseline-legacy-48k",
        evidence_packing_mode=LEGACY_PACKING_MODE,
        synthesis_context_budget_chars=48000,
    ),
    BenchmarkVariantSpec(
        "ranked-48k",
        evidence_packing_mode=QUALITY_RANKED_PACKING_MODE,
        synthesis_context_budget_chars=48000,
    ),
    BenchmarkVariantSpec(
        "ranked-40k",
        evidence_packing_mode=QUALITY_RANKED_PACKING_MODE,
        synthesis_context_budget_chars=40000,
    ),
    BenchmarkVariantSpec(
        "ranked-32k",
        evidence_packing_mode=QUALITY_RANKED_PACKING_MODE,
        synthesis_context_budget_chars=32000,
    ),
)


class BenchmarkSuiteError(RuntimeError):
    """The fixed-task benchmark cannot produce trustworthy comparison evidence."""


def _sha256_bytes(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return _sha256_bytes(raw)


@dataclass(frozen=True)
class BenchmarkCase:
    case_id: str
    title: str
    request: str
    fixtures: tuple[str, ...]
    audience: str = "R&D internal"
    purpose: str = "inform"
    language: str = "en"
    slide_count: int = 6

    def to_payload(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "request": self.request,
            "fixtures": list(self.fixtures),
            "audience": self.audience,
            "purpose": self.purpose,
            "language": self.language,
            "slide_count": self.slide_count,
        }


@dataclass(frozen=True)
class FixedBenchmarkTaskSet:
    task_set_id: str
    cases: tuple[BenchmarkCase, ...]
    source_path: Path

    def to_payload(self) -> dict[str, Any]:
        return {
            "schema_version": TASKSET_SCHEMA,
            "task_set_id": self.task_set_id,
            "tasks": [case.to_payload() for case in self.cases],
        }

    @property
    def sha256(self) -> str:
        return _canonical_sha256(self.to_payload())

    @classmethod
    def load(cls, path: Path) -> "FixedBenchmarkTaskSet":
        source = Path(path)
        payload = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(payload, dict) or payload.get("schema_version") != TASKSET_SCHEMA:
            raise ValueError(f"task set schema must be {TASKSET_SCHEMA}")
        task_set_id = str(payload.get("task_set_id") or "").strip()
        if not _ID_RE.fullmatch(task_set_id):
            raise ValueError("task_set_id must be a compact stable identifier")
        raw_tasks = payload.get("tasks")
        if not isinstance(raw_tasks, list) or not raw_tasks or len(raw_tasks) > 32:
            raise ValueError("task set must contain between 1 and 32 tasks")

        cases: list[BenchmarkCase] = []
        seen: set[str] = set()
        for raw in raw_tasks:
            if not isinstance(raw, dict):
                raise ValueError("every benchmark task must be an object")
            case_id = str(raw.get("case_id") or "").strip()
            if not _ID_RE.fullmatch(case_id) or case_id in seen:
                raise ValueError("benchmark case_id values must be unique compact identifiers")
            seen.add(case_id)
            title = " ".join(str(raw.get("title") or "").split())
            request = str(raw.get("request") or "").strip()
            if not title or len(title) > 500:
                raise ValueError(f"invalid benchmark title for {case_id}")
            if not request or len(request) > 12000:
                raise ValueError(f"invalid benchmark request for {case_id}")

            raw_fixtures = raw.get("fixtures")
            if not isinstance(raw_fixtures, list) or not 1 <= len(raw_fixtures) <= 8:
                raise ValueError(f"{case_id} must declare between 1 and 8 fixtures")
            fixtures: list[str] = []
            for item in raw_fixtures:
                rel = str(item or "").strip().replace("\\", "/")
                candidate = Path(rel)
                if (
                    not rel
                    or candidate.is_absolute()
                    or ".." in candidate.parts
                    or candidate.suffix.casefold() not in _ALLOWED_FIXTURE_SUFFIXES
                ):
                    raise ValueError(f"unsafe or unsupported fixture path: {rel!r}")
                if rel not in fixtures:
                    fixtures.append(rel)
            if not fixtures:
                raise ValueError(f"{case_id} has no usable fixture paths")

            language = str(raw.get("language", "en")).strip().lower()
            if language not in {"en", "ja", "vi"}:
                raise ValueError(f"unsupported benchmark language for {case_id}: {language}")
            slides = raw.get("slide_count", 6)
            if isinstance(slides, bool) or not isinstance(slides, int) or not 3 <= slides <= 20:
                raise ValueError(f"slide_count must be 3..20 for {case_id}")

            cases.append(
                BenchmarkCase(
                    case_id=case_id,
                    title=title,
                    request=request,
                    fixtures=tuple(fixtures),
                    audience=" ".join(str(raw.get("audience", "R&D internal")).split()) or "R&D internal",
                    purpose=" ".join(str(raw.get("purpose", "inform")).split()) or "inform",
                    language=language,
                    slide_count=slides,
                )
            )
        return cls(task_set_id=task_set_id, cases=tuple(cases), source_path=source)


@dataclass(frozen=True)
class VariantExecution:
    metrics: dict[str, Any]
    cases: tuple[dict[str, Any], ...]
    elapsed_ms: int
    corpus_sha256: str


class _BenchmarkNoopDailyReport:
    """Remove date-wide report generation from a task-level packing benchmark.

    Daily Report is not a required task validator. Replacing it with a no-op keeps
    the production WorkflowRunner/RuntimeValidatorBridge path while preventing an
    unrelated reporting model call and sandbox-specific activity text from
    contaminating context-packing token/latency measurements.
    """

    agent_id = "benchmark_daily_report_noop"

    @staticmethod
    def run(*args: Any, **kwargs: Any) -> tuple[()]:
        del args, kwargs
        return ()


VariantExecutor = Callable[
    [PreparedBenchmarkVariant, FixedBenchmarkTaskSet, Path], VariantExecution
]


class FixedTaskBenchmarkSuite:
    """Execute one fixed local-evidence task set across isolated packing variants."""

    def __init__(
        self,
        base_config: AppConfig,
        benchmark_root: Path,
        repo_root: Path,
        *,
        variants: tuple[BenchmarkVariantSpec, ...] = DEFAULT_VARIANTS,
        variant_executor: VariantExecutor | None = None,
        verify_source_checkout: bool = True,
    ):
        self.base_config = base_config
        self.benchmark_root = Path(benchmark_root).expanduser().resolve()
        self.repo_root = Path(repo_root).expanduser().resolve()
        self.variants = tuple(item.validate() for item in variants)
        self.variant_executor = variant_executor or self._execute_variant
        self.verify_source_checkout = verify_source_checkout
        if not self.variants or self.variants[0].label != "baseline-legacy-48k":
            raise ValueError("first benchmark variant must be baseline-legacy-48k")
        if len({item.label for item in self.variants}) != len(self.variants):
            raise ValueError("benchmark variant labels must be unique")

    def _validate_local_only_policy(self) -> None:
        internet = self.base_config.internet_gateway
        mode = str(self.base_config.confidentiality_mode or "").strip().lower()
        if self.base_config.test_mode_full_access:
            raise BenchmarkSuiteError("benchmark refuses test_mode_full_access")
        if internet.allow_all or internet.public_search_enabled or internet.direct_egress:
            raise BenchmarkSuiteError(
                "fixed benchmark requires local fixture-only inference with public Internet egress disabled"
            )
        if mode in {"public", "public-research"}:
            raise BenchmarkSuiteError(
                "fixed benchmark must run in an internal/confidential local trust domain"
            )

    def _verify_checkout(self, source_ref: str) -> None:
        if not self.verify_source_checkout:
            return
        try:
            head = subprocess.run(
                ["git", "-C", str(self.repo_root), "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip().lower()
            dirty = subprocess.run(
                [
                    "git",
                    "-C",
                    str(self.repo_root),
                    "status",
                    "--porcelain",
                    "--untracked-files=no",
                ],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except (OSError, subprocess.CalledProcessError) as exc:
            raise BenchmarkSuiteError("benchmark requires a readable Git checkout for source lineage") from exc
        if head != source_ref:
            raise BenchmarkSuiteError(
                f"source_ref does not match checkout HEAD: expected={source_ref} actual={head}"
            )
        if dirty:
            raise BenchmarkSuiteError("tracked working tree must be clean before benchmark execution")

    def _fixture_path(self, relative: str) -> Path:
        path = (self.repo_root / relative).resolve()
        if not path.is_relative_to(self.repo_root) or not path.is_file():
            raise BenchmarkSuiteError(f"benchmark fixture is missing or escaped repo root: {relative}")
        if path.suffix.casefold() not in _ALLOWED_FIXTURE_SUFFIXES:
            raise BenchmarkSuiteError(f"unsupported benchmark fixture type: {relative}")
        return path

    @staticmethod
    def _stable_upload_id(task_set_id: str, relative: str, data: bytes) -> str:
        seed = (
            task_set_id.encode("utf-8")
            + b"\0"
            + relative.encode("utf-8")
            + b"\0"
            + hashlib.sha256(data).digest()
        )
        return hashlib.sha256(seed).hexdigest()[:16]

    def _prepare_fixture_uploads(
        self,
        orchestrator: Orchestrator,
        task_set: FixedBenchmarkTaskSet,
    ) -> tuple[dict[str, str], str]:
        cache: dict[str, str] = {}
        corpus_rows: list[dict[str, str]] = []
        ordered_paths = list(
            dict.fromkeys(path for case in task_set.cases for path in case.fixtures)
        )
        for relative in ordered_paths:
            path = self._fixture_path(relative)
            data = path.read_bytes()
            content_sha = _sha256_bytes(data)
            record = orchestrator.knowledge_gateway.ingest_upload(
                path.name,
                data,
                sender="workspace-fixed-benchmark",
            )
            stable_id = self._stable_upload_id(task_set.task_set_id, relative, data)
            source_folder = orchestrator.knowledge_gateway._folder(record.upload_id)
            stable_folder = orchestrator.knowledge_gateway._folder(stable_id)
            if stable_folder.exists():
                raise BenchmarkSuiteError(
                    f"deterministic benchmark upload collision for fixture: {relative}"
                )
            source_folder.rename(stable_folder)
            manifest_path = stable_folder / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["upload_id"] = stable_id
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            cache[relative] = stable_id
            corpus_rows.append(
                {
                    "path": relative,
                    "content_sha256": content_sha,
                    "upload_id": stable_id,
                }
            )
        return cache, _canonical_sha256(corpus_rows)

    def _execute_variant(
        self,
        prepared: PreparedBenchmarkVariant,
        task_set: FixedBenchmarkTaskSet,
        repo_root: Path,
    ) -> VariantExecution:
        del repo_root
        orchestrator = Orchestrator(prepared.config)
        orchestrator.initialize()
        orchestrator.workflow.daily_agent = _BenchmarkNoopDailyReport()
        fixture_ids, corpus_sha = self._prepare_fixture_uploads(orchestrator, task_set)

        task_ids: list[str] = []
        case_rows: list[dict[str, Any]] = []
        suite_started = time.perf_counter_ns()
        ledger = ValidatorLedger(orchestrator.store)
        for case in task_set.cases:
            task = orchestrator.store.create_task(case.title, case.request)
            task_ids.append(task.task_id)
            orchestrator.store.attach_uploads(
                task.task_id,
                [fixture_ids[path] for path in case.fixtures],
            )
            started = time.perf_counter_ns()
            result = orchestrator.workflow.run_task(
                task.task_id,
                live=True,
                audience=case.audience,
                purpose=case.purpose,
                language=case.language,
                slide_count=case.slide_count,
                output_format="source",
            )
            elapsed_ms = max(0, (time.perf_counter_ns() - started) // 1_000_000)
            verification = ledger.evaluate(task.task_id)
            case_rows.append(
                {
                    "case_id": case.case_id,
                    "task_id": task.task_id,
                    "workflow_status": result.status,
                    "task_status": result.task_status,
                    "elapsed_ms": int(elapsed_ms),
                    "contract_bound": verification.contract_bound,
                    "required_validators": list(verification.required_validators),
                    "passed_validators": list(verification.passed_validators),
                    "failed_validators": list(verification.failed_validators),
                    "missing_validators": list(verification.missing_validators),
                    "verified": verification.verified,
                    "first_pass_verified": verification.first_pass_verified,
                }
            )

        metrics = MetricsSnapshotService.from_orchestrator(orchestrator).snapshot(
            task_ids=task_ids
        )
        total_ms = max(0, (time.perf_counter_ns() - suite_started) // 1_000_000)
        return VariantExecution(
            metrics=metrics,
            cases=tuple(case_rows),
            elapsed_ms=int(total_ms),
            corpus_sha256=corpus_sha,
        )

    @staticmethod
    def _case_map(execution: VariantExecution) -> dict[str, dict[str, Any]]:
        return {str(item["case_id"]): item for item in execution.cases}

    @classmethod
    def _validator_gate(
        cls,
        baseline: VariantExecution,
        candidate: VariantExecution,
    ) -> dict[str, Any]:
        before = cls._case_map(baseline)
        after = cls._case_map(candidate)
        failures: list[str] = []
        checks: dict[str, Any] = {}
        if set(before) != set(after):
            failures.append("VALIDATOR_CASE_SET_MISMATCH")
        for case_id in sorted(set(before) & set(after)):
            left = before[case_id]
            right = after[case_id]
            left_required = tuple(left.get("required_validators", []))
            right_required = tuple(right.get("required_validators", []))
            required_match = left_required == right_required
            if not required_match:
                failures.append(f"VALIDATOR_REQUIREMENT_CHANGED:{case_id}")

            left_passed = set(left.get("passed_validators", []))
            right_passed = set(right.get("passed_validators", []))
            lost = sorted(left_passed - right_passed)
            for validator in lost:
                failures.append(f"VALIDATOR_REGRESSION:{case_id}:{validator}")
            checks[case_id] = {
                "required_match": required_match,
                "baseline_required": list(left_required),
                "candidate_required": list(right_required),
                "baseline_passed": sorted(left_passed),
                "candidate_passed": sorted(right_passed),
                "lost_passes": lost,
            }
        return {
            "schema_version": "workspace-required-validator-acceptance/v1",
            "passed": not failures,
            "checks": checks,
            "failures": failures,
        }

    @staticmethod
    def _quality_checks_passed(report: dict[str, Any]) -> bool:
        checks = report.get("quality_checks")
        return isinstance(checks, dict) and bool(checks) and all(
            isinstance(value, dict) and value.get("passed") is True
            for value in checks.values()
        )

    @staticmethod
    def _comparison_error(message: str) -> dict[str, Any]:
        return {
            "schema_version": "workspace-optimization-acceptance/v1",
            "accepted": False,
            "error": message,
            "quality_checks": {},
            "failures": ["COMPARISON_INVALID"],
        }

    def run(self, task_set_path: Path, *, source_ref: str) -> dict[str, Any]:
        source = str(source_ref or "").strip().lower()
        if not _SOURCE_REF_RE.fullmatch(source):
            raise ValueError("source_ref must be an exact 40-hex Git commit SHA")
        self._validate_local_only_policy()
        self._verify_checkout(source)
        task_set = FixedBenchmarkTaskSet.load(task_set_path)

        suite_path = self.benchmark_root / "suite.json"
        if suite_path.exists():
            raise FileExistsError(f"benchmark suite output already exists: {suite_path}")
        self.benchmark_root.mkdir(parents=True, exist_ok=True)
        isolation = BenchmarkIsolation(self.base_config, self.benchmark_root)

        executions: dict[str, VariantExecution] = {}
        manifests: dict[str, dict[str, Any]] = {}
        variant_rows: dict[str, dict[str, Any]] = {}
        baseline_task_ids: tuple[str, ...] | None = None
        baseline_corpus: str | None = None

        for spec in self.variants:
            with isolation.activate(spec) as prepared:
                execution = self.variant_executor(prepared, task_set, self.repo_root)
                task_ids = tuple(str(item["task_id"]) for item in execution.cases)
                if len(task_ids) != len(task_set.cases):
                    raise BenchmarkSuiteError(
                        f"variant {spec.label} did not execute every fixed benchmark case"
                    )
                if baseline_task_ids is None:
                    baseline_task_ids = task_ids
                    baseline_corpus = execution.corpus_sha256
                else:
                    if task_ids != baseline_task_ids:
                        raise BenchmarkSuiteError(
                            "isolated variants produced different runtime task IDs; fixed-scope comparison is invalid"
                        )
                    if execution.corpus_sha256 != baseline_corpus:
                        raise BenchmarkSuiteError(
                            "benchmark fixture corpus changed between variants"
                        )

                manifest = build_benchmark_manifest(
                    execution.metrics,
                    prepared.config,
                    variant_label=spec.label,
                    source_ref=source,
                )
                manifest_path = write_benchmark_manifest(
                    prepared.paths.sandbox_root / "benchmark.json",
                    manifest,
                )
                executions[spec.label] = execution
                manifests[spec.label] = manifest
                variant_rows[spec.label] = {
                    "schema_version": _VARIANT_SCHEMA,
                    "packing_mode": spec.evidence_packing_mode,
                    "context_budget_chars": spec.synthesis_context_budget_chars,
                    "elapsed_ms": execution.elapsed_ms,
                    "corpus_sha256": execution.corpus_sha256,
                    "manifest_path": str(manifest_path),
                    "configuration_sha256": manifest["lineage"]["configuration_sha256"],
                    "metrics_sha256": manifest["lineage"]["metrics_sha256"],
                    "cases": list(execution.cases),
                }

        baseline_label = self.variants[0].label
        baseline_execution = executions[baseline_label]
        baseline_manifest = manifests[baseline_label]
        comparisons: dict[str, Any] = {}
        gate = OptimizationAcceptanceGate()
        for spec in self.variants[1:]:
            candidate_execution = executions[spec.label]
            validator_report = self._validator_gate(
                baseline_execution,
                candidate_execution,
            )
            try:
                optimization_report = gate.evaluate(
                    baseline_manifest,
                    manifests[spec.label],
                )
            except (OptimizationGateError, ValueError) as exc:
                optimization_report = self._comparison_error(
                    f"{type(exc).__name__}: {exc}"
                )

            quality_preserved = (
                validator_report["passed"]
                and self._quality_checks_passed(optimization_report)
            )
            efficiency_evaluated = bool(quality_preserved)
            accepted = bool(
                quality_preserved
                and optimization_report.get("accepted") is True
            )
            latency = None
            if efficiency_evaluated:
                baseline_ms = baseline_execution.elapsed_ms
                candidate_ms = candidate_execution.elapsed_ms
                latency = {
                    "baseline_elapsed_ms": baseline_ms,
                    "candidate_elapsed_ms": candidate_ms,
                    "delta_ms": candidate_ms - baseline_ms,
                    "change_pct": (
                        0.0
                        if baseline_ms == 0 and candidate_ms == 0
                        else None
                        if baseline_ms == 0
                        else round(((candidate_ms - baseline_ms) / baseline_ms) * 100.0, 6)
                    ),
                }
            comparisons[spec.label] = {
                "schema_version": "workspace-fixed-benchmark-comparison/v1",
                "quality_preserved": quality_preserved,
                "required_validator_acceptance": validator_report,
                "optimization_acceptance": optimization_report,
                "efficiency_evaluated": efficiency_evaluated,
                "latency": latency,
                "promotion_eligible": accepted,
            }

        payload = {
            "schema_version": SUITE_SCHEMA,
            "source_ref": source,
            "task_set": {
                "task_set_id": task_set.task_set_id,
                "task_set_sha256": task_set.sha256,
                "case_ids": [case.case_id for case in task_set.cases],
                "case_count": len(task_set.cases),
                "raw_task_text_embedded_in_suite": False,
            },
            "fixture_corpus_sha256": baseline_corpus,
            "variants": variant_rows,
            "comparisons": comparisons,
            "security": {
                "local_fixture_only": True,
                "public_internet_required": False,
                "public_internet_authority_added": False,
                "raw_prompt_logged": False,
                "raw_evidence_logged": False,
                "daily_report_excluded_from_task_level_efficiency_measurement": True,
            },
        }
        temporary = suite_path.with_name(suite_path.name + ".tmp")
        temporary.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        temporary.replace(suite_path)
        return payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-benchmark",
        description="Run the fixed local-evidence WorkSpace context-packing benchmark suite.",
    )
    parser.add_argument(
        "--task-set",
        default="benchmarks/fixed_task_set_v1.json",
        help="Versioned fixed benchmark task set JSON.",
    )
    parser.add_argument(
        "--root",
        required=True,
        help="Fresh output root; existing non-empty variant sandboxes fail closed.",
    )
    parser.add_argument(
        "--repo-root",
        default=".",
        help="Git checkout root used for fixture paths and source-ref verification.",
    )
    parser.add_argument(
        "--source-ref",
        required=True,
        help="Exact 40-hex Git commit SHA; must equal checkout HEAD.",
    )
    parser.add_argument(
        "--config",
        help="Optional WorkSpace config path. Default resolution remains WORKSPACE_CONFIG/config/workspace.secure.json.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        suite = FixedTaskBenchmarkSuite(
            load_config(args.config),
            Path(args.root),
            Path(args.repo_root),
        ).run(Path(args.task_set), source_ref=args.source_ref)
    except (OSError, json.JSONDecodeError, ValueError, BenchmarkSuiteError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": SUITE_SCHEMA,
                    "completed": False,
                    "error": f"{type(exc).__name__}: {exc}",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3
    print(json.dumps(suite, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
