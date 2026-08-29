from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .benchmark_snapshot import unpack_metrics_payload


class OptimizationGateError(ValueError):
    """The supplied metrics snapshots cannot be compared safely."""


@dataclass(frozen=True)
class OptimizationGatePolicy:
    min_token_reduction_pct: float = 0.0

    def __post_init__(self) -> None:
        value = float(self.min_token_reduction_pct)
        if value < 0.0 or value > 100.0:
            raise ValueError("min_token_reduction_pct must be between 0 and 100")


class OptimizationAcceptanceGate:
    """Fail closed when an efficiency candidate sacrifices verified quality.

    Inputs may be raw `workspace-unified-metrics/v1` snapshots or two validated
    `workspace-benchmark-snapshot/v1` manifests. Mixed raw/manifest comparisons are
    rejected so lineage cannot be present on only one side.
    """

    SCHEMA = "workspace-unified-metrics/v1"
    _EPSILON = 1e-9

    def __init__(self, policy: OptimizationGatePolicy | None = None):
        self.policy = policy or OptimizationGatePolicy()

    @staticmethod
    def _section(snapshot: dict[str, Any], key: str) -> dict[str, Any]:
        value = snapshot.get(key)
        if not isinstance(value, dict):
            raise OptimizationGateError(f"snapshot section {key!r} is missing or invalid")
        return value

    @staticmethod
    def _number(value: Any, label: str) -> float:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise OptimizationGateError(f"{label} must be numeric")
        return float(value)

    @staticmethod
    def _optional_number(value: Any, label: str) -> float | None:
        if value is None:
            return None
        return OptimizationAcceptanceGate._number(value, label)

    @classmethod
    def _scope(cls, snapshot: dict[str, Any]) -> tuple[str, ...]:
        if snapshot.get("schema_version") != cls.SCHEMA:
            raise OptimizationGateError(
                f"snapshot schema must be {cls.SCHEMA!r}"
            )
        scope = cls._section(snapshot, "scope")
        raw_ids = scope.get("task_ids")
        if not isinstance(raw_ids, list) or any(not isinstance(item, str) or not item for item in raw_ids):
            raise OptimizationGateError("scope.task_ids must be a list of non-empty strings")
        if len(set(raw_ids)) != len(raw_ids):
            raise OptimizationGateError("scope.task_ids must not contain duplicates")
        count = scope.get("selected_task_count")
        if isinstance(count, bool) or not isinstance(count, int) or count != len(raw_ids):
            raise OptimizationGateError("scope.selected_task_count does not match task_ids")
        if not raw_ids:
            raise OptimizationGateError("optimization comparison requires a non-empty fixed task set")
        return tuple(sorted(raw_ids))

    @classmethod
    def _quality_values(cls, snapshot: dict[str, Any]) -> dict[str, float | None]:
        verified = cls._section(snapshot, "verified_work")
        evidence = cls._section(snapshot, "evidence_coverage")
        return {
            "verified_task_success_rate": cls._number(
                verified.get("verified_task_success_rate"),
                "verified_work.verified_task_success_rate",
            ),
            "first_pass_verified_success_rate": cls._number(
                verified.get("first_pass_verified_success_rate"),
                "verified_work.first_pass_verified_success_rate",
            ),
            "verified_tasks": cls._number(
                verified.get("verified_tasks"), "verified_work.verified_tasks"
            ),
            "evidence_coverage": cls._optional_number(
                evidence.get("evidence_coverage"),
                "evidence_coverage.evidence_coverage",
            ),
        }

    @classmethod
    def _token_value(cls, snapshot: dict[str, Any]) -> float:
        section = cls._section(snapshot, "token_efficiency")
        value = section.get("total_tokens_per_verified_task")
        if value is None:
            raise OptimizationGateError(
                "total_tokens_per_verified_task is undefined; both snapshots need verified tasks"
            )
        result = cls._number(value, "token_efficiency.total_tokens_per_verified_task")
        if result < 0:
            raise OptimizationGateError("token cost cannot be negative")
        return result

    @classmethod
    def _diagnostic_delta(
        cls,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
        section: str,
        field: str,
    ) -> dict[str, float | None]:
        before = cls._optional_number(cls._section(baseline, section).get(field), f"{section}.{field}")
        after = cls._optional_number(cls._section(candidate, section).get(field), f"{section}.{field}")
        delta = None if before is None or after is None else round(after - before, 6)
        return {"baseline": before, "candidate": after, "delta": delta}

    def evaluate(
        self,
        baseline: dict[str, Any],
        candidate: dict[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(baseline, dict) or not isinstance(candidate, dict):
            raise OptimizationGateError("baseline and candidate must be JSON objects")
        try:
            baseline_metrics, baseline_lineage = unpack_metrics_payload(baseline)
            candidate_metrics, candidate_lineage = unpack_metrics_payload(candidate)
        except ValueError as exc:
            raise OptimizationGateError(str(exc)) from exc
        if (baseline_lineage is None) != (candidate_lineage is None):
            raise OptimizationGateError(
                "baseline and candidate must both be benchmark manifests or both be raw metrics"
            )

        baseline_scope = self._scope(baseline_metrics)
        candidate_scope = self._scope(candidate_metrics)
        if baseline_scope != candidate_scope:
            raise OptimizationGateError("baseline and candidate must use the same fixed task set")

        baseline_quality = self._quality_values(baseline_metrics)
        candidate_quality = self._quality_values(candidate_metrics)
        if baseline_quality["verified_tasks"] <= 0:
            raise OptimizationGateError("baseline must contain at least one verified task")

        failures: list[str] = []
        quality_checks: dict[str, dict[str, Any]] = {}
        for key in (
            "verified_task_success_rate",
            "first_pass_verified_success_rate",
        ):
            before = float(baseline_quality[key])
            after = float(candidate_quality[key])
            passed = after + self._EPSILON >= before
            quality_checks[key] = {
                "baseline": before,
                "candidate": after,
                "delta": round(after - before, 6),
                "passed": passed,
            }
            if not passed:
                failures.append(f"QUALITY_REGRESSION:{key}")

        before_verified = float(baseline_quality["verified_tasks"])
        after_verified = float(candidate_quality["verified_tasks"])
        verified_count_passed = after_verified + self._EPSILON >= before_verified
        quality_checks["verified_tasks"] = {
            "baseline": int(before_verified),
            "candidate": int(after_verified),
            "delta": int(after_verified - before_verified),
            "passed": verified_count_passed,
        }
        if not verified_count_passed:
            failures.append("QUALITY_REGRESSION:verified_tasks")

        before_evidence = baseline_quality["evidence_coverage"]
        after_evidence = candidate_quality["evidence_coverage"]
        if before_evidence is None:
            evidence_passed = True
        else:
            evidence_passed = (
                after_evidence is not None
                and float(after_evidence) + self._EPSILON >= float(before_evidence)
            )
        quality_checks["evidence_coverage"] = {
            "baseline": before_evidence,
            "candidate": after_evidence,
            "delta": (
                None
                if before_evidence is None or after_evidence is None
                else round(float(after_evidence) - float(before_evidence), 6)
            ),
            "passed": evidence_passed,
        }
        if not evidence_passed:
            failures.append("QUALITY_REGRESSION:evidence_coverage")

        baseline_tokens = self._token_value(baseline_metrics)
        candidate_tokens = self._token_value(candidate_metrics)
        if baseline_tokens == 0:
            reduction_pct = 0.0 if candidate_tokens == 0 else -100.0
        else:
            reduction_pct = round(
                ((baseline_tokens - candidate_tokens) / baseline_tokens) * 100.0,
                6,
            )
        token_passed = (
            reduction_pct + self._EPSILON >= float(self.policy.min_token_reduction_pct)
        )
        if not token_passed:
            failures.append("EFFICIENCY_TARGET_MISSED:total_tokens_per_verified_task")

        diagnostics = {
            "tool_calls_per_verified_task": self._diagnostic_delta(
                baseline_metrics, candidate_metrics, "resource_efficiency", "tool_calls_per_verified_task"
            ),
            "model_retries_per_verified_task": self._diagnostic_delta(
                baseline_metrics, candidate_metrics, "resource_efficiency", "model_retries_per_verified_task"
            ),
            "model_escalations_per_verified_task": self._diagnostic_delta(
                baseline_metrics, candidate_metrics, "resource_efficiency", "model_escalations_per_verified_task"
            ),
            "context_precision_proxy": self._diagnostic_delta(
                baseline_metrics, candidate_metrics, "context_precision_proxy", "context_precision_proxy"
            ),
            "context_recall_proxy": self._diagnostic_delta(
                baseline_metrics, candidate_metrics, "context_recall_proxy", "context_recall_proxy"
            ),
        }

        lineage_report = None
        if baseline_lineage is not None and candidate_lineage is not None:
            lineage_report = {
                "baseline": baseline_lineage,
                "candidate": candidate_lineage,
                "source_changed": baseline_lineage["source_ref"] != candidate_lineage["source_ref"],
                "configuration_changed": (
                    baseline_lineage["configuration_sha256"]
                    != candidate_lineage["configuration_sha256"]
                ),
            }

        return {
            "schema_version": "workspace-optimization-acceptance/v1",
            "accepted": not failures,
            "fixed_task_count": len(baseline_scope),
            "task_ids": list(baseline_scope),
            "lineage": lineage_report,
            "policy": {
                "min_token_reduction_pct": float(self.policy.min_token_reduction_pct),
                "verified_success_non_regression": True,
                "first_pass_non_regression": True,
                "evidence_coverage_non_regression": True,
            },
            "quality_checks": quality_checks,
            "token_efficiency": {
                "baseline_total_tokens_per_verified_task": baseline_tokens,
                "candidate_total_tokens_per_verified_task": candidate_tokens,
                "reduction_pct": reduction_pct,
                "passed": token_passed,
            },
            "diagnostics": diagnostics,
            "failures": failures,
        }
