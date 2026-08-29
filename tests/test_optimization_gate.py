import json
import tempfile
import unittest
from pathlib import Path

from three_agent.cli import build_parser, main
from three_agent.optimization_gate import (
    OptimizationAcceptanceGate,
    OptimizationGateError,
    OptimizationGatePolicy,
)


def snapshot(*, tokens=100.0, verified_rate=1.0, first_pass=1.0, verified_tasks=2, evidence=1.0, task_ids=None):
    ids = task_ids or ["TASK-1", "TASK-2"]
    return {
        "schema_version": "workspace-unified-metrics/v1",
        "scope": {"date": None, "selected_task_count": len(ids), "task_ids": list(ids)},
        "verified_work": {
            "verified_task_success_rate": verified_rate,
            "first_pass_verified_success_rate": first_pass,
            "verified_tasks": verified_tasks,
        },
        "token_efficiency": {"total_tokens_per_verified_task": tokens},
        "resource_efficiency": {
            "tool_calls_per_verified_task": 3.0,
            "model_retries_per_verified_task": 0.5,
            "model_escalations_per_verified_task": 0.25,
        },
        "evidence_coverage": {"evidence_coverage": evidence},
        "context_precision_proxy": {"context_precision_proxy": 0.6},
        "context_recall_proxy": {"context_recall_proxy": 0.9},
    }


class OptimizationAcceptanceGateTests(unittest.TestCase):
    def test_token_saving_candidate_passes_when_quality_does_not_regress(self):
        report = OptimizationAcceptanceGate(
            OptimizationGatePolicy(min_token_reduction_pct=10.0)
        ).evaluate(snapshot(tokens=100), snapshot(tokens=80))
        self.assertTrue(report["accepted"])
        self.assertEqual(report["token_efficiency"]["reduction_pct"], 20.0)
        self.assertEqual(report["failures"], [])

    def test_large_token_saving_is_rejected_when_verified_quality_drops(self):
        report = OptimizationAcceptanceGate().evaluate(
            snapshot(tokens=100, verified_rate=1.0, verified_tasks=2),
            snapshot(tokens=40, verified_rate=0.5, verified_tasks=1),
        )
        self.assertFalse(report["accepted"])
        self.assertIn("QUALITY_REGRESSION:verified_task_success_rate", report["failures"])
        self.assertIn("QUALITY_REGRESSION:verified_tasks", report["failures"])

    def test_first_pass_and_evidence_regressions_fail_closed(self):
        report = OptimizationAcceptanceGate().evaluate(
            snapshot(tokens=100, first_pass=1.0, evidence=0.9),
            snapshot(tokens=90, first_pass=0.5, evidence=0.8),
        )
        self.assertFalse(report["accepted"])
        self.assertIn("QUALITY_REGRESSION:first_pass_verified_success_rate", report["failures"])
        self.assertIn("QUALITY_REGRESSION:evidence_coverage", report["failures"])

    def test_candidate_must_meet_requested_token_target(self):
        report = OptimizationAcceptanceGate(
            OptimizationGatePolicy(min_token_reduction_pct=15.0)
        ).evaluate(snapshot(tokens=100), snapshot(tokens=90))
        self.assertFalse(report["accepted"])
        self.assertIn(
            "EFFICIENCY_TARGET_MISSED:total_tokens_per_verified_task",
            report["failures"],
        )

    def test_mismatched_task_set_is_not_comparable(self):
        with self.assertRaises(OptimizationGateError):
            OptimizationAcceptanceGate().evaluate(
                snapshot(task_ids=["TASK-1", "TASK-2"]),
                snapshot(task_ids=["TASK-1", "TASK-3"]),
            )

    def test_baseline_without_verified_task_is_not_a_cost_baseline(self):
        with self.assertRaises(OptimizationGateError):
            OptimizationAcceptanceGate().evaluate(
                snapshot(verified_rate=0.0, first_pass=0.0, verified_tasks=0),
                snapshot(),
            )

    def test_proxy_changes_are_diagnostics_not_semantic_quality_claims(self):
        baseline = snapshot(tokens=100)
        candidate = snapshot(tokens=90)
        candidate["context_precision_proxy"]["context_precision_proxy"] = 0.7
        candidate["context_recall_proxy"]["context_recall_proxy"] = 0.8
        report = OptimizationAcceptanceGate().evaluate(baseline, candidate)
        self.assertTrue(report["accepted"])
        self.assertEqual(report["diagnostics"]["context_precision_proxy"]["delta"], 0.1)
        self.assertEqual(report["diagnostics"]["context_recall_proxy"]["delta"], -0.1)

    def test_cli_parses_compare_without_runtime_configuration(self):
        parser = build_parser()
        args = parser.parse_args(
            [
                "metrics-compare",
                "--baseline",
                "a.json",
                "--candidate",
                "b.json",
                "--min-token-reduction-pct",
                "5",
            ]
        )
        self.assertEqual(args.command, "metrics-compare")
        self.assertEqual(args.min_token_reduction_pct, 5.0)

    def test_cli_returns_zero_for_pass_and_three_for_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            baseline = root / "baseline.json"
            candidate = root / "candidate.json"
            baseline.write_text(json.dumps(snapshot(tokens=100)), encoding="utf-8")
            candidate.write_text(json.dumps(snapshot(tokens=80)), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "metrics-compare",
                        "--baseline",
                        str(baseline),
                        "--candidate",
                        str(candidate),
                        "--min-token-reduction-pct",
                        "10",
                    ]
                ),
                0,
            )
            candidate.write_text(json.dumps(snapshot(tokens=80, evidence=0.5)), encoding="utf-8")
            self.assertEqual(
                main(
                    [
                        "metrics-compare",
                        "--baseline",
                        str(baseline),
                        "--candidate",
                        str(candidate),
                    ]
                ),
                3,
            )


if __name__ == "__main__":
    unittest.main()
