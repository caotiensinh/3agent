from __future__ import annotations

import inspect
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

import three_agent.security_monitoring.enterprise_verification as verification
from three_agent.security_monitoring.advanced_benchmark import (
    load_fixed_benchmark,
    run_advanced_benchmark,
)
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.enterprise_verification import (
    REPORT_EVIDENCE_COVERAGE_TARGET_PCT,
    REQUIRED_ENTERPRISE_CHECKS,
    build_enterprise_verification_receipt,
    measure_report_evidence_coverage,
    receipt_json,
)
from three_agent.security_monitoring.locking import HOURLY_LOCK_STALE_AFTER_SECONDS
from three_agent.security_monitoring.reporting import (
    DeterministicReport,
    MetricSummary,
    PeriodSummary,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/security_monitoring/anomaly_benchmark.json"


def period(label: str) -> PeriodSummary:
    return PeriodSummary(
        label=label,
        starts_at="2026-08-30T00:00:00+09:00",
        ends_at="2026-08-30T17:30:00+09:00",
        hourly_runs=17,
        average_coverage_pct=100.0,
        event_count=1,
        finding_count=1,
        open_high_critical=1,
        severity_counts={"high": 1},
        finding_status_counts={"open": 1},
        data_gap_count=0,
        metric_summaries=(MetricSummary("if_rx_errors", 17, 0.0, 2.0, 0.1),),
    )


def report(evidence_refs=("event:ev-1",)) -> DeterministicReport:
    finding = {
        "finding_id": "F-EV-1",
        "category": "network_instability",
        "severity": "high",
        "status": "open",
        "first_seen": "2026-08-30T12:00:00+09:00",
        "last_seen": "2026-08-30T12:05:00+09:00",
        "asset_refs": ["switch-ev-01"],
        "evidence_refs": ["event:ev-1"],
        "rule_id": "rule-ev-network",
    }
    return DeterministicReport(
        report_id="report-ev-fixed",
        cutoff_at="2026-08-30T17:30:00+09:00",
        generated_at="2026-08-30T17:30:01+09:00",
        today=period("today"),
        rolling_7d=period("rolling_7d"),
        rolling_30d=period("rolling_30d"),
        evidence_refs=tuple(evidence_refs),
        findings=(finding,),
    )


def evidence():
    return {check: (f"test:{check.lower()}",) for check in REQUIRED_ENTERPRISE_CHECKS}


class EnterpriseVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.benchmark = run_advanced_benchmark(load_fixed_benchmark(FIXTURE))

    def test_report_evidence_reference_target_is_exact_and_fail_closed(self):
        self.assertEqual(REPORT_EVIDENCE_COVERAGE_TARGET_PCT, 100.0)
        complete = measure_report_evidence_coverage(report())
        self.assertTrue(complete.passed)
        self.assertEqual(complete.coverage_pct, 100.0)
        self.assertEqual(complete.material_findings, 1)
        self.assertEqual(complete.fully_referenced_findings, 1)

        missing = measure_report_evidence_coverage(report(evidence_refs=()))
        self.assertFalse(missing.passed)
        self.assertEqual(missing.coverage_pct, 0.0)

    def test_receipt_requires_exact_ev01_to_ev10_and_is_metadata_only(self):
        receipt = build_enterprise_verification_receipt(
            source_sha="a" * 40,
            evidence=evidence(),
            report=report(),
            benchmark=self.benchmark,
        )
        self.assertEqual(tuple(check for check, _ in receipt.checks), REQUIRED_ENTERPRISE_CHECKS)
        self.assertEqual(len(receipt.checks), 10)
        self.assertFalse(receipt.real_lan_exercised)
        self.assertRegex(receipt.fingerprint, r"^sha256:[0-9a-f]{64}$")
        rendered = receipt_json(receipt)
        self.assertIn('"coverage_pct":100.0', rendered)
        self.assertIn('"real_lan_exercised":false', rendered)
        for forbidden in ("192.168.", "raw_log", "packet_payload", "secret-ref:", "password", "token"):
            self.assertNotIn(forbidden, rendered.lower())

    def test_missing_check_bad_sha_or_unreferenced_finding_blocks_receipt(self):
        missing = evidence()
        missing.pop("EV-04")
        with self.assertRaises(MonitoringContractError):
            build_enterprise_verification_receipt(
                source_sha="a" * 40,
                evidence=missing,
                report=report(),
                benchmark=self.benchmark,
            )
        with self.assertRaises(MonitoringContractError):
            build_enterprise_verification_receipt(
                source_sha="not-a-git-sha",
                evidence=evidence(),
                report=report(),
                benchmark=self.benchmark,
            )
        with self.assertRaisesRegex(MonitoringContractError, "EV-07"):
            build_enterprise_verification_receipt(
                source_sha="a" * 40,
                evidence=evidence(),
                report=report(evidence_refs=()),
                benchmark=self.benchmark,
            )

    def test_resource_benchmark_records_latency_cpu_ram_state_and_zero_llm(self):
        receipt = build_enterprise_verification_receipt(
            source_sha="b" * 40,
            evidence=evidence(),
            report=report(),
            benchmark=self.benchmark,
        )
        resources = receipt.resource_benchmark
        self.assertGreaterEqual(resources.baseline_wall_ms, 0.0)
        self.assertGreaterEqual(resources.candidate_wall_ms, 0.0)
        self.assertGreaterEqual(resources.baseline_cpu_ms, 0.0)
        self.assertGreaterEqual(resources.candidate_cpu_ms, 0.0)
        self.assertGreater(resources.baseline_peak_allocated_bytes, 0)
        self.assertGreater(resources.candidate_peak_allocated_bytes, 0)
        self.assertGreater(resources.baseline_state_bytes, 0)
        self.assertGreater(resources.candidate_state_bytes, 0)
        self.assertEqual(resources.baseline_llm_calls, 0)
        self.assertEqual(resources.candidate_llm_calls, 0)
        self.assertEqual(resources.candidate_external_dependencies, 0)
        self.assertFalse(resources.production_promotion_authorized)

    def test_verifier_has_no_network_model_or_shell_authority(self):
        module_source = inspect.getsource(verification)
        script_source = (ROOT / "scripts/security_enterprise_verify.py").read_text(encoding="utf-8")
        combined = module_source + "\n" + script_source
        for forbidden in (
            "import socket",
            "urlopen",
            "requests.",
            "subprocess",
            "OllamaClient",
            "generate_json",
            "shell=True",
        ):
            self.assertNotIn(forbidden, combined)

    def test_hourly_process_timeout_precedes_stale_lock_recovery_bound(self):
        service = (ROOT / "scripts/systemd/workspace-security-monitor-hourly.service").read_text(
            encoding="utf-8"
        )
        self.assertIn("TimeoutStartSec=15min", service)
        self.assertIn("KillMode=control-group", service)
        self.assertEqual(HOURLY_LOCK_STALE_AFTER_SECONDS, 20 * 60)
        self.assertGreater(HOURLY_LOCK_STALE_AFTER_SECONDS, 15 * 60)


if __name__ == "__main__":
    unittest.main()
