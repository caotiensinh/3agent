#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
from pathlib import Path

from three_agent.security_monitoring.advanced_benchmark import (
    load_fixed_benchmark,
    run_advanced_benchmark,
)
from three_agent.security_monitoring.enterprise_verification import (
    build_enterprise_verification_receipt,
    receipt_json,
)
from three_agent.security_monitoring.reporting import (
    DeterministicReport,
    MetricSummary,
    PeriodSummary,
)

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "security_monitoring" / "anomaly_benchmark.json"

EVIDENCE = {
    "EV-01": ("ci:full-unit-integration-suite",),
    "EV-02": ("ci:security-boundary-suite",),
    "EV-03": ("test:MonitoringPolicyTests.test_exact_approved_host_and_port_are_required",),
    "EV-04": ("test:MonitoringContractsTests.test_snmp_requires_opaque_reference_not_raw_secret",),
    "EV-05": (
        "test:PcapApprovalConfirmationTests.test_approval_and_execution_use_distinct_literal_confirmations",
        "test:AIAnalystTests.test_schema_cannot_mint_severity_authority_inventory_or_remediation_state",
    ),
    "EV-06": ("test:HourlyRunnerTests.test_hourly_run_persists_receipt_and_full_coverage_without_llm",),
    "EV-07": ("metric:report-evidence-reference-coverage-100pct",),
    "EV-08": ("test:NasArchiveRecoveryTests.test_missing_or_unmounted_nas_is_pending_and_exact_bundle_recovers_without_reanalysis",),
    "EV-09": (
        "test:HourlyRunnerTests.test_finalized_hourly_slot_replay_returns_durable_receipt_without_recollection",
        "test:HourlyRunnerTests.test_restart_can_reclaim_only_a_hard_stale_lock",
    ),
    "EV-10": ("benchmark:fixed-anomaly-resource-v1",),
}


def _period(label: str) -> PeriodSummary:
    return PeriodSummary(
        label=label,
        starts_at="2026-08-30T00:00:00+09:00",
        ends_at="2026-08-30T17:30:00+09:00",
        hourly_runs=17,
        average_coverage_pct=100.0,
        event_count=2,
        finding_count=2,
        open_high_critical=2,
        severity_counts={"high": 2},
        finding_status_counts={"open": 2},
        data_gap_count=0,
        metric_summaries=(MetricSummary("if_rx_errors", 17, 0.0, 2.0, 0.1),),
    )


def _fixed_report() -> DeterministicReport:
    findings = (
        {
            "finding_id": "F-EV-1",
            "category": "network_instability",
            "severity": "high",
            "status": "open",
            "first_seen": "2026-08-30T12:00:00+09:00",
            "last_seen": "2026-08-30T12:05:00+09:00",
            "asset_refs": ["switch-ev-01"],
            "evidence_refs": ["event:ev-1", "obs:ev-1"],
            "rule_id": "rule-ev-network",
        },
        {
            "finding_id": "F-EV-2",
            "category": "sensor_data_gap",
            "severity": "high",
            "status": "open",
            "first_seen": "2026-08-30T13:00:00+09:00",
            "last_seen": "2026-08-30T13:05:00+09:00",
            "asset_refs": ["sensor-ev-01"],
            "evidence_refs": ["event:ev-2"],
            "rule_id": "rule-ev-gap",
        },
    )
    evidence_refs = ("event:ev-1", "obs:ev-1", "event:ev-2")
    return DeterministicReport(
        report_id="report-ev-fixed",
        cutoff_at="2026-08-30T17:30:00+09:00",
        generated_at="2026-08-30T17:30:01+09:00",
        today=_period("today"),
        rolling_7d=_period("rolling_7d"),
        rolling_30d=_period("rolling_30d"),
        evidence_refs=evidence_refs,
        findings=findings,
    )


def build_receipt(source_sha: str):
    benchmark = run_advanced_benchmark(load_fixed_benchmark(FIXTURE))
    return build_enterprise_verification_receipt(
        source_sha=source_sha,
        evidence=EVIDENCE,
        report=_fixed_report(),
        benchmark=benchmark,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="security-enterprise-verify")
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)

    receipt = build_receipt(args.source_sha)
    output = args.output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".tmp")
    temporary.write_text(receipt_json(receipt), encoding="utf-8")
    os.replace(temporary, output)
    print(
        f"security-enterprise-verification: PASS checks={len(receipt.checks)} "
        f"coverage={receipt.report_evidence_coverage.coverage_pct:.1f}% "
        f"fingerprint={receipt.fingerprint}",
        flush=True,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
