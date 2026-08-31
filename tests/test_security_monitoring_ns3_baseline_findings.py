import unittest

from three_agent.security_monitoring.alerting import MemoryAlertSink, emit_high_critical
from three_agent.security_monitoring.baseline_benchmark import (
    BaselineBenchmarkCase,
    run_baseline_benchmark,
)
from three_agent.security_monitoring.baselines import (
    EwmaState,
    MaintenanceWindow,
    assess_robust_anomaly,
    maintenance_suppression,
    robust_baseline,
)
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.findings import (
    FindingSignal,
    correlate_signals,
    deterministic_severity,
    transition_finding,
)
from three_agent.security_monitoring.log_pipeline import evaluate_source_freshness


class BaselineTests(unittest.TestCase):
    def test_robust_baseline_warms_only_after_required_history(self):
        cold = robust_baseline((10, 10, 11), min_samples=5)
        self.assertFalse(cold.warm)
        assessment = assess_robust_anomaly(100, cold)
        self.assertEqual(assessment.status, "data_gap")
        self.assertEqual(assessment.reason_code, "BASELINE_WARMING")

        warm = robust_baseline((10, 10, 10, 11, 9, 10, 10), min_samples=5)
        self.assertTrue(warm.warm)
        self.assertEqual(warm.median_value, 10.0)

    def test_median_mad_flags_large_deviation_without_model(self):
        baseline = robust_baseline((99, 100, 100, 101, 100, 99, 101))
        normal = assess_robust_anomaly(101, baseline, absolute_floor=1.0)
        anomalous = assess_robust_anomaly(150, baseline, absolute_floor=1.0)
        self.assertEqual(normal.status, "normal")
        self.assertEqual(anomalous.status, "anomaly")

    def test_ewma_is_bounded_and_deterministic(self):
        state = EwmaState(alpha=0.2).update(100).update(110)
        self.assertEqual(state.sample_count, 2)
        self.assertAlmostEqual(state.value, 102.0)
        with self.assertRaises(MonitoringContractError):
            EwmaState(alpha=0.0).validate()

    def test_maintenance_context_marks_but_does_not_delete_evidence(self):
        window = MaintenanceWindow(
            change_id="chg-001",
            starts_at="2026-08-30T10:00:00+09:00",
            ends_at="2026-08-30T12:00:00+09:00",
            asset_refs=("switch-1",),
            category_prefixes=("network.",),
        ).validate()
        self.assertEqual(
            maintenance_suppression(
                asset_id="switch-1",
                category="network.interface",
                observed_at="2026-08-30T11:00:00+09:00",
                windows=(window,),
            ),
            "chg-001",
        )


class FindingCorrelationTests(unittest.TestCase):
    @staticmethod
    def signal(
        signal_id,
        *,
        source_id,
        observed_at,
        severity="high",
        evidence_ref=None,
    ):
        return FindingSignal(
            signal_id=signal_id,
            asset_id="switch-1",
            source_id=source_id,
            category="network.interface.error",
            severity=severity,
            observed_at=observed_at,
            evidence_ref=evidence_ref or f"evidence:{signal_id}",
            rule_id="rule-interface-error",
        ).validate()

    def test_cross_source_signals_correlate_inside_bounded_window(self):
        signals = (
            self.signal("s1", source_id="snmp", observed_at="2026-08-30T10:00:00+09:00"),
            self.signal("s2", source_id="syslog", observed_at="2026-08-30T10:03:00+09:00"),
        )
        result = correlate_signals(signals, window_seconds=900)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].signal_count, 2)
        self.assertEqual(result[0].distinct_sources, 2)
        self.assertEqual(result[0].finding.status, "correlated")
        self.assertEqual(len(result[0].finding.evidence_refs), 2)

    def test_maintenance_suppression_never_removes_or_downgrades_finding(self):
        window = MaintenanceWindow(
            change_id="chg-002",
            starts_at="2026-08-30T09:00:00+09:00",
            ends_at="2026-08-30T11:00:00+09:00",
            asset_refs=("switch-1",),
            category_prefixes=("network.",),
        )
        result = correlate_signals(
            (self.signal("s1", source_id="snmp", observed_at="2026-08-30T10:00:00+09:00"),),
            maintenance_windows=(window,),
        )[0]
        self.assertEqual(result.suppressed_by_change, "chg-002")
        self.assertEqual(result.finding.severity, "high")
        self.assertEqual(result.finding.evidence_refs, ("evidence:s1",))

    def test_finding_lifecycle_is_closed_and_reopen_requires_resolved(self):
        finding = correlate_signals(
            (self.signal("s1", source_id="snmp", observed_at="2026-08-30T10:00:00+09:00"),)
        )[0].finding
        investigating = transition_finding(
            finding, new_status="investigating", changed_at="2026-08-30T10:05:00+09:00"
        )
        resolved = transition_finding(
            investigating, new_status="resolved", changed_at="2026-08-30T10:10:00+09:00"
        )
        reopened = transition_finding(
            resolved, new_status="reopened", changed_at="2026-08-30T10:15:00+09:00"
        )
        self.assertEqual(reopened.status, "reopened")
        with self.assertRaises(MonitoringContractError):
            transition_finding(
                finding, new_status="reopened", changed_at="2026-08-30T10:05:00+09:00"
            )

    def test_severity_is_deterministic_and_data_gap_never_means_healthy(self):
        self.assertEqual(
            deterministic_severity(base_severity="medium", distinct_sources=2, repeated_count=3),
            "critical",
        )
        self.assertEqual(
            deterministic_severity(
                base_severity="low", distinct_sources=1, repeated_count=1, data_gap=True
            ),
            "medium",
        )
        freshness = evaluate_source_freshness(
            source_id="suricata-1",
            expected_interval_seconds=60,
            last_seen_at="2026-08-30T09:00:00+09:00",
            evaluated_at="2026-08-30T10:00:00+09:00",
        )
        self.assertFalse(freshness.fresh)
        self.assertEqual(freshness.reason_code, "SOURCE_STALE")


class InternalAlertTests(unittest.TestCase):
    def test_high_finding_emits_metadata_only_alert_without_ai(self):
        finding = FindingCorrelationTests.signal(
            "s1", source_id="snmp", observed_at="2026-08-30T10:00:00+09:00"
        )
        correlated = correlate_signals((finding,))[0].finding
        sink = MemoryAlertSink()
        alert = emit_high_critical(correlated, sink)
        self.assertIsNotNone(alert)
        self.assertEqual(len(sink.alerts), 1)
        self.assertTrue(alert.correlation_key_sha256.startswith("sha256:"))
        self.assertFalse(hasattr(alert, "raw_log"))
        self.assertFalse(hasattr(alert, "prompt"))

    def test_medium_finding_does_not_generate_immediate_alert(self):
        signal = FindingCorrelationTests.signal(
            "s1",
            source_id="snmp",
            observed_at="2026-08-30T10:00:00+09:00",
            severity="medium",
        )
        sink = MemoryAlertSink()
        self.assertIsNone(emit_high_critical(correlate_signals((signal,))[0].finding, sink))
        self.assertEqual(sink.alerts, [])


class BaselineBenchmarkTests(unittest.TestCase):
    def test_fixed_benchmark_records_detection_false_positive_and_zero_llm(self):
        result = run_baseline_benchmark(
            (
                BaselineBenchmarkCase(
                    "normal",
                    (100, 101, 99, 100, 100, 101, 99),
                    101,
                    False,
                ),
                BaselineBenchmarkCase(
                    "spike",
                    (100, 101, 99, 100, 100, 101, 99),
                    180,
                    True,
                ),
                BaselineBenchmarkCase(
                    "stable-zero-mad",
                    (50, 50, 50, 50, 50, 50, 50),
                    50,
                    False,
                ),
            )
        )
        self.assertEqual(result.case_count, 3)
        self.assertEqual(result.detection_rate, 1.0)
        self.assertEqual(result.false_positive_rate, 0.0)
        self.assertEqual(result.llm_calls, 0)
        self.assertEqual(result.evaluated_samples, 24)
        self.assertGreaterEqual(result.elapsed_ms, 0.0)


if __name__ == "__main__":
    unittest.main()
