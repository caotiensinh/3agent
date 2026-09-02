import json
import unittest

from three_agent.security_monitoring.ai_analyst import AIAnalysisResult
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.reporting import DeterministicReport, PeriodSummary
from three_agent.security_monitoring.soc_read_model import (
    MAX_SOC_EVIDENCE_REFS,
    MAX_SOC_FINDINGS,
    SOC_READ_MODEL_SCHEMA_VERSION,
    build_soc_read_model,
)

_VALID_SHA256 = "sha256:" + ("0" * 64)


def period(label="today", *, open_high_critical=1, data_gaps=0):
    return PeriodSummary(
        label=label,
        starts_at="2026-09-02T00:00:00+09:00",
        ends_at="2026-09-02T17:30:00+09:00",
        hourly_runs=17,
        average_coverage_pct=99.0,
        event_count=3,
        finding_count=1,
        open_high_critical=open_high_critical,
        severity_counts={"high": 1},
        finding_status_counts={"open": 1},
        data_gap_count=data_gaps,
        metric_summaries=(),
    )


def finding(index=0, *, evidence_refs=None):
    refs = list(evidence_refs) if evidence_refs is not None else [f"event:{index}:0"]
    return {
        "finding_id": f"F-{index}",
        "category": "network_instability",
        "severity": "high",
        "status": "open",
        "first_seen": "2026-09-02T12:00:00+09:00",
        "last_seen": "2026-09-02T12:05:00+09:00",
        "asset_refs": ["asset:secret-switch"],
        "evidence_refs": refs,
        "rule_id": "rule-network-instability",
    }


def report(*, findings=None, evidence_refs=None):
    source_findings = tuple(findings if findings is not None else [finding()])
    refs = tuple(
        evidence_refs
        if evidence_refs is not None
        else [
            ref
            for item in source_findings
            for ref in item["evidence_refs"]
        ]
    )
    return DeterministicReport(
        report_id="report-20260902-1730",
        cutoff_at="2026-09-02T17:30:00+09:00",
        generated_at="2026-09-02T17:30:01+09:00",
        today=period("today", open_high_critical=2, data_gaps=1),
        rolling_7d=period("rolling_7d", open_high_critical=4),
        rolling_30d=period("rolling_30d", open_high_critical=7),
        evidence_refs=refs,
        findings=source_findings,
    )


def analysis():
    return AIAnalysisResult(
        report_id="report-20260902-1730",
        status="valid",
        summary="Enterprise assessment.",
        items=(
            {
                "label": "FACT",
                "text": "Authentication evidence was observed.",
                "evidence_refs": ["event:0:0"],
            },
            {
                "label": "RISK",
                "text": "Review the correlated activity.",
                "evidence_refs": ["finding:F-0"],
            },
            {
                "label": "DATA GAP",
                "text": "Current monitoring has a coverage gap.",
                "evidence_refs": ["data-gap:today"],
            },
        ),
        evidence_pack_sha256=_VALID_SHA256,
        model_calls=1,
        retry_count=0,
        allowed_evidence_ids=("event:0:0", "finding:F-0", "data-gap:today"),
    ).validate()


class SOCReadModelTests(unittest.TestCase):
    def test_contract_exposes_bounded_read_only_soc_sections(self):
        payload = build_soc_read_model(report(), analysis=analysis())

        self.assertEqual(payload["schema_version"], SOC_READ_MODEL_SCHEMA_VERSION)
        self.assertEqual(
            set(payload),
            {
                "schema_version",
                "report_id",
                "cutoff_at",
                "generated_at",
                "overview",
                "risk_summary",
                "findings",
                "omitted_findings",
                "evidence_refs",
                "analyst_findings",
            },
        )
        self.assertEqual(payload["risk_summary"]["today_open_high_critical"], 2)
        self.assertEqual(payload["risk_summary"]["rolling_30d_open_high_critical"], 7)
        self.assertEqual(payload["risk_summary"]["today_data_gaps"], 1)

    def test_contract_drops_asset_identity_and_internal_ai_labels(self):
        payload = build_soc_read_model(report(), analysis=analysis())
        encoded = json.dumps(payload, sort_keys=True)

        self.assertNotIn("asset:secret-switch", encoded)
        self.assertNotIn('"asset_refs"', encoded)
        self.assertNotIn('"label"', encoded)
        self.assertNotIn('"allowed_evidence_ids"', encoded)
        for forbidden in ("authority", "command", "tool", "remediation", "mutation", "raw_log", "raw_message"):
            self.assertNotIn(f'"{forbidden}"', encoded)

    def test_contract_uses_only_enterprise_truth_states_and_preserves_evidence(self):
        payload = build_soc_read_model(report(), analysis=analysis())
        analyst_findings = payload["analyst_findings"]

        self.assertEqual(
            [item["truth_state"] for item in analyst_findings],
            ["VERIFIED FACT", "INFERENCE", "UNKNOWN"],
        )
        self.assertEqual(analyst_findings[0]["evidence_ids"], ["event:0:0"])

    def test_findings_and_evidence_are_hard_bounded_with_explicit_omission_count(self):
        many_findings = [finding(index, evidence_refs=[f"event:{index}:{n}" for n in range(20)]) for index in range(120)]
        many_evidence = [f"event:bulk:{index}" for index in range(MAX_SOC_EVIDENCE_REFS + 50)]
        payload = build_soc_read_model(report(findings=many_findings, evidence_refs=many_evidence))

        self.assertEqual(len(payload["findings"]), MAX_SOC_FINDINGS)
        self.assertEqual(payload["omitted_findings"], 20)
        self.assertLessEqual(len(payload["evidence_refs"]), MAX_SOC_EVIDENCE_REFS)
        self.assertTrue(all(len(item["evidence_refs"]) <= 16 for item in payload["findings"]))

    def test_fabricated_analyst_evidence_fails_closed_before_soc_projection(self):
        bad = AIAnalysisResult(
            report_id="report-20260902-1730",
            status="valid",
            summary="Bad assessment.",
            items=(
                {
                    "label": "FACT",
                    "text": "Fabricated fact.",
                    "evidence_refs": ["event:fabricated"],
                },
            ),
            evidence_pack_sha256=_VALID_SHA256,
            model_calls=1,
            retry_count=0,
            allowed_evidence_ids=("event:known",),
        )
        with self.assertRaises(MonitoringContractError):
            build_soc_read_model(report(), analysis=bad)

    def test_input_report_is_not_mutated(self):
        source = report()
        before_findings = tuple(dict(item) for item in source.findings)
        before_evidence = source.evidence_refs

        build_soc_read_model(source, analysis=analysis())

        self.assertEqual(source.findings, before_findings)
        self.assertEqual(source.evidence_refs, before_evidence)


if __name__ == "__main__":
    unittest.main()
