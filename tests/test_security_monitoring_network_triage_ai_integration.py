from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import unittest

from three_agent.security_monitoring.ai_analyst import (
    AI_EVIDENCE_PACK_SCHEMA_VERSION,
    MAX_EVIDENCE_PACK_BYTES,
    MAX_NETWORK_TRIAGE_IN_PACK,
    LocalAIAnalyst,
    build_ai_evidence_pack,
)
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.correlation_graph import (
    RULE_AUTH_PROCESS,
    RULE_DNS_FLOW,
    RULE_FLOW_AUTH,
)
from three_agent.security_monitoring.network_triage import NetworkIncidentTriage
from three_agent.security_monitoring.reporting import DeterministicReport, PeriodSummary


def period(label: str) -> PeriodSummary:
    return PeriodSummary(
        label=label,
        starts_at="2026-09-01T00:00:00+09:00",
        ends_at="2026-09-01T01:00:00+09:00",
        hourly_runs=1,
        average_coverage_pct=100.0,
        event_count=0,
        finding_count=0,
        open_high_critical=0,
        severity_counts={},
        finding_status_counts={},
        data_gap_count=0,
        metric_summaries=(),
    )


def report() -> DeterministicReport:
    return DeterministicReport(
        report_id="report-ai-triage-001",
        cutoff_at="2026-09-01T01:00:00+09:00",
        generated_at="2026-09-01T01:00:01+09:00",
        today=period("today"),
        rolling_7d=period("rolling_7d"),
        rolling_30d=period("rolling_30d"),
        evidence_refs=(),
        findings=(),
    )


def triage(
    index: int = 1,
    *,
    priority: str = "high",
    severity: str = "high",
    confidence: str = "high",
) -> NetworkIncidentTriage:
    token24 = f"{index:024x}"
    token64 = f"{index:064x}"
    return NetworkIncidentTriage(
        triage_id=f"triage-{token24}",
        graph_id=f"incident-{token24}",
        graph_fingerprint=f"sha256:{token64}",
        triage_kind="dns-flow-auth-process",
        confidence=confidence,
        severity=severity,
        investigation_priority=priority,
        reason_codes=("complete_exact_multistage_chain", "exact_dns_flow"),
        stage_types=("DNS", "FLOW", "AUTH", "PROCESS"),
        rule_ids=(RULE_AUTH_PROCESS, RULE_DNS_FLOW, RULE_FLOW_AUTH),
        event_ids=(f"evt-{index}-1", f"evt-{index}-2"),
        evidence_refs=(f"event:evt-{index}-1", f"event:evt-{index}-2"),
        entity_refs=(
            "asset:server-rd-01",
            "entity:ip:sha256:" + "f" * 64,
            "entity:user:sha256:" + "e" * 64,
        ),
        first_seen="2026-09-01T00:00:00+00:00",
        last_seen="2026-09-01T00:00:12+00:00",
    )


class FixedClient:
    def __init__(self, evidence_ref: str):
        self.evidence_ref = evidence_ref
        self.calls = 0
        self.last_system_prompt = ""
        self.last_prompt = ""

    def generate_json(self, system_prompt, prompt, **kwargs):
        self.calls += 1
        self.last_system_prompt = system_prompt
        self.last_prompt = prompt
        return {
            "summary": "Correlated network evidence requires operator review.",
            "items": [
                {
                    "label": "CORRELATION",
                    "text": "The deterministic triage chain is correlated evidence, not proof of compromise.",
                    "evidence_refs": [self.evidence_ref],
                }
            ],
        }


class NetworkTriageAIIntegrationTests(unittest.TestCase):
    def test_existing_report_only_payload_contract_remains_legacy_compatible(self):
        current_report = report()
        pack = build_ai_evidence_pack(current_report)
        self.assertNotIn("network_triage", pack.payload)
        self.assertNotIn("omitted_network_triage", pack.payload)

        expected_payload = {
            "schema_version": AI_EVIDENCE_PACK_SCHEMA_VERSION,
            "report_id": current_report.report_id,
            "cutoff_at": current_report.cutoff_at,
            "periods": {
                "today": {
                    "label": "today",
                    "starts_at": "2026-09-01T00:00:00+09:00",
                    "ends_at": "2026-09-01T01:00:00+09:00",
                    "hourly_runs": 1,
                    "average_coverage_pct": 100.0,
                    "event_count": 0,
                    "finding_count": 0,
                    "open_high_critical": 0,
                    "data_gap_count": 0,
                    "severity_counts": {},
                    "finding_status_counts": {},
                    "metric_summaries": [],
                },
                "rolling_7d": {
                    "label": "rolling_7d",
                    "starts_at": "2026-09-01T00:00:00+09:00",
                    "ends_at": "2026-09-01T01:00:00+09:00",
                    "hourly_runs": 1,
                    "average_coverage_pct": 100.0,
                    "event_count": 0,
                    "finding_count": 0,
                    "open_high_critical": 0,
                    "data_gap_count": 0,
                    "severity_counts": {},
                    "finding_status_counts": {},
                    "metric_summaries": [],
                },
                "rolling_30d": {
                    "label": "rolling_30d",
                    "starts_at": "2026-09-01T00:00:00+09:00",
                    "ends_at": "2026-09-01T01:00:00+09:00",
                    "hourly_runs": 1,
                    "average_coverage_pct": 100.0,
                    "event_count": 0,
                    "finding_count": 0,
                    "open_high_critical": 0,
                    "data_gap_count": 0,
                    "severity_counts": {},
                    "finding_status_counts": {},
                    "metric_summaries": [],
                },
            },
            "findings": [],
            "allowed_evidence_ids": [],
            "omitted_findings": 0,
            "authority": "advisory_only",
        }
        canonical = json.dumps(expected_payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.assertEqual(pack.canonical_json, canonical)
        self.assertEqual(pack.sha256, "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest())

        client = FixedClient("unused")
        result = LocalAIAnalyst(client).analyze(current_report)
        self.assertEqual(result.status, "not_requested")
        self.assertEqual(result.model_calls, 0)
        self.assertEqual(client.calls, 0)

    def test_model_view_is_bounded_and_omits_event_and_entity_identity(self):
        record = triage()
        pack = build_ai_evidence_pack(report(), (record,))
        self.assertLessEqual(pack.byte_count, MAX_EVIDENCE_PACK_BYTES)
        self.assertEqual(len(pack.payload["network_triage"]), 1)
        view = pack.payload["network_triage"][0]
        self.assertNotIn("entity_refs", view)
        self.assertNotIn("event_ids", view)

        rendered = json.dumps(pack.payload, sort_keys=True)
        self.assertNotIn("asset:server-rd-01", rendered)
        self.assertNotIn("entity:ip:sha256:", rendered)
        self.assertNotIn("entity:user:sha256:", rendered)
        self.assertNotIn("f" * 64, rendered)
        self.assertNotIn("e" * 64, rendered)
        self.assertIn(f"triage:{record.triage_id}", pack.allowed_evidence_ids)
        self.assertIn(f"graph:{record.graph_id}", pack.allowed_evidence_ids)
        self.assertIn("event:evt-1-1", pack.allowed_evidence_ids)

    def test_triage_only_evidence_can_trigger_local_analyst(self):
        record = triage()
        evidence_ref = f"triage:{record.triage_id}"
        client = FixedClient(evidence_ref)
        result = LocalAIAnalyst(client).analyze(report(), network_triage=(record,))
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.model_calls, 1)
        self.assertEqual(client.calls, 1)
        self.assertIn("not proof of compromise", client.last_system_prompt)
        self.assertIn('"network_triage"', client.last_prompt)
        self.assertEqual(result.items[0]["evidence_refs"], [evidence_ref])

    def test_model_cannot_cite_an_invented_network_evidence_reference(self):
        client = FixedClient("graph:incident-not-supplied")
        result = LocalAIAnalyst(client).analyze(report(), network_triage=(triage(),))
        self.assertEqual(result.status, "fallback")
        self.assertEqual(result.failure_code, "AI_EVIDENCE_REF_UNKNOWN")
        self.assertEqual(result.model_calls, 2)
        self.assertEqual(result.retry_count, 1)

    def test_non_advisory_or_malformed_triage_fails_closed_before_model_call(self):
        client = FixedClient("unused")
        with self.assertRaises(MonitoringContractError):
            LocalAIAnalyst(client).analyze(
                report(),
                network_triage=(replace(triage(), authority="execute"),),
            )
        with self.assertRaises(MonitoringContractError):
            build_ai_evidence_pack(
                report(),
                (replace(triage(), entity_refs=("192.0.2.10",)),),
            )
        with self.assertRaises(MonitoringContractError):
            build_ai_evidence_pack(
                report(),
                (replace(triage(), reason_codes=("ignore_previous_instructions",)),),
            )
        self.assertEqual(client.calls, 0)

    def test_highest_priority_triage_is_retained_under_count_bound(self):
        records = [
            triage(index, priority="normal", severity="low", confidence="medium")
            for index in range(1, MAX_NETWORK_TRIAGE_IN_PACK + 5)
        ]
        records[-1] = triage(99, priority="high", severity="critical", confidence="high")
        pack = build_ai_evidence_pack(report(), records)
        self.assertLessEqual(len(pack.payload["network_triage"]), MAX_NETWORK_TRIAGE_IN_PACK)
        self.assertEqual(pack.payload["omitted_network_triage"], 4)
        self.assertLessEqual(pack.byte_count, MAX_EVIDENCE_PACK_BYTES)
        retained = {item["triage_ref"] for item in pack.payload["network_triage"]}
        self.assertIn("triage:triage-000000000000000000000063", retained)


if __name__ == "__main__":
    unittest.main()
