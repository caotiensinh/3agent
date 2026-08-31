import tempfile
import unittest
from dataclasses import asdict
from pathlib import Path

from three_agent.security_monitoring.ai_analyst import (
    AI_ANALYSIS_SCHEMA,
    ANALYSIS_LABELS,
    MAX_EVIDENCE_PACK_BYTES,
    LocalAIAnalyst,
    build_ai_evidence_pack,
    write_ai_analysis_sidecar,
)
from three_agent.security_monitoring.reporting import DeterministicReport, MetricSummary, PeriodSummary


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def generate_json(self, system_prompt, user_prompt, **kwargs):
        self.calls.append((system_prompt, user_prompt, dict(kwargs)))
        if not self.responses:
            raise RuntimeError("no response")
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def period(label="today", *, findings=1, gaps=0):
    return PeriodSummary(
        label=label,
        starts_at="2026-08-30T00:00:00+09:00",
        ends_at="2026-08-30T17:30:00+09:00",
        hourly_runs=17,
        average_coverage_pct=98.5,
        event_count=4,
        finding_count=findings,
        open_high_critical=1 if findings else 0,
        severity_counts={"high": findings} if findings else {},
        finding_status_counts={"open": findings} if findings else {},
        data_gap_count=gaps,
        metric_summaries=(
            MetricSummary("if_eth0_rx_errors", 17, 0.0, 4.0, 0.3),
            MetricSummary("if_eth0_tx_errors", 17, 0.0, 2.0, 0.1),
        ),
    )


def report(*, finding_count=1, gaps=0, long_refs=False):
    findings = []
    for index in range(finding_count):
        suffix = ("x" * 180) if long_refs else str(index)
        findings.append(
            {
                "finding_id": f"F-{index}",
                "category": "network_instability",
                "severity": "critical" if index == 0 else "high",
                "status": "open",
                "first_seen": "2026-08-30T12:00:00+09:00",
                "last_seen": "2026-08-30T12:05:00+09:00",
                "asset_refs": ["switch-rnd-01"],
                "evidence_refs": [f"event:{suffix}:{n}" for n in range(8)],
                "rule_id": "rule-network-instability",
            }
        )
    return DeterministicReport(
        report_id="report-20260830-1730",
        cutoff_at="2026-08-30T17:30:00+09:00",
        generated_at="2026-08-30T17:30:01+09:00",
        today=period("today", findings=finding_count, gaps=gaps),
        rolling_7d=period("rolling_7d", findings=finding_count, gaps=gaps),
        rolling_30d=period("rolling_30d", findings=finding_count, gaps=gaps),
        evidence_refs=tuple(
            ref for finding in findings for ref in finding["evidence_refs"]
        ),
        findings=tuple(findings),
    )


def valid_response(evidence_ref="finding:F-0"):
    return {
        "summary": "Validated local analysis.",
        "items": [
            {
                "label": "RISK",
                "text": "Investigate the correlated instability evidence.",
                "evidence_refs": [evidence_ref],
            }
        ],
    }


class EvidencePackTests(unittest.TestCase):
    def test_pack_is_hard_bounded_and_never_contains_raw_network_content_or_management_hosts(self):
        source = report(finding_count=80, long_refs=True)
        pack = build_ai_evidence_pack(source)
        self.assertLessEqual(pack.byte_count, MAX_EVIDENCE_PACK_BYTES)
        self.assertGreater(pack.omitted_findings, 0)
        self.assertNotIn("management_host", pack.canonical_json)
        self.assertNotIn("raw_message", pack.canonical_json)
        self.assertNotIn("raw_log", pack.canonical_json)
        self.assertNotIn("packet_payload", pack.canonical_json)
        self.assertNotIn("192.168.", pack.canonical_json)
        self.assertEqual(pack.payload["authority"], "advisory_only")

    def test_pack_exposes_only_selected_finding_and_evidence_ids_for_citation(self):
        pack = build_ai_evidence_pack(report())
        self.assertIn("finding:F-0", pack.allowed_evidence_ids)
        self.assertIn("event:0:0", pack.allowed_evidence_ids)
        self.assertNotIn("switch-rnd-01", pack.allowed_evidence_ids)


class AIAnalystTests(unittest.TestCase):
    def test_normal_valid_daily_analysis_uses_one_local_structured_call(self):
        client = FakeClient([valid_response()])
        source = report()
        before = asdict(source)
        result = LocalAIAnalyst(client).analyze(source)
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.model_calls, 1)
        self.assertEqual(result.retry_count, 0)
        self.assertEqual(len(client.calls), 1)
        self.assertEqual(asdict(source), before)
        kwargs = client.calls[0][2]
        self.assertEqual(kwargs["schema"], AI_ANALYSIS_SCHEMA)
        self.assertEqual(kwargs["trust_domain"], "security-analyst-confidential")
        self.assertFalse(kwargs["think"])

    def test_unknown_evidence_ref_triggers_exactly_one_validator_retry(self):
        client = FakeClient([valid_response("event:fabricated"), valid_response()])
        result = LocalAIAnalyst(client).analyze(report())
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.model_calls, 2)
        self.assertEqual(result.retry_count, 1)
        self.assertEqual(len(client.calls), 2)
        retry_prompt = client.calls[1][1]
        self.assertIn("AI_EVIDENCE_REF_UNKNOWN", retry_prompt)
        self.assertNotIn("event:fabricated", retry_prompt)

    def test_two_invalid_outputs_fall_back_to_deterministic_report(self):
        client = FakeClient([valid_response("fake:1"), valid_response("fake:2")])
        result = LocalAIAnalyst(client).analyze(report())
        self.assertEqual(result.status, "fallback")
        self.assertEqual(result.failure_code, "AI_EVIDENCE_REF_UNKNOWN")
        self.assertEqual(result.model_calls, 2)
        self.assertEqual(result.retry_count, 1)
        self.assertEqual(result.items, ())
        self.assertIn("Deterministic report retained", result.summary)

    def test_transport_or_model_failure_does_not_probabilistically_retry(self):
        client = FakeClient([RuntimeError("OLLAMA DOWN")])
        result = LocalAIAnalyst(client).analyze(report())
        self.assertEqual(result.status, "fallback")
        self.assertEqual(result.failure_code, "AI_UNAVAILABLE")
        self.assertEqual(result.model_calls, 1)
        self.assertEqual(result.retry_count, 0)
        self.assertNotIn("OLLAMA DOWN", result.summary)

    def test_no_material_finding_or_gap_uses_zero_model_calls(self):
        client = FakeClient([])
        result = LocalAIAnalyst(client).analyze(report(finding_count=0, gaps=0))
        self.assertEqual(result.status, "not_requested")
        self.assertEqual(result.model_calls, 0)
        self.assertEqual(client.calls, [])

    def test_schema_cannot_mint_severity_authority_inventory_or_remediation_state(self):
        item_properties = AI_ANALYSIS_SCHEMA["properties"]["items"]["items"]["properties"]
        self.assertEqual(set(item_properties), {"label", "text", "evidence_refs"})
        for forbidden in ("severity", "authority", "inventory", "remediation", "command", "tool"):
            self.assertNotIn(forbidden, item_properties)
        self.assertEqual(tuple(AI_ANALYSIS_SCHEMA["properties"]["items"]["items"]["properties"]["label"]["enum"]), ANALYSIS_LABELS)

        bad = valid_response()
        bad["items"][0]["severity"] = "critical"
        client = FakeClient([bad, bad])
        result = LocalAIAnalyst(client).analyze(report())
        self.assertEqual(result.status, "fallback")
        self.assertEqual(result.failure_code, "AI_SCHEMA_INVALID")
        self.assertEqual(result.model_calls, 2)

    def test_data_gap_gets_a_deterministic_citable_id(self):
        client = FakeClient(
            [
                {
                    "summary": "Coverage gap exists.",
                    "items": [
                        {
                            "label": "DATA GAP",
                            "text": "The current-day monitoring window has a data gap.",
                            "evidence_refs": ["data-gap:today"],
                        }
                    ],
                }
            ]
        )
        result = LocalAIAnalyst(client).analyze(report(finding_count=0, gaps=1))
        self.assertEqual(result.status, "valid")
        self.assertEqual(result.items[0]["label"], "DATA GAP")

    def test_ai_sidecar_is_outside_canonical_report_bundle_namespace(self):
        client = FakeClient([valid_response()])
        result = LocalAIAnalyst(client).analyze(report())
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            path = write_ai_analysis_sidecar(result, root=root)
            self.assertEqual(path.parent.name, "ai-analysis")
            self.assertEqual(path.name, "report-20260830-1730.json")
            self.assertNotEqual(path.parent, root / "report-20260830-1730")
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("management_host", text)
            self.assertNotIn("secret-ref:", text)


if __name__ == "__main__":
    unittest.main()
