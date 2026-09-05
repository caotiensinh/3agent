import json
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.ai_analyst import (
    AI_ENTERPRISE_ANALYSIS_SCHEMA_VERSION,
    AIAnalysisResult,
    write_ai_analysis_sidecar,
)
from three_agent.security_monitoring.contracts import MonitoringContractError


_VALID_SHA256 = "sha256:" + ("0" * 64)


def valid_result(*, items, allowed_evidence_ids):
    return AIAnalysisResult(
        report_id="report-enterprise-boundary",
        status="valid",
        summary="Validated enterprise analyst boundary.",
        items=tuple(dict(item) for item in items),
        evidence_pack_sha256=_VALID_SHA256,
        model_calls=1,
        retry_count=0,
        allowed_evidence_ids=tuple(allowed_evidence_ids),
    )


class EnterpriseAIOutputBoundaryTests(unittest.TestCase):
    def test_public_boundary_exposes_only_three_state_findings(self):
        result = valid_result(
            items=(
                {
                    "label": "FACT",
                    "text": "Authentication was observed.",
                    "evidence_refs": ["event:auth-1"],
                },
                {
                    "label": "RISK",
                    "text": "Review the correlated path.",
                    "evidence_refs": ["finding:F-1"],
                },
                {
                    "label": "DATA GAP",
                    "text": "The current monitoring window has a gap.",
                    "evidence_refs": ["data-gap:today"],
                },
            ),
            allowed_evidence_ids=("event:auth-1", "finding:F-1", "data-gap:today"),
        ).validate()

        public = result.public_dict()
        self.assertEqual(public["schema_version"], AI_ENTERPRISE_ANALYSIS_SCHEMA_VERSION)
        self.assertEqual(
            [item["truth_state"] for item in public["findings"]],
            ["VERIFIED FACT", "INFERENCE", "UNKNOWN"],
        )
        self.assertEqual(public["findings"][0]["evidence_ids"], ["event:auth-1"])
        self.assertNotIn("items", public)
        self.assertNotIn("allowed_evidence_ids", public)

    def test_public_boundary_does_not_leak_internal_labels_or_mint_authority(self):
        result = valid_result(
            items=(
                {
                    "label": "ACTION",
                    "text": "Review the cited evidence manually.",
                    "evidence_refs": ["finding:F-1"],
                },
            ),
            allowed_evidence_ids=("finding:F-1",),
        ).validate()
        public = result.public_dict()
        encoded = json.dumps(public, sort_keys=True)
        self.assertNotIn('"label"', encoded)
        self.assertNotIn('"allowed_evidence_ids"', encoded)
        self.assertEqual(public["findings"][0]["truth_state"], "INFERENCE")
        for forbidden in (
            "authority",
            "command",
            "tool",
            "remediation",
            "execute",
            "policy",
            "inventory",
            "severity",
        ):
            self.assertNotIn(forbidden, public)
            self.assertNotIn(forbidden, public["findings"][0])

    def test_fabricated_evidence_reference_fails_closed_at_result_boundary(self):
        result = valid_result(
            items=(
                {
                    "label": "FACT",
                    "text": "Fabricated claim.",
                    "evidence_refs": ["event:fabricated"],
                },
            ),
            allowed_evidence_ids=("event:known",),
        )
        with self.assertRaises(MonitoringContractError):
            result.validate()

    def test_fact_without_evidence_cannot_cross_public_boundary(self):
        result = valid_result(
            items=(
                {
                    "label": "FACT",
                    "text": "Uncited claim.",
                    "evidence_refs": [],
                },
            ),
            allowed_evidence_ids=(),
        )
        with self.assertRaises(MonitoringContractError):
            result.public_dict()

    def test_sidecar_serializes_enterprise_boundary_only(self):
        result = valid_result(
            items=(
                {
                    "label": "FACT",
                    "text": "Authentication was observed.",
                    "evidence_refs": ["event:auth-1"],
                },
            ),
            allowed_evidence_ids=("event:auth-1",),
        ).validate()
        with tempfile.TemporaryDirectory() as tmp:
            path = write_ai_analysis_sidecar(result, root=Path(tmp).resolve())
            payload = json.loads(path.read_text(encoding="utf-8"))

        self.assertEqual(payload["schema_version"], AI_ENTERPRISE_ANALYSIS_SCHEMA_VERSION)
        self.assertEqual(payload["findings"][0]["truth_state"], "VERIFIED FACT")
        self.assertEqual(payload["findings"][0]["evidence_ids"], ["event:auth-1"])
        self.assertNotIn("items", payload)
        self.assertNotIn("allowed_evidence_ids", payload)
        self.assertNotIn("label", payload["findings"][0])

    def test_fallback_sidecar_has_no_enterprise_findings(self):
        result = AIAnalysisResult(
            report_id="report-fallback",
            status="fallback",
            summary="Deterministic report retained.",
            items=(),
            evidence_pack_sha256=_VALID_SHA256,
            model_calls=1,
            retry_count=0,
            failure_code="AI_UNAVAILABLE",
        ).validate()
        public = result.public_dict()
        self.assertEqual(public["findings"], [])
        self.assertNotIn("allowed_evidence_ids", public)


if __name__ == "__main__":
    unittest.main()
