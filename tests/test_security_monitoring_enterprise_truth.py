import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.enterprise_truth import (
    ENTERPRISE_TRUTH_STATES,
    EnterpriseFinding,
)


class EnterpriseTruthContractTests(unittest.TestCase):
    def test_contract_exposes_exactly_three_enterprise_truth_states(self):
        self.assertEqual(
            ENTERPRISE_TRUTH_STATES,
            ("VERIFIED FACT", "INFERENCE", "UNKNOWN"),
        )

    def test_verified_fact_requires_known_evidence_and_preserves_references(self):
        finding = EnterpriseFinding(
            truth_state="VERIFIED FACT",
            statement="Authentication was observed.",
            evidence_ids=("event:auth-1", "finding:F-7"),
        ).validate(
            allowed_evidence_ids=("event:auth-1", "finding:F-7", "event:other")
        )
        self.assertEqual(
            finding.public_dict(),
            {
                "truth_state": "VERIFIED FACT",
                "statement": "Authentication was observed.",
                "evidence_ids": ["event:auth-1", "finding:F-7"],
            },
        )

    def test_verified_fact_without_evidence_fails_closed(self):
        with self.assertRaises(MonitoringContractError):
            EnterpriseFinding(
                truth_state="VERIFIED FACT",
                statement="Uncited claim.",
            ).validate(allowed_evidence_ids=())

    def test_unknown_evidence_reference_fails_closed(self):
        with self.assertRaises(MonitoringContractError):
            EnterpriseFinding(
                truth_state="INFERENCE",
                statement="Possible relationship.",
                evidence_ids=("event:fabricated",),
            ).validate(allowed_evidence_ids=("event:known",))

    def test_invalid_truth_state_is_rejected(self):
        with self.assertRaises(MonitoringContractError):
            EnterpriseFinding(
                truth_state="FACT",
                statement="Internal labels are not enterprise truth states.",
                evidence_ids=("event:known",),
            ).validate(allowed_evidence_ids=("event:known",))

    def test_inference_and_unknown_can_represent_uncertainty_without_evidence(self):
        for state in ("INFERENCE", "UNKNOWN"):
            finding = EnterpriseFinding(
                truth_state=state,
                statement="Evidence is insufficient.",
            ).validate(allowed_evidence_ids=())
            self.assertEqual(finding.evidence_ids, ())

    def test_public_contract_cannot_mint_execution_authority(self):
        finding = EnterpriseFinding(
            truth_state="UNKNOWN",
            statement="No verified conclusion.",
        ).validate(allowed_evidence_ids=())
        public = finding.public_dict()
        self.assertEqual(set(public), {"truth_state", "statement", "evidence_ids"})
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


if __name__ == "__main__":
    unittest.main()
