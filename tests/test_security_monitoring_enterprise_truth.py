import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.enterprise_truth import (
    ANALYST_LABEL_TO_ENTERPRISE_STATE,
    ENTERPRISE_TRUTH_STATES,
    EnterpriseFinding,
    map_analyst_finding,
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


class EnterpriseTruthMappingTests(unittest.TestCase):
    def test_internal_label_mapping_is_explicit_and_complete(self):
        self.assertEqual(
            ANALYST_LABEL_TO_ENTERPRISE_STATE,
            {
                "FACT": "VERIFIED FACT",
                "CORRELATION": "INFERENCE",
                "HYPOTHESIS": "INFERENCE",
                "RISK": "INFERENCE",
                "ACTION": "INFERENCE",
                "DATA GAP": "UNKNOWN",
            },
        )

    def test_fact_maps_to_verified_fact_and_preserves_evidence(self):
        finding = map_analyst_finding(
            label="FACT",
            statement="Authentication was observed.",
            evidence_ids=("event:auth-1", "finding:F-7"),
            allowed_evidence_ids=("event:auth-1", "finding:F-7"),
        )
        self.assertEqual(finding.truth_state, "VERIFIED FACT")
        self.assertEqual(finding.evidence_ids, ("event:auth-1", "finding:F-7"))

    def test_analytical_and_advisory_labels_map_to_inference(self):
        for label in ("CORRELATION", "HYPOTHESIS", "RISK", "ACTION"):
            with self.subTest(label=label):
                finding = map_analyst_finding(
                    label=label,
                    statement="Analyst interpretation.",
                    evidence_ids=("event:known",),
                    allowed_evidence_ids=("event:known",),
                )
                self.assertEqual(finding.truth_state, "INFERENCE")

    def test_data_gap_maps_to_unknown(self):
        finding = map_analyst_finding(
            label="DATA GAP",
            statement="Required evidence is unavailable.",
            evidence_ids=(),
            allowed_evidence_ids=(),
        )
        self.assertEqual(finding.truth_state, "UNKNOWN")

    def test_mapper_has_no_fallback_for_unknown_internal_labels(self):
        with self.assertRaises(MonitoringContractError):
            map_analyst_finding(
                label="OPINION",
                statement="Unsupported label.",
                evidence_ids=(),
                allowed_evidence_ids=(),
            )

    def test_fact_without_evidence_cannot_become_verified_fact(self):
        with self.assertRaises(MonitoringContractError):
            map_analyst_finding(
                label="FACT",
                statement="Uncited claim.",
                evidence_ids=(),
                allowed_evidence_ids=(),
            )

    def test_mapper_rejects_fabricated_evidence_reference(self):
        with self.assertRaises(MonitoringContractError):
            map_analyst_finding(
                label="FACT",
                statement="Claim with fabricated evidence.",
                evidence_ids=("event:fabricated",),
                allowed_evidence_ids=("event:known",),
            )

    def test_mapper_rejects_string_as_evidence_collection(self):
        with self.assertRaises(MonitoringContractError):
            map_analyst_finding(
                label="FACT",
                statement="Malformed evidence collection.",
                evidence_ids="event:known",
                allowed_evidence_ids=("event:known",),
            )


if __name__ == "__main__":
    unittest.main()
