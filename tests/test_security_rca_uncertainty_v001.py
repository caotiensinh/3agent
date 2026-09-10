import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.rca_uncertainty import RcaContradiction, RcaDataGap, RcaUncertaintyAssessment

E1 = "evidence:" + "1" * 24
E2 = "evidence:" + "2" * 24


class RcaUncertaintyTests(unittest.TestCase):
    def test_clear_assessment_allows_confirmation_boundary(self):
        result = RcaUncertaintyAssessment.assess(hypothesis_ref="hypothesis:config-drift")
        self.assertEqual(result.status, "clear")
        self.assertTrue(result.can_claim_confirmed_root_cause)

    def test_data_gap_blocks_confirmed_claim(self):
        result = RcaUncertaintyAssessment.assess(
            hypothesis_ref="hypothesis:config-drift",
            gaps=(RcaDataGap("power", "no_power_telemetry"),),
        )
        self.assertEqual(result.status, "data_gap")
        self.assertFalse(result.can_claim_confirmed_root_cause)

    def test_contradiction_has_priority_over_gap(self):
        result = RcaUncertaintyAssessment.assess(
            hypothesis_ref="hypothesis:config-drift",
            gaps=(RcaDataGap("path", "missing_route_observation"),),
            contradictions=(RcaContradiction(E1, E2, "reachability"),),
        )
        self.assertEqual(result.status, "contradicted")
        self.assertFalse(result.can_claim_confirmed_root_cause)

    def test_same_evidence_cannot_contradict_itself(self):
        with self.assertRaisesRegex(MonitoringContractError, "distinct"):
            RcaContradiction(E1, E1, "path").validate()


if __name__ == "__main__":
    unittest.main()
