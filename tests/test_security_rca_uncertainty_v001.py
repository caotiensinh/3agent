import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.rca_uncertainty import (
    RcaContradiction,
    RcaDataGap,
    RcaUncertaintyAssessment,
)

E1 = "evidence:" + "1" * 24
E2 = "evidence:" + "2" * 24


class RcaUncertaintyTests(unittest.TestCase):
    def test_clear_assessment_allows_confirmation_boundary(self):
        result = RcaUncertaintyAssessment.assess(hypothesis_ref="hypothesis:config-drift")
        self.assertEqual(result.status, "clear")
        self.assertTrue(result.can_claim_confirmed_root_cause)
        self.assertEqual(result.validate(), result)

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

    def test_forged_clear_status_cannot_bypass_data_gap(self):
        valid = RcaUncertaintyAssessment.assess(
            hypothesis_ref="hypothesis:power-loss",
            gaps=(RcaDataGap("power", "no_power_telemetry"),),
        )
        forged = replace(valid, status="clear")
        with self.assertRaisesRegex(MonitoringContractError, "status"):
            _ = forged.can_claim_confirmed_root_cause

    def test_forged_authority_is_rejected(self):
        valid = RcaUncertaintyAssessment.assess(hypothesis_ref="hypothesis:dns-failure")
        forged = replace(valid, authority="mutation")
        with self.assertRaisesRegex(MonitoringContractError, "advisory"):
            forged.validate()

    def test_forged_assessment_id_is_rejected(self):
        valid = RcaUncertaintyAssessment.assess(hypothesis_ref="hypothesis:dns-failure")
        forged = replace(valid, assessment_id="rca-uncertainty:" + "0" * 24)
        with self.assertRaisesRegex(MonitoringContractError, "does not match"):
            forged.validate()

    def test_public_dict_is_metadata_only_and_deterministic(self):
        left = RcaUncertaintyAssessment.assess(
            hypothesis_ref="hypothesis:config-drift",
            gaps=(
                RcaDataGap("power", "no_power_telemetry"),
                RcaDataGap("path", "missing_route_observation"),
            ),
        )
        right = RcaUncertaintyAssessment.assess(
            hypothesis_ref="hypothesis:config-drift",
            gaps=(
                RcaDataGap("path", "missing_route_observation"),
                RcaDataGap("power", "no_power_telemetry"),
            ),
        )
        self.assertEqual(left.assessment_id, right.assessment_id)
        payload = left.public_dict()
        self.assertEqual(payload["authority"], "advisory")
        self.assertNotIn("raw", payload)
        self.assertNotIn("credential", str(payload).lower())


if __name__ == "__main__":
    unittest.main()
