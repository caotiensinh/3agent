import unittest

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.rca_evidence_quorum import RcaEvidenceQuorum, RcaEvidenceSignal

E1 = "evidence:" + "1" * 24
E2 = "evidence:" + "2" * 24
E3 = "evidence:" + "3" * 24


class RcaEvidenceQuorumTests(unittest.TestCase):
    def test_two_independent_classes_support_hypothesis(self):
        result = RcaEvidenceQuorum.evaluate(
            hypothesis_ref="hypothesis:gateway-outage",
            signals=(RcaEvidenceSignal(E1, "reachability", "supports"), RcaEvidenceSignal(E2, "power", "supports")),
        )
        self.assertTrue(result.confirmed)
        self.assertEqual(result.status, "supported")
        self.assertEqual(result.distinct_supporting_classes, 2)

    def test_same_class_does_not_fake_independence(self):
        result = RcaEvidenceQuorum.evaluate(
            hypothesis_ref="hypothesis:gateway-outage",
            signals=(RcaEvidenceSignal(E1, "reachability", "supports"), RcaEvidenceSignal(E2, "reachability", "supports")),
        )
        self.assertFalse(result.confirmed)
        self.assertEqual(result.status, "insufficient_evidence")

    def test_any_contradiction_blocks_confirmation(self):
        result = RcaEvidenceQuorum.evaluate(
            hypothesis_ref="hypothesis:gateway-outage",
            signals=(RcaEvidenceSignal(E1, "reachability", "supports"), RcaEvidenceSignal(E2, "power", "supports"), RcaEvidenceSignal(E3, "config", "contradicts")),
        )
        self.assertFalse(result.confirmed)
        self.assertEqual(result.status, "contradicted")

    def test_duplicate_or_noncanonical_evidence_fails_closed(self):
        with self.assertRaisesRegex(MonitoringContractError, "unique"):
            RcaEvidenceQuorum.evaluate(
                hypothesis_ref="hypothesis:x",
                signals=(RcaEvidenceSignal(E1, "a", "supports"), RcaEvidenceSignal(E1, "b", "supports")),
            )
        with self.assertRaisesRegex(MonitoringContractError, "canonical"):
            RcaEvidenceSignal("finding:123", "a", "supports").validate()


if __name__ == "__main__":
    unittest.main()
