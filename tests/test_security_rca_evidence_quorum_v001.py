import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.rca_evidence_quorum import (
    RcaEvidenceQuorum,
    RcaEvidenceSignal,
)

E1 = "evidence:" + "1" * 24
E2 = "evidence:" + "2" * 24
E3 = "evidence:" + "3" * 24


class RcaEvidenceQuorumTests(unittest.TestCase):
    def test_two_independent_classes_support_hypothesis(self):
        result = RcaEvidenceQuorum.evaluate(
            hypothesis_ref="hypothesis:gateway-outage",
            signals=(
                RcaEvidenceSignal(E1, "reachability", "supports"),
                RcaEvidenceSignal(E2, "power", "supports"),
            ),
        )
        self.assertTrue(result.confirmed)
        self.assertEqual(result.status, "supported")
        self.assertEqual(result.distinct_supporting_classes, 2)
        self.assertEqual(result.validate(), result)

    def test_same_class_does_not_fake_independence(self):
        result = RcaEvidenceQuorum.evaluate(
            hypothesis_ref="hypothesis:gateway-outage",
            signals=(
                RcaEvidenceSignal(E1, "reachability", "supports"),
                RcaEvidenceSignal(E2, "reachability", "supports"),
            ),
        )
        self.assertFalse(result.confirmed)
        self.assertEqual(result.status, "insufficient_evidence")

    def test_any_contradiction_blocks_confirmation(self):
        result = RcaEvidenceQuorum.evaluate(
            hypothesis_ref="hypothesis:gateway-outage",
            signals=(
                RcaEvidenceSignal(E1, "reachability", "supports"),
                RcaEvidenceSignal(E2, "power", "supports"),
                RcaEvidenceSignal(E3, "config", "contradicts"),
            ),
        )
        self.assertFalse(result.confirmed)
        self.assertEqual(result.status, "contradicted")

    def test_duplicate_or_noncanonical_evidence_fails_closed(self):
        with self.assertRaisesRegex(MonitoringContractError, "unique"):
            RcaEvidenceQuorum.evaluate(
                hypothesis_ref="hypothesis:x",
                signals=(
                    RcaEvidenceSignal(E1, "a", "supports"),
                    RcaEvidenceSignal(E1, "b", "supports"),
                ),
            )
        with self.assertRaisesRegex(MonitoringContractError, "canonical"):
            RcaEvidenceSignal("finding:123", "a", "supports").validate()

    def test_string_threshold_is_not_accepted_as_integer(self):
        with self.assertRaisesRegex(MonitoringContractError, "min_supporting_evidence"):
            RcaEvidenceQuorum.evaluate(
                hypothesis_ref="hypothesis:x",
                signals=(RcaEvidenceSignal(E1, "a", "supports"),),
                min_supporting_evidence="1",  # type: ignore[arg-type]
                min_distinct_classes=1,
            )

    def test_forged_supported_status_cannot_bypass_quorum(self):
        valid = RcaEvidenceQuorum.evaluate(
            hypothesis_ref="hypothesis:x",
            signals=(RcaEvidenceSignal(E1, "reachability", "supports"),),
        )
        forged = replace(valid, status="supported")
        with self.assertRaisesRegex(MonitoringContractError, "status"):
            _ = forged.confirmed

    def test_forged_counts_and_authority_are_rejected(self):
        valid = RcaEvidenceQuorum.evaluate(
            hypothesis_ref="hypothesis:x",
            signals=(
                RcaEvidenceSignal(E1, "reachability", "supports"),
                RcaEvidenceSignal(E2, "power", "supports"),
            ),
        )
        with self.assertRaisesRegex(MonitoringContractError, "supporting_count"):
            replace(valid, supporting_count=99).validate()
        with self.assertRaisesRegex(MonitoringContractError, "advisory"):
            replace(valid, authority="mutation").validate()

    def test_forged_quorum_id_is_rejected(self):
        valid = RcaEvidenceQuorum.evaluate(
            hypothesis_ref="hypothesis:x",
            signals=(
                RcaEvidenceSignal(E1, "reachability", "supports"),
                RcaEvidenceSignal(E2, "power", "supports"),
            ),
        )
        with self.assertRaisesRegex(MonitoringContractError, "does not match"):
            replace(valid, quorum_id="rca-quorum:" + "0" * 24).validate()

    def test_signal_order_is_canonical(self):
        left = RcaEvidenceQuorum.evaluate(
            hypothesis_ref="hypothesis:x",
            signals=(
                RcaEvidenceSignal(E2, "power", "supports"),
                RcaEvidenceSignal(E1, "reachability", "supports"),
            ),
        )
        right = RcaEvidenceQuorum.evaluate(
            hypothesis_ref="hypothesis:x",
            signals=(
                RcaEvidenceSignal(E1, "reachability", "supports"),
                RcaEvidenceSignal(E2, "power", "supports"),
            ),
        )
        self.assertEqual(left.quorum_id, right.quorum_id)


if __name__ == "__main__":
    unittest.main()
