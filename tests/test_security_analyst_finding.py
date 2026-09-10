import unittest
from dataclasses import replace

from three_agent.security_monitoring.analyst_finding import (
    DEFAULT_PROHIBITED_AUTOMATIC_ACTIONS,
    AnalystFinding,
    AnalystFindingError,
)
from three_agent.security_monitoring.evidence_lineage import EvidenceLineageReceipt
from three_agent.security_monitoring.normalized_evidence import EvidenceObservationWindow

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
SHA_E = "sha256:" + "e" * 64
EVIDENCE_1 = "evidence:" + "1" * 24
EVIDENCE_2 = "evidence:" + "2" * 24
EVIDENCE_3 = "evidence:" + "3" * 24


class AnalystFindingTests(unittest.TestCase):
    @staticmethod
    def _receipt(*, evidence_ids=(EVIDENCE_1, EVIDENCE_2)):
        return EvidenceLineageReceipt(
            task_ref_sha256=SHA_A,
            policy_fingerprint=SHA_B,
            evidence_batch_fingerprint=SHA_C,
            evidence_ids=tuple(evidence_ids),
            evidence_count=len(tuple(evidence_ids)),
        ).validate()

    @classmethod
    def _finding(cls, **overrides):
        values = {
            "observed_facts": ("DNS resolver returned repeated SERVFAIL responses.",),
            "derived_indicators": ("Resolver failure ratio exceeds the reviewed baseline.",),
            "hypotheses": ("Upstream DNS dependency may be degraded.",),
            "confidence": 0.82,
            "supporting_evidence_ids": (EVIDENCE_1,),
            "conflicting_evidence_ids": (EVIDENCE_2,),
            "recommended_human_actions": (
                "Review upstream DNS health and approved resolver telemetry.",
            ),
            "affected_refs": ("asset:edge-router-01", "service:dns"),
            "severity": "medium",
            "risk_classification": "availability",
            "created_at": "2026-09-02T09:01:00+00:00",
            "observation_window": EvidenceObservationWindow(
                "2026-09-02T09:00:00+00:00",
                "2026-09-02T09:00:59+00:00",
            ),
            "task_ref_sha256": SHA_A,
            "audit_record_sha256": SHA_D,
            "lineage_receipt": cls._receipt(),
        }
        values.update(overrides)
        return AnalystFinding.create(**values)

    def test_valid_finding_is_deterministic_and_keeps_fact_hypothesis_separation(self):
        first = self._finding()
        second = self._finding()
        self.assertEqual(first.finding_id, second.finding_id)
        self.assertEqual(first.identity_sha256, second.identity_sha256)
        self.assertEqual(first.canonical_json(), second.canonical_json())
        self.assertNotEqual(first.observed_facts, first.hypotheses)
        self.assertEqual(first.prohibited_automatic_actions, DEFAULT_PROHIBITED_AUTOMATIC_ACTIONS)
        self.assertFalse(first.lineage_receipt.automatic_action_allowed)
        self.assertEqual(first.lineage_receipt.authority, "advisory")

    def test_finding_without_supporting_evidence_fails_closed(self):
        with self.assertRaisesRegex(AnalystFindingError, "supporting_evidence_ids is required"):
            self._finding(supporting_evidence_ids=())

    def test_hypothesis_cannot_be_represented_as_observed_fact(self):
        statement = "Unexpected authentication failures were observed."
        with self.assertRaisesRegex(AnalystFindingError, "hypothesis must not be represented as an observed fact"):
            self._finding(observed_facts=(statement,), hypotheses=(statement,))

    def test_hypothesis_cannot_be_represented_as_derived_indicator(self):
        statement = "A lateral movement pattern may be present."
        with self.assertRaisesRegex(AnalystFindingError, "hypothesis must remain separate"):
            self._finding(derived_indicators=(statement,), hypotheses=(statement,))

    def test_conflicting_evidence_is_explicitly_supported_when_in_validated_lineage(self):
        finding = self._finding(conflicting_evidence_ids=(EVIDENCE_2,))
        self.assertEqual(finding.conflicting_evidence_ids, (EVIDENCE_2,))
        self.assertNotEqual(finding.supporting_evidence_ids, finding.conflicting_evidence_ids)

    def test_supporting_evidence_missing_from_lineage_fails_closed(self):
        with self.assertRaisesRegex(AnalystFindingError, "supporting evidence is missing from validated lineage"):
            self._finding(supporting_evidence_ids=(EVIDENCE_3,))

    def test_conflicting_evidence_missing_from_lineage_fails_closed(self):
        with self.assertRaisesRegex(AnalystFindingError, "conflicting evidence is missing from validated lineage"):
            self._finding(conflicting_evidence_ids=(EVIDENCE_3,))

    def test_supporting_and_conflicting_evidence_must_be_disjoint(self):
        with self.assertRaisesRegex(AnalystFindingError, "supporting and conflicting evidence must be disjoint"):
            self._finding(conflicting_evidence_ids=(EVIDENCE_1,))

    def test_task_must_match_validated_lineage_receipt(self):
        with self.assertRaisesRegex(AnalystFindingError, "finding task does not match evidence lineage task"):
            self._finding(task_ref_sha256=SHA_E)

    def test_audit_linkage_is_required_and_must_be_sha256(self):
        with self.assertRaisesRegex(AnalystFindingError, "audit_record_sha256"):
            self._finding(audit_record_sha256="")
        with self.assertRaisesRegex(AnalystFindingError, "audit_record_sha256"):
            self._finding(audit_record_sha256="sha256:not-valid")

    def test_prohibited_automatic_action_boundary_cannot_be_weakened(self):
        finding = self._finding()
        weakened = replace(
            finding,
            prohibited_automatic_actions=DEFAULT_PROHIBITED_AUTOMATIC_ACTIONS[:-1],
        )
        with self.assertRaisesRegex(AnalystFindingError, "cannot be weakened"):
            weakened.validate()

    def test_created_at_cannot_precede_observation_window_end(self):
        with self.assertRaisesRegex(AnalystFindingError, "created_at cannot precede"):
            self._finding(created_at="2026-09-02T09:00:30+00:00")

    def test_invalid_severity_and_risk_classification_fail_closed(self):
        with self.assertRaisesRegex(AnalystFindingError, "severity"):
            self._finding(severity="emergency")
        with self.assertRaisesRegex(AnalystFindingError, "risk classification"):
            self._finding(risk_classification="offensive")

    def test_confidence_boolean_or_out_of_range_fails_closed(self):
        with self.assertRaisesRegex(AnalystFindingError, "confidence"):
            self._finding(confidence=True)
        with self.assertRaisesRegex(AnalystFindingError, "confidence"):
            self._finding(confidence=1.01)

    def test_tampered_finding_id_fails_closed(self):
        finding = self._finding()
        tampered = replace(finding, finding_id="finding:" + "f" * 24)
        with self.assertRaisesRegex(AnalystFindingError, "finding_id does not match"):
            tampered.validate()

    def test_statements_are_bounded_single_line_values(self):
        with self.assertRaisesRegex(AnalystFindingError, "single-line"):
            self._finding(hypotheses=("first line\nsecond line",))
        with self.assertRaisesRegex(AnalystFindingError, "bounded"):
            self._finding(hypotheses=("X" * 513,))


if __name__ == "__main__":
    unittest.main()
