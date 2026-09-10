from __future__ import annotations

import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.forensic_evidence import EvidenceReference
from three_agent.security_monitoring.forensic_hypothesis import (
    HYPOTHESIS_CONFIRMED_BY_HUMAN,
    HYPOTHESIS_CONTRADICTED,
    HYPOTHESIS_INCONCLUSIVE,
    HYPOTHESIS_OPEN,
    HYPOTHESIS_SUPPORTED,
    ForensicHypothesis,
    HumanHypothesisConfirmation,
    confirm_hypothesis,
    evaluate_hypothesis,
)


def _sha(marker: str) -> str:
    return sha256_fingerprint({"marker": marker})


def _ref(evidence_id: str, relation: str) -> EvidenceReference:
    return EvidenceReference(
        evidence_id=evidence_id,
        content_sha256=_sha(evidence_id),
        relation=relation,
    ).validate()


def _evaluate(*, supporting=(), contradicting=(), missing=()):
    return evaluate_hypothesis(
        hypothesis_id="hypothesis:credential-abuse-01",
        statement_sha256=_sha("credential abuse occurred"),
        created_at="2026-09-02T14:30:00Z",
        updated_at="2026-09-02T14:30:00Z",
        supporting=supporting,
        contradicting=contradicting,
        missing_evidence_codes=missing,
    )


class SecurityForensicHypothesisV014Tests(unittest.TestCase):
    def test_status_is_derived_only_from_evidence(self) -> None:
        opened = _evaluate(missing=("AUTH_LOG_NOT_AVAILABLE",))
        supported = _evaluate(supporting=(_ref("evidence:support-1", "supports"),))
        contradicted = _evaluate(contradicting=(_ref("evidence:counter-1", "contradicts"),))
        inconclusive = _evaluate(
            supporting=(_ref("evidence:support-1", "supports"),),
            contradicting=(_ref("evidence:counter-1", "contradicts"),),
        )

        self.assertEqual(opened.status, HYPOTHESIS_OPEN)
        self.assertEqual(supported.status, HYPOTHESIS_SUPPORTED)
        self.assertEqual(contradicted.status, HYPOTHESIS_CONTRADICTED)
        self.assertEqual(inconclusive.status, HYPOTHESIS_INCONCLUSIVE)
        self.assertEqual(opened.evidence.missing_evidence_codes, ("AUTH_LOG_NOT_AVAILABLE",))

        with self.assertRaisesRegex(MonitoringContractError, "status must be derived"):
            replace(opened, status=HYPOTHESIS_SUPPORTED).validate()

    def test_evidence_order_is_deterministic_and_relations_are_enforced(self) -> None:
        left = _ref("evidence:z-support", "supports")
        right = _ref("evidence:a-support", "supports")
        first = _evaluate(supporting=(left, right))
        second = _evaluate(supporting=(right, left))

        self.assertEqual(first.public_dict(), second.public_dict())
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(
            tuple(ref.evidence_id for ref in first.evidence.supporting),
            ("evidence:a-support", "evidence:z-support"),
        )

        with self.assertRaisesRegex(MonitoringContractError, "supports relation"):
            _evaluate(supporting=(_ref("evidence:wrong-relation", "contradicts"),))
        with self.assertRaisesRegex(MonitoringContractError, "contradicts relation"):
            _evaluate(contradicting=(_ref("evidence:wrong-counter", "supports"),))

    def test_same_evidence_cannot_both_support_and_contradict(self) -> None:
        support = _ref("evidence:same", "supports")
        contradiction = _ref("evidence:same", "contradicts")
        with self.assertRaisesRegex(MonitoringContractError, "cannot both support and contradict"):
            _evaluate(supporting=(support,), contradicting=(contradiction,))

    def test_statement_is_hash_only_and_raw_hypothesis_text_is_not_stored(self) -> None:
        hypothesis = _evaluate(supporting=(_ref("evidence:support-1", "supports"),))
        rendered = str(hypothesis.public_dict())
        self.assertIn("statement_sha256", rendered)
        self.assertNotIn("credential abuse occurred", rendered)
        with self.assertRaisesRegex(MonitoringContractError, "SHA-256"):
            replace(hypothesis, statement_sha256="raw natural-language hypothesis").validate()

    def test_supported_hypothesis_requires_explicit_human_confirmation_to_be_confirmed(self) -> None:
        hypothesis = _evaluate(supporting=(_ref("evidence:support-1", "supports"),))
        self.assertEqual(hypothesis.status, HYPOTHESIS_SUPPORTED)
        self.assertIsNone(hypothesis.human_confirmation)

        confirmation = HumanHypothesisConfirmation.build(
            hypothesis_id=hypothesis.hypothesis_id,
            evidence_fingerprint=hypothesis.evidence.fingerprint,
            human_ref="human:" + _sha("analyst-01"),
            confirmed_at="2026-09-02T14:30:00.500000Z",
            note_sha256=_sha("manual review complete"),
        )
        confirmed = confirm_hypothesis(hypothesis, confirmation)

        self.assertEqual(confirmed.status, HYPOTHESIS_CONFIRMED_BY_HUMAN)
        self.assertEqual(confirmed.human_confirmation, confirmation)
        self.assertEqual(confirmed.updated_at, confirmation.confirmed_at)
        self.assertTrue(confirmed.human_review_required)
        self.assertEqual(confirmed.authority, "advisory")

    def test_confirmation_rejects_model_or_generic_actor_identity(self) -> None:
        hypothesis = _evaluate(supporting=(_ref("evidence:support-1", "supports"),))
        with self.assertRaisesRegex(MonitoringContractError, "human:sha256"):
            HumanHypothesisConfirmation.build(
                hypothesis_id=hypothesis.hypothesis_id,
                evidence_fingerprint=hypothesis.evidence.fingerprint,
                human_ref="actor:" + _sha("model"),
                confirmed_at="2026-09-02T14:31:00Z",
            )
        with self.assertRaisesRegex(MonitoringContractError, "human:sha256"):
            HumanHypothesisConfirmation.build(
                hypothesis_id=hypothesis.hypothesis_id,
                evidence_fingerprint=hypothesis.evidence.fingerprint,
                human_ref="model:sha256:" + "0" * 64,
                confirmed_at="2026-09-02T14:31:00Z",
            )

    def test_confirmation_requires_supported_state_and_exact_evidence_fingerprint(self) -> None:
        contradicted = _evaluate(contradicting=(_ref("evidence:counter-1", "contradicts"),))
        contradiction_confirmation = HumanHypothesisConfirmation.build(
            hypothesis_id=contradicted.hypothesis_id,
            evidence_fingerprint=contradicted.evidence.fingerprint,
            human_ref="human:" + _sha("analyst-01"),
            confirmed_at="2026-09-02T14:31:00Z",
        )
        with self.assertRaisesRegex(MonitoringContractError, "only an unconfirmed SUPPORTED"):
            confirm_hypothesis(contradicted, contradiction_confirmation)

        supported = _evaluate(supporting=(_ref("evidence:support-1", "supports"),))
        wrong_evidence = HumanHypothesisConfirmation.build(
            hypothesis_id=supported.hypothesis_id,
            evidence_fingerprint=_sha("different evidence set"),
            human_ref="human:" + _sha("analyst-01"),
            confirmed_at="2026-09-02T14:31:00Z",
        )
        with self.assertRaisesRegex(MonitoringContractError, "evidence fingerprint mismatch"):
            confirm_hypothesis(supported, wrong_evidence)

    def test_confirmation_is_tamper_evident_and_cannot_precede_hypothesis(self) -> None:
        supported = _evaluate(supporting=(_ref("evidence:support-1", "supports"),))
        confirmation = HumanHypothesisConfirmation.build(
            hypothesis_id=supported.hypothesis_id,
            evidence_fingerprint=supported.evidence.fingerprint,
            human_ref="human:" + _sha("analyst-01"),
            confirmed_at="2026-09-02T14:31:00Z",
        )
        with self.assertRaisesRegex(MonitoringContractError, "record_sha256"):
            replace(confirmation, note_sha256=_sha("tampered after signing")).validate()

        too_early = HumanHypothesisConfirmation.build(
            hypothesis_id=supported.hypothesis_id,
            evidence_fingerprint=supported.evidence.fingerprint,
            human_ref="human:" + _sha("analyst-01"),
            confirmed_at="2026-09-02T14:29:59Z",
        )
        with self.assertRaisesRegex(MonitoringContractError, "cannot precede"):
            confirm_hypothesis(supported, too_early)

    def test_confirmed_hypothesis_cannot_be_fabricated_without_confirmation(self) -> None:
        supported = _evaluate(supporting=(_ref("evidence:support-1", "supports"),))
        fabricated = ForensicHypothesis(
            hypothesis_id=supported.hypothesis_id,
            statement_sha256=supported.statement_sha256,
            created_at=supported.created_at,
            updated_at=supported.updated_at,
            evidence=supported.evidence,
            status=HYPOTHESIS_CONFIRMED_BY_HUMAN,
            human_confirmation=None,
        )
        with self.assertRaisesRegex(MonitoringContractError, "status must be derived"):
            fabricated.validate()


if __name__ == "__main__":
    unittest.main()
