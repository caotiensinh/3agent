import unittest
from dataclasses import replace

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.evidence_privacy_receipt import EvidencePrivacyReceipt

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64


class EvidencePrivacyReceiptTests(unittest.TestCase):
    def _receipt(self):
        return EvidencePrivacyReceipt(
            evidence_ref="evidence:1234567890abcdef12345678",
            sensitivity="internal",
            redaction_policy_sha256=SHA_A,
            source_record_sha256=SHA_B,
            retained_payload_sha256=SHA_C,
        )

    def test_receipt_is_deterministic_and_metadata_only(self):
        first = self._receipt()
        second = self._receipt()
        self.assertEqual(first.receipt_id, second.receipt_id)
        self.assertEqual(first.public_dict(), second.public_dict())
        self.assertFalse(first.raw_payload_retained)
        self.assertFalse(first.credentials_retained)
        self.assertFalse(first.secrets_retained)
        self.assertNotIn("raw_payload", first.public_dict())

    def test_raw_payload_or_secret_retention_fails_closed(self):
        receipt = self._receipt()
        with self.assertRaisesRegex(MonitoringContractError, "forbids"):
            replace(receipt, raw_payload_retained=True).validate()
        with self.assertRaisesRegex(MonitoringContractError, "forbids"):
            replace(receipt, credentials_retained=True).validate()
        with self.assertRaisesRegex(MonitoringContractError, "forbids"):
            replace(receipt, secrets_retained=True).validate()

    def test_false_like_non_boolean_values_are_rejected(self):
        receipt = self._receipt()
        with self.assertRaisesRegex(MonitoringContractError, "exact boolean False"):
            replace(receipt, raw_payload_retained=0).validate()  # type: ignore[arg-type]
        with self.assertRaisesRegex(MonitoringContractError, "exact boolean False"):
            replace(receipt, credentials_retained="").validate()  # type: ignore[arg-type]

    def test_invalid_sensitivity_hash_and_evidence_ref_fail_closed(self):
        with self.assertRaisesRegex(MonitoringContractError, "sensitivity"):
            replace(self._receipt(), sensitivity="unclassified-custom").validate()
        with self.assertRaisesRegex(MonitoringContractError, "redaction_policy_sha256"):
            replace(self._receipt(), redaction_policy_sha256="bad").validate()
        with self.assertRaisesRegex(MonitoringContractError, "canonical evidence"):
            replace(self._receipt(), evidence_ref="finding:123").validate()


if __name__ == "__main__":
    unittest.main()
