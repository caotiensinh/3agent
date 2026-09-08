import json
import unittest
from dataclasses import replace

from three_agent.capability_authority import CapabilityDecision
from three_agent.invocation_decision_receipt import (
    InvocationDecisionReceiptError,
    receipt_from_capability_decision,
)


def _sha(char: str) -> str:
    return "sha256:" + (char * 64)


def _decision(*, allowed: bool = True, reason_code: str | None = None) -> CapabilityDecision:
    return CapabilityDecision(
        task_id="task-001",
        capability="network.quality.internal",
        resource_kind="network_endpoint",
        resource_ref="credential/private-network-target",
        effect="network_read",
        allowed=allowed,
        reason_code=reason_code or ("CAPABILITY_ALLOWED" if allowed else "CAPABILITY_DENIED"),
        authority_fingerprint=_sha("a"),
    )


def _receipt(**overrides: object):
    values: dict[str, object] = {
        "decision": _decision(),
        "task_ref_sha256": _sha("1"),
        "request_ref_sha256": _sha("2"),
        "tool_id": "network_quality_probe",
        "descriptor_fingerprint": _sha("3"),
        "snapshot_fingerprint": _sha("4"),
    }
    values.update(overrides)
    return receipt_from_capability_decision(**values)  # type: ignore[arg-type]


class InvocationDecisionReceiptTests(unittest.TestCase):
    def test_receipt_is_deterministic_and_advisory_only(self) -> None:
        first = _receipt()
        second = _receipt()

        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertTrue(first.fingerprint.startswith("sha256:"))
        self.assertEqual(first.authority, "advisory")
        self.assertFalse(first.automatic_action_allowed)

    def test_lineage_mutation_changes_receipt_fingerprint(self) -> None:
        baseline = _receipt()
        request_changed = _receipt(request_ref_sha256=_sha("5"))
        descriptor_changed = _receipt(descriptor_fingerprint=_sha("6"))

        self.assertNotEqual(baseline.fingerprint, request_changed.fingerprint)
        self.assertNotEqual(baseline.fingerprint, descriptor_changed.fingerprint)

    def test_denied_decision_is_recorded_without_granting_authority(self) -> None:
        denied = _receipt(decision=_decision(allowed=False))

        self.assertFalse(denied.allowed)
        self.assertEqual(denied.reason_code, "CAPABILITY_DENIED")
        self.assertFalse(denied.automatic_action_allowed)

    def test_raw_resource_is_hashed_not_promoted(self) -> None:
        receipt = _receipt()
        serialized = json.dumps(receipt.canonical_dict(), sort_keys=True)

        self.assertNotIn("credential/private-network-target", serialized)
        self.assertIn("resource_sha256", serialized)

    def test_untrusted_free_text_reason_fails_closed(self) -> None:
        with self.assertRaisesRegex(InvocationDecisionReceiptError, "INVALID_REASON_CODE"):
            _receipt(decision=_decision(reason_code="model says this seems safe"))

    def test_malformed_identity_and_authority_escalation_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            InvocationDecisionReceiptError,
            "INVALID_REQUEST_REF_SHA256",
        ):
            _receipt(request_ref_sha256="not-a-hash")

        baseline = _receipt()
        with self.assertRaisesRegex(
            InvocationDecisionReceiptError,
            "RECEIPT_CANNOT_GRANT_AUTHORITY",
        ):
            replace(baseline, automatic_action_allowed=True).validate()


if __name__ == "__main__":
    unittest.main()
