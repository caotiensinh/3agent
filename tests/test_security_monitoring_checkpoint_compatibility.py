from __future__ import annotations

import unittest

from three_agent.security_monitoring.checkpoint import SourceCheckpoint, SourceDescriptor
from three_agent.security_monitoring.checkpoint_compatibility import SourceContinuationEvaluator
from three_agent.security_monitoring.contracts import MonitoringContractError

IDENTITY_A = "sha256:" + "a" * 64
IDENTITY_B = "sha256:" + "b" * 64


def source(**overrides: object) -> SourceDescriptor:
    values: dict[str, object] = {
        "source_id": "sensor-01:auth-log",
        "source_kind": "file",
        "identity_fingerprint": IDENTITY_A,
        "format_id": "syslog-rfc5424",
    }
    values.update(overrides)
    return SourceDescriptor(**values).validate()  # type: ignore[arg-type]


def checkpoint(**overrides: object) -> SourceCheckpoint:
    values: dict[str, object] = {
        "source": source(),
        "cursor_offset_bytes": 128,
        "observed_size_bytes": 512,
        "checkpointed_at": "2026-09-01T12:34:56Z",
        "last_event_at": "2026-09-01T12:34:00Z",
    }
    values.update(overrides)
    return SourceCheckpoint(**values).validate()  # type: ignore[arg-type]


def evaluate(*, current_source: SourceDescriptor | None = None, current_size: int = 512, prior: SourceCheckpoint | None = None):
    return SourceContinuationEvaluator().evaluate(
        current_source=current_source or source(),
        current_size_bytes=current_size,
        checkpoint=prior,
    )


class SourceCheckpointCompatibilityTests(unittest.TestCase):
    def test_no_checkpoint_starts_from_zero(self) -> None:
        receipt = evaluate(prior=None)
        self.assertEqual((receipt.action, receipt.reason_code, receipt.resume_offset_bytes), ("start", "no_checkpoint", 0))
        self.assertIsNone(receipt.previous_checkpoint_fingerprint)

    def test_compatible_checkpoint_resumes_exact_cursor(self) -> None:
        prior = checkpoint()
        receipt = evaluate(current_size=1024, prior=prior)
        self.assertEqual((receipt.action, receipt.reason_code), ("resume", "compatible"))
        self.assertEqual(receipt.resume_offset_bytes, 128)
        self.assertEqual(receipt.previous_checkpoint_fingerprint, prior.fingerprint)

    def test_same_extent_is_still_compatible(self) -> None:
        receipt = evaluate(current_size=512, prior=checkpoint())
        self.assertEqual(receipt.action, "resume")
        self.assertEqual(receipt.resume_offset_bytes, 128)

    def test_rotated_identity_resets_instead_of_silent_resume(self) -> None:
        receipt = evaluate(current_source=source(identity_fingerprint=IDENTITY_B), prior=checkpoint())
        self.assertEqual((receipt.action, receipt.reason_code, receipt.resume_offset_bytes), ("reset", "source_rotated", 0))

    def test_truncated_source_resets_instead_of_silent_resume(self) -> None:
        receipt = evaluate(current_size=511, prior=checkpoint())
        self.assertEqual((receipt.action, receipt.reason_code, receipt.resume_offset_bytes), ("reset", "source_truncated", 0))

    def test_format_change_resets_from_zero(self) -> None:
        receipt = evaluate(current_source=source(format_id="workspace-jsonl-v1"), prior=checkpoint())
        self.assertEqual((receipt.action, receipt.reason_code, receipt.resume_offset_bytes), ("reset", "source_format_changed", 0))

    def test_wrong_source_id_is_invalid_and_exposes_no_resume_offset(self) -> None:
        receipt = evaluate(current_source=source(source_id="sensor-02:auth-log"), prior=checkpoint())
        self.assertEqual((receipt.action, receipt.reason_code, receipt.resume_offset_bytes), ("invalid", "source_id_mismatch", None))

    def test_source_kind_change_is_invalid_and_exposes_no_resume_offset(self) -> None:
        receipt = evaluate(current_source=source(source_kind="journal"), prior=checkpoint())
        self.assertEqual((receipt.action, receipt.reason_code, receipt.resume_offset_bytes), ("invalid", "source_kind_changed", None))

    def test_current_extent_must_be_a_nonnegative_integer(self) -> None:
        for current_size in (-1, True, 512.0):
            with self.subTest(current_size=current_size):
                with self.assertRaises(MonitoringContractError):
                    SourceContinuationEvaluator().evaluate(
                        current_source=source(),
                        current_size_bytes=current_size,  # type: ignore[arg-type]
                        checkpoint=checkpoint(),
                    )

    def test_receipt_is_deterministic_for_identical_inputs(self) -> None:
        prior = checkpoint()
        left = evaluate(current_size=900, prior=prior)
        right = evaluate(current_size=900, prior=prior)
        self.assertEqual(left.to_json(), right.to_json())
        self.assertEqual(left.fingerprint, right.fingerprint)


if __name__ == "__main__":
    unittest.main()
