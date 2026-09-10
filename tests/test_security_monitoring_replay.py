from __future__ import annotations

import unittest

from three_agent.security_monitoring.checkpoint import SourceCheckpoint, SourceDescriptor
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.replay import DeterministicByteReplay

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


def checkpoint(*, cursor: int, size: int, source_value: SourceDescriptor | None = None) -> SourceCheckpoint:
    return SourceCheckpoint(
        source=source_value or source(),
        cursor_offset_bytes=cursor,
        observed_size_bytes=size,
        checkpointed_at="2026-09-01T12:34:56Z",
    ).validate()


def harness(**overrides: object) -> DeterministicByteReplay:
    values: dict[str, object] = {
        "max_source_bytes": 4096,
        "max_replay_bytes": 4096,
        "max_records": 100,
        "max_record_bytes": 1024,
    }
    values.update(overrides)
    return DeterministicByteReplay(**values)  # type: ignore[arg-type]


class DeterministicByteReplayTests(unittest.TestCase):
    def test_same_input_and_checkpoint_produce_byte_identical_receipt(self) -> None:
        payload = b"alpha\nbeta\ngamma\n"
        left = harness().replay(source=source(), source_bytes=payload)
        right = harness().replay(source=source(), source_bytes=payload)
        self.assertEqual([item.text for item in left.records], ["alpha", "beta", "gamma"])
        self.assertEqual(left.receipt.to_json(), right.receipt.to_json())
        self.assertEqual(left.receipt.fingerprint, right.receipt.fingerprint)

    def test_resume_starts_at_exact_record_boundary(self) -> None:
        payload = b"alpha\nbeta\ngamma\n"
        prior = checkpoint(cursor=len(b"alpha\n"), size=len(payload))
        batch = harness().replay(source=source(), source_bytes=payload, checkpoint=prior)
        self.assertEqual(batch.compatibility.action, "resume")
        self.assertEqual(batch.receipt.start_offset_bytes, len(b"alpha\n"))
        self.assertEqual([item.text for item in batch.records], ["beta", "gamma"])

    def test_rotation_resets_to_start_and_replays_new_source(self) -> None:
        old = source(identity_fingerprint=IDENTITY_A)
        new = source(identity_fingerprint=IDENTITY_B)
        prior = checkpoint(cursor=6, size=11, source_value=old)
        batch = harness().replay(source=new, source_bytes=b"new-1\nnew-2\n", checkpoint=prior)
        self.assertEqual((batch.compatibility.action, batch.compatibility.reason_code), ("reset", "source_rotated"))
        self.assertEqual(batch.receipt.start_offset_bytes, 0)
        self.assertEqual([item.text for item in batch.records], ["new-1", "new-2"])

    def test_truncation_resets_to_start(self) -> None:
        prior = checkpoint(cursor=6, size=20)
        batch = harness().replay(source=source(), source_bytes=b"new\n", checkpoint=prior)
        self.assertEqual((batch.compatibility.action, batch.compatibility.reason_code), ("reset", "source_truncated"))
        self.assertEqual(batch.receipt.start_offset_bytes, 0)
        self.assertEqual([item.text for item in batch.records], ["new"])

    def test_invalid_checkpoint_never_exposes_replay(self) -> None:
        prior = checkpoint(cursor=0, size=0, source_value=source(source_id="other-source"))
        with self.assertRaisesRegex(MonitoringContractError, "not replayable"):
            harness().replay(source=source(), source_bytes=b"alpha\n", checkpoint=prior)

    def test_non_boundary_cursor_fails_closed(self) -> None:
        payload = b"alpha\nbeta\n"
        prior = checkpoint(cursor=2, size=len(payload))
        with self.assertRaisesRegex(MonitoringContractError, "record boundary"):
            harness().replay(source=source(), source_bytes=payload, checkpoint=prior)

    def test_partial_trailing_record_is_not_consumed(self) -> None:
        payload = b"alpha\nbeta-partial"
        batch = harness().replay(source=source(), source_bytes=payload)
        self.assertEqual([item.text for item in batch.records], ["alpha"])
        self.assertEqual(batch.receipt.stop_reason, "partial_record")
        self.assertEqual(batch.receipt.next_offset_bytes, len(b"alpha\n"))
        self.assertEqual(batch.receipt.replayed_bytes, len(b"alpha\n"))

    def test_record_limit_preserves_next_exact_offset(self) -> None:
        payload = b"a\nb\nc\n"
        batch = harness(max_records=2).replay(source=source(), source_bytes=payload)
        self.assertEqual([item.text for item in batch.records], ["a", "b"])
        self.assertEqual(batch.receipt.stop_reason, "record_limit")
        self.assertEqual(batch.receipt.next_offset_bytes, len(b"a\nb\n"))

    def test_byte_limit_never_splits_a_record(self) -> None:
        payload = b"abc\ndef\n"
        batch = harness(max_replay_bytes=5, max_record_bytes=5).replay(source=source(), source_bytes=payload)
        self.assertEqual([item.text for item in batch.records], ["abc"])
        self.assertEqual(batch.receipt.stop_reason, "byte_limit")
        self.assertEqual(batch.receipt.next_offset_bytes, len(b"abc\n"))

    def test_receipt_is_hash_only_and_does_not_serialize_raw_lines(self) -> None:
        secretish_line = "user=alice action=login"
        batch = harness().replay(source=source(), source_bytes=(secretish_line + "\n").encode())
        self.assertEqual(batch.records[0].text, secretish_line)
        self.assertNotIn(secretish_line, batch.receipt.to_json())
        self.assertIn("sha256:", batch.receipt.to_json())

    def test_source_and_record_bounds_fail_closed(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "max_source_bytes"):
            harness(max_source_bytes=4096).replay(source=source(), source_bytes=b"x" * 4097)
        with self.assertRaisesRegex(MonitoringContractError, "max_record_bytes"):
            harness(max_record_bytes=4).replay(source=source(), source_bytes=b"12345\n")


if __name__ == "__main__":
    unittest.main()
