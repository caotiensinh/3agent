from __future__ import annotations

import unittest

from three_agent.security_monitoring.checkpoint import SourceCheckpoint, SourceDescriptor
from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.replay import DeterministicByteReplay

IDENTITY_A = "sha256:" + "a" * 64
IDENTITY_B = "sha256:" + "b" * 64
CHECKPOINTED_AT = "2026-09-01T13:00:00Z"


def source(*, format_id: str = "syslog-rfc5424", identity: str = IDENTITY_A) -> SourceDescriptor:
    return SourceDescriptor(
        source_id="sensor-01:security-log",
        source_kind="file",
        identity_fingerprint=identity,
        format_id=format_id,
    ).validate()


def harness() -> DeterministicByteReplay:
    return DeterministicByteReplay(
        max_source_bytes=4096,
        max_replay_bytes=4096,
        max_records=100,
        max_record_bytes=1024,
    )


class ReplayParserIntegrationTests(unittest.TestCase):
    def test_complete_records_use_existing_parser_and_partial_tail_is_not_consumed(self) -> None:
        valid = b"<34>2026-09-01T12:00:00Z router sshd: accepted\n"
        malformed = b"not-a-syslog-record\n"
        partial = b"<34>2026-09-01T12:01:00Z router sshd: partial"
        payload = valid + malformed + partial

        result = harness().replay_and_parse(
            source=source(),
            source_bytes=payload,
            checkpointed_at=CHECKPOINTED_AT,
        )

        self.assertEqual(len(result.events), 1)
        self.assertEqual(len(result.quarantined), 1)
        self.assertEqual(result.quarantined[0].reason_code, "SYSLOG_PARSE_FAILED")
        self.assertEqual(result.quarantined[0].observed_at, CHECKPOINTED_AT)
        self.assertEqual(result.replay.receipt.stop_reason, "partial_record")
        self.assertEqual(result.next_checkpoint.cursor_offset_bytes, len(valid + malformed))
        self.assertEqual(result.next_checkpoint.observed_size_bytes, len(payload))
        self.assertEqual(result.next_checkpoint.last_event_at, "2026-09-01T12:00:00Z")

    def test_repeated_input_and_timestamp_are_deterministic(self) -> None:
        payload = b"bad-record\n"
        left = harness().replay_and_parse(
            source=source(), source_bytes=payload, checkpointed_at=CHECKPOINTED_AT
        )
        right = harness().replay_and_parse(
            source=source(), source_bytes=payload, checkpointed_at=CHECKPOINTED_AT
        )

        self.assertEqual(left.quarantined, right.quarantined)
        self.assertEqual(left.replay.receipt.to_json(), right.replay.receipt.to_json())
        self.assertEqual(left.next_checkpoint.to_json(), right.next_checkpoint.to_json())

    def test_resume_preserves_last_event_when_only_new_quarantine_is_seen(self) -> None:
        first = b"<34>2026-09-01T12:00:00Z router sshd: accepted\n"
        payload = first + b"bad-record\n"
        prior = SourceCheckpoint(
            source=source(),
            cursor_offset_bytes=len(first),
            observed_size_bytes=len(first),
            checkpointed_at="2026-09-01T12:30:00Z",
            last_event_at="2026-09-01T12:00:00Z",
        ).validate()

        result = harness().replay_and_parse(
            source=source(),
            source_bytes=payload,
            checkpointed_at=CHECKPOINTED_AT,
            checkpoint=prior,
        )

        self.assertEqual(result.replay.compatibility.action, "resume")
        self.assertEqual(len(result.events), 0)
        self.assertEqual(len(result.quarantined), 1)
        self.assertEqual(result.next_checkpoint.last_event_at, "2026-09-01T12:00:00Z")

    def test_rotation_does_not_carry_old_source_last_event(self) -> None:
        old_source = source(identity=IDENTITY_A)
        new_source = source(identity=IDENTITY_B)
        prior = SourceCheckpoint(
            source=old_source,
            cursor_offset_bytes=4,
            observed_size_bytes=4,
            checkpointed_at="2026-09-01T12:30:00Z",
            last_event_at="2026-09-01T12:00:00Z",
        ).validate()

        result = harness().replay_and_parse(
            source=new_source,
            source_bytes=b"bad\n",
            checkpointed_at=CHECKPOINTED_AT,
            checkpoint=prior,
        )

        self.assertEqual(result.replay.compatibility.action, "reset")
        self.assertIsNone(result.next_checkpoint.last_event_at)

    def test_json_sensor_format_reuses_existing_parser(self) -> None:
        payload = (
            b'{"timestamp":"2026-09-01T12:00:00Z","event_type":"alert",'
            b'"alert":{"severity":2}}\n'
        )
        result = harness().replay_and_parse(
            source=source(format_id="suricata-eve-jsonl"),
            source_bytes=payload,
            checkpointed_at=CHECKPOINTED_AT,
        )
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].source_type, "suricata_eve")
        self.assertEqual(result.events[0].category, "suricata.alert")
        self.assertEqual(result.events[0].severity, "high")

    def test_unsupported_format_fails_closed_before_parsing(self) -> None:
        with self.assertRaisesRegex(MonitoringContractError, "unsupported replay format_id"):
            harness().replay_and_parse(
                source=source(format_id="unknown-format"),
                source_bytes=b"anything\n",
                checkpointed_at=CHECKPOINTED_AT,
            )


if __name__ == "__main__":
    unittest.main()
