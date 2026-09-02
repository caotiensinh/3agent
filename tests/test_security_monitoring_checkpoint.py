from __future__ import annotations

import json
import unittest

from three_agent.security_monitoring.checkpoint import (
    SOURCE_CHECKPOINT_SCHEMA,
    SOURCE_DESCRIPTOR_SCHEMA,
    SourceCheckpoint,
    SourceDescriptor,
)
from three_agent.security_monitoring.contracts import MonitoringContractError

IDENTITY = "sha256:" + "a" * 64


def descriptor(**overrides: object) -> SourceDescriptor:
    values: dict[str, object] = {
        "source_id": "sensor-01:auth-log",
        "source_kind": "file",
        "identity_fingerprint": IDENTITY,
        "format_id": "syslog-rfc5424",
        "schema_version": SOURCE_DESCRIPTOR_SCHEMA,
    }
    values.update(overrides)
    return SourceDescriptor(**values).validate()  # type: ignore[arg-type]


def checkpoint(**overrides: object) -> SourceCheckpoint:
    values: dict[str, object] = {
        "source": descriptor(),
        "cursor_offset_bytes": 128,
        "observed_size_bytes": 512,
        "checkpointed_at": "2026-09-01T12:34:56Z",
        "last_event_at": "2026-09-01T12:34:00Z",
        "schema_version": SOURCE_CHECKPOINT_SCHEMA,
    }
    values.update(overrides)
    return SourceCheckpoint(**values).validate()  # type: ignore[arg-type]


class SourceCheckpointTests(unittest.TestCase):
    def test_descriptor_is_opaque_and_deterministic(self) -> None:
        item = descriptor(source_kind="FILE")
        self.assertEqual(item.source_kind, "file")
        self.assertEqual(item.fingerprint, SourceDescriptor.from_dict(item.to_dict()).fingerprint)
        self.assertIn("auth-log", item.to_dict()["source_id"])
        self.assertNotIn("path", item.to_dict())
        self.assertNotIn("url", item.to_dict())

    def test_descriptor_rejects_unsafe_or_unsupported_values(self) -> None:
        cases = [
            ("source_id", "https://internal.example/log"),
            ("source_kind", "file/source"),
            ("identity_fingerprint", "not-a-digest"),
            ("format_id", "https://example.invalid/schema"),
            ("schema_version", "workspace-security-monitoring/source-descriptor-v2"),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                with self.assertRaises(MonitoringContractError):
                    descriptor(**{field: value})

    def test_checkpoint_rejects_invalid_cursor_state(self) -> None:
        cases: list[dict[str, object]] = [
            {"cursor_offset_bytes": -1},
            {"observed_size_bytes": -1},
            {"cursor_offset_bytes": 513},
            {"cursor_offset_bytes": True},
            {"observed_size_bytes": 512.0},
        ]
        for overrides in cases:
            with self.subTest(overrides=overrides):
                with self.assertRaises(MonitoringContractError):
                    checkpoint(**overrides)

    def test_checkpoint_normalizes_utc_and_has_stable_fingerprint(self) -> None:
        left = checkpoint(
            checkpointed_at="2026-09-01T12:34:56+00:00",
            last_event_at="2026-09-01T12:34:00+00:00",
        )
        right = checkpoint(
            checkpointed_at="2026-09-01T12:34:56Z",
            last_event_at="2026-09-01T12:34:00Z",
        )
        self.assertEqual(left.checkpointed_at, "2026-09-01T12:34:56Z")
        self.assertEqual(left.last_event_at, "2026-09-01T12:34:00Z")
        self.assertEqual(left.to_json(), right.to_json())
        self.assertEqual(left.fingerprint, right.fingerprint)

    def test_checkpoint_rejects_non_utc_or_unsupported_schema(self) -> None:
        cases = [
            ("checkpointed_at", "2026-09-01T12:34:56"),
            ("checkpointed_at", "2026-09-01T21:34:56+09:00"),
            ("last_event_at", "2026-09-01T21:34:00+09:00"),
            ("schema_version", "workspace-security-monitoring/source-checkpoint-v2"),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                with self.assertRaises(MonitoringContractError):
                    checkpoint(**{field: value})

    def test_checkpoint_round_trip_is_strict_and_deterministic(self) -> None:
        item = checkpoint()
        restored = SourceCheckpoint.from_json(item.to_json())
        self.assertEqual(restored, item)
        self.assertEqual(restored.fingerprint, item.fingerprint)
        self.assertEqual(json.loads(restored.to_json())["source"]["identity_fingerprint"], IDENTITY)

    def test_checkpoint_rejects_unknown_or_missing_fields(self) -> None:
        payload = checkpoint().to_dict()
        payload["unexpected"] = "value"
        with self.assertRaises(MonitoringContractError):
            SourceCheckpoint.from_dict(payload)

        payload = checkpoint().to_dict()
        del payload["observed_size_bytes"]
        with self.assertRaises(MonitoringContractError):
            SourceCheckpoint.from_dict(payload)

    def test_descriptor_rejects_unknown_nested_fields(self) -> None:
        payload = checkpoint().to_dict()
        payload["source"]["raw_path"] = "/var/log/auth.log"
        with self.assertRaises(MonitoringContractError):
            SourceCheckpoint.from_dict(payload)

    def test_checkpoint_rejects_malformed_json_or_non_object(self) -> None:
        with self.assertRaises(MonitoringContractError):
            SourceCheckpoint.from_json("{")
        with self.assertRaises(MonitoringContractError):
            SourceCheckpoint.from_json("[]")


if __name__ == "__main__":
    unittest.main()
