from __future__ import annotations

import json

import pytest

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


def test_descriptor_is_opaque_and_deterministic() -> None:
    item = descriptor(source_kind="FILE")
    assert item.source_kind == "file"
    assert item.fingerprint == SourceDescriptor.from_dict(item.to_dict()).fingerprint
    assert "auth-log" in item.to_dict()["source_id"]
    assert "path" not in item.to_dict()
    assert "url" not in item.to_dict()


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_id", "https://internal.example/log"),
        ("source_kind", "file/source"),
        ("identity_fingerprint", "not-a-digest"),
        ("format_id", "https://example.invalid/schema"),
        ("schema_version", "workspace-security-monitoring/source-descriptor-v2"),
    ],
)
def test_descriptor_rejects_unsafe_or_unsupported_values(field: str, value: str) -> None:
    with pytest.raises(MonitoringContractError):
        descriptor(**{field: value})


@pytest.mark.parametrize(
    "overrides",
    [
        {"cursor_offset_bytes": -1},
        {"observed_size_bytes": -1},
        {"cursor_offset_bytes": 513},
        {"cursor_offset_bytes": True},
        {"observed_size_bytes": 512.0},
    ],
)
def test_checkpoint_rejects_invalid_cursor_state(overrides: dict[str, object]) -> None:
    with pytest.raises(MonitoringContractError):
        checkpoint(**overrides)


def test_checkpoint_normalizes_utc_and_has_stable_fingerprint() -> None:
    left = checkpoint(checkpointed_at="2026-09-01T12:34:56+00:00", last_event_at="2026-09-01T12:34:00+00:00")
    right = checkpoint(checkpointed_at="2026-09-01T12:34:56Z", last_event_at="2026-09-01T12:34:00Z")
    assert left.checkpointed_at == "2026-09-01T12:34:56Z"
    assert left.last_event_at == "2026-09-01T12:34:00Z"
    assert left.to_json() == right.to_json()
    assert left.fingerprint == right.fingerprint


@pytest.mark.parametrize(
    "field,value",
    [
        ("checkpointed_at", "2026-09-01T12:34:56"),
        ("checkpointed_at", "2026-09-01T21:34:56+09:00"),
        ("last_event_at", "2026-09-01T21:34:00+09:00"),
        ("schema_version", "workspace-security-monitoring/source-checkpoint-v2"),
    ],
)
def test_checkpoint_rejects_non_utc_or_unsupported_schema(field: str, value: str) -> None:
    with pytest.raises(MonitoringContractError):
        checkpoint(**{field: value})


def test_checkpoint_round_trip_is_strict_and_deterministic() -> None:
    item = checkpoint()
    restored = SourceCheckpoint.from_json(item.to_json())
    assert restored == item
    assert restored.fingerprint == item.fingerprint
    assert json.loads(restored.to_json())["source"]["identity_fingerprint"] == IDENTITY


def test_checkpoint_rejects_unknown_or_missing_fields() -> None:
    payload = checkpoint().to_dict()
    payload["unexpected"] = "value"
    with pytest.raises(MonitoringContractError):
        SourceCheckpoint.from_dict(payload)

    payload = checkpoint().to_dict()
    del payload["observed_size_bytes"]
    with pytest.raises(MonitoringContractError):
        SourceCheckpoint.from_dict(payload)


def test_descriptor_rejects_unknown_nested_fields() -> None:
    payload = checkpoint().to_dict()
    payload["source"]["raw_path"] = "/var/log/auth.log"
    with pytest.raises(MonitoringContractError):
        SourceCheckpoint.from_dict(payload)


def test_checkpoint_rejects_malformed_json_or_non_object() -> None:
    with pytest.raises(MonitoringContractError):
        SourceCheckpoint.from_json("{")
    with pytest.raises(MonitoringContractError):
        SourceCheckpoint.from_json("[]")
