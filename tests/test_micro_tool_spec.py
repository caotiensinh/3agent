from dataclasses import FrozenInstanceError
import json
import sys

import pytest

from three_agent.micro_tools import (
    ToolCost,
    ToolEffect,
    ToolNetworkRequirement,
    ToolPlatform,
    ToolPrivilege,
    ToolSensitivity,
    ToolSpec,
    ToolSpecValidationError,
)


def valid_payload() -> dict:
    return {
        "id": "windows.event.system",
        "version": "0.1.0",
        "title": "Read Windows System event channel",
        "platforms": ["windows"],
        "category": "event",
        "intents": ["system_error", "unexpected_restart"],
        "keywords": ["event viewer", "system", "restart"],
        "cost": "C1",
        "effect": "read_only",
        "privilege": "user_or_elevated_when_required",
        "network_requirement": "none",
        "sensitivity": "internal",
        "timeout_seconds": 10,
        "max_output_bytes": 10485760,
        "executor_ref": "three_agent.micro_tools.executors.windows_event:run",
        "preset": {"channel": "System", "filters": {"level": ["Error", "Critical"]}},
        "input_schema_ref": "schemas/windows_event_input.json",
        "output_schema_ref": "schemas/evidence_record.json",
    }


def test_valid_spec_builds_without_importing_executor() -> None:
    executor_module = "three_agent.micro_tools.executors.windows_event"
    sys.modules.pop(executor_module, None)

    spec = ToolSpec.from_dict(valid_payload())

    assert spec.id == "windows.event.system"
    assert spec.platforms == (ToolPlatform.WINDOWS,)
    assert spec.cost is ToolCost.C1
    assert spec.effect is ToolEffect.READ_ONLY
    assert spec.privilege is ToolPrivilege.USER_OR_ELEVATED_WHEN_REQUIRED
    assert spec.network_requirement is ToolNetworkRequirement.NONE
    assert spec.sensitivity is ToolSensitivity.INTERNAL
    assert executor_module not in sys.modules


def test_to_dict_is_deterministic_and_json_serializable() -> None:
    payload = valid_payload()
    spec = ToolSpec.from_dict(payload)

    first = json.dumps(spec.to_dict(), sort_keys=True, separators=(",", ":"))
    second = json.dumps(spec.to_dict(), sort_keys=True, separators=(",", ":"))

    assert first == second
    assert spec.to_dict() == payload


@pytest.mark.parametrize(
    "bad_id",
    [
        "windows",
        "windows.event",
        "Windows.event.system",
        "windows.event.system-v2",
        "windows.event.system_v2",
        "windows.event.system_new",
        "windows.event.system_final",
        "windows.event.system_copy2",
    ],
)
def test_invalid_or_version_copy_tool_ids_are_rejected(bad_id: str) -> None:
    payload = valid_payload()
    payload["id"] = bad_id

    with pytest.raises(ToolSpecValidationError):
        ToolSpec.from_dict(payload)


@pytest.mark.parametrize("bad_version", ["1", "1.0", "v1.0.0", "01.0.0", "1.0.0-beta"])
def test_invalid_versions_are_rejected(bad_version: str) -> None:
    payload = valid_payload()
    payload["version"] = bad_version

    with pytest.raises(ToolSpecValidationError):
        ToolSpec.from_dict(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("platforms", []),
        ("platforms", ["windows", "windows"]),
        ("intents", []),
        ("keywords", []),
        ("intents", ["system_error", "system_error"]),
        ("keywords", ["system", "system"]),
        ("intents", [""]),
        ("keywords", [" "]),
    ],
)
def test_empty_or_duplicate_metadata_is_rejected(field: str, value: list[str]) -> None:
    payload = valid_payload()
    payload[field] = value

    with pytest.raises(ToolSpecValidationError):
        ToolSpec.from_dict(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("timeout_seconds", 0),
        ("timeout_seconds", -1),
        ("timeout_seconds", True),
        ("max_output_bytes", 0),
        ("max_output_bytes", -1),
        ("max_output_bytes", False),
    ],
)
def test_nonpositive_or_noninteger_execution_bounds_are_rejected(field: str, value: object) -> None:
    payload = valid_payload()
    payload[field] = value

    with pytest.raises(ToolSpecValidationError):
        ToolSpec.from_dict(payload)


@pytest.mark.parametrize(
    "executor_ref",
    [
        "three_agent.micro_tools.executors.windows_event",
        "three_agent.micro_tools.executors.windows_event:",
        ":run",
        "three-agent.executor:run",
        "three_agent.executor:run now",
    ],
)
def test_bad_executor_refs_are_rejected_without_import(executor_ref: str) -> None:
    payload = valid_payload()
    payload["executor_ref"] = executor_ref

    with pytest.raises(ToolSpecValidationError):
        ToolSpec.from_dict(payload)


def test_unknown_and_missing_fields_fail_closed() -> None:
    payload = valid_payload()
    payload["unexpected"] = True
    with pytest.raises(ToolSpecValidationError, match="unsupported ToolSpec fields"):
        ToolSpec.from_dict(payload)

    payload = valid_payload()
    del payload["effect"]
    with pytest.raises(ToolSpecValidationError, match="missing ToolSpec fields"):
        ToolSpec.from_dict(payload)


def test_preset_and_spec_are_immutable() -> None:
    spec = ToolSpec.from_dict(valid_payload())

    with pytest.raises(TypeError):
        spec.preset["channel"] = "Application"

    with pytest.raises(FrozenInstanceError):
        spec.title = "changed"


@pytest.mark.parametrize(
    "preset",
    [
        {1: "not-a-string-key"},
        {"bad": {1, 2}},
        {"bad": object()},
        {"bad": float("inf")},
        {"bad": float("nan")},
    ],
)
def test_preset_must_remain_deterministic_json_compatible(preset: object) -> None:
    payload = valid_payload()
    payload["preset"] = preset

    with pytest.raises(ToolSpecValidationError):
        ToolSpec.from_dict(payload)
