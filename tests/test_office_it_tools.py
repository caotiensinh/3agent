from __future__ import annotations

import pytest

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.office_it_tools import (
    TOOL_SPECS,
    build_windows_event_plan,
    build_windows_printer_queue_plan,
    get_tool_spec,
    is_internal_ip_literal,
    select_tools,
    tool_ids,
)
from three_agent.task_contract import TaskContractCompiler, TaskContractError


def _authority(*tool_ids: str) -> TaskCapabilityAuthority:
    contract = TaskContractCompiler().compile(
        task_id="office-it-test",
        task_type="analysis",
        sensitivity="internal",
        allowed_tools=tool_ids,
    )
    return TaskCapabilityAuthority.from_contract(contract)


def test_registry_contains_only_the_v0_1_atomic_tools() -> None:
    assert tool_ids() == (
        "windows.event.system",
        "windows.event.application",
        "windows.event.security",
        "windows.printer.queue",
        "network.ssh.probe",
        "network.smb.probe",
        "network.printer.ipp_probe",
        "network.printer.raw_probe",
    )
    assert len(TOOL_SPECS) == len(tool_ids())
    assert all(spec.risk == "read_only" for spec in TOOL_SPECS.values())
    assert all(spec.cost in {"C1", "C2"} for spec in TOOL_SPECS.values())


def test_security_event_metadata_marks_admin_and_sensitive_output() -> None:
    spec = get_tool_spec("windows.event.security")
    assert spec.requires_admin is True
    assert spec.sensitive_outputs is True
    assert spec.network_access == "none"


def test_selector_is_targeted_and_cost_bounded() -> None:
    ssh = select_tools("SSH server 192.168.11.10 is unreachable", platform_name="Windows")
    assert tuple(spec.id for spec in ssh) == ("network.ssh.probe",)

    printer = select_tools("May in mang khong in", platform_name="Windows")
    printer_ids = {spec.id for spec in printer}
    assert "windows.printer.queue" in printer_ids
    assert "network.printer.ipp_probe" in printer_ids
    assert "network.printer.raw_probe" in printer_ids
    assert "windows.event.security" not in printer_ids


def test_windows_event_plan_uses_fixed_channel_and_bounded_integers() -> None:
    plan = build_windows_event_plan("windows.event.system", hours=24, max_events=200)
    assert plan[:4] == ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command")
    assert "LogName='System'" in plan[4]
    assert "AddHours(-24)" in plan[4]
    assert "-MaxEvents 200" in plan[4]
    forbidden = ("Clear-EventLog", "Restart-Service", "Stop-Service", "Set-Item", "Remove-Item")
    assert not any(token in plan[4] for token in forbidden)

    with pytest.raises(ValueError):
        build_windows_event_plan("windows.event.system", hours=0)
    with pytest.raises(ValueError):
        build_windows_event_plan("windows.event.system", max_events=1001)
    with pytest.raises(ValueError):
        build_windows_event_plan("windows.event.system;Remove-Item", hours=24)


def test_printer_queue_plan_is_read_only() -> None:
    plan = build_windows_printer_queue_plan()
    assert "Get-Printer" in plan[4]
    assert "ConvertTo-Json" in plan[4]
    assert "Remove-Printer" not in plan[4]
    assert "Set-Printer" not in plan[4]
    assert "Restart-Service" not in plan[4]


def test_network_targets_are_private_ip_literals_only() -> None:
    assert is_internal_ip_literal("192.168.11.196")
    assert is_internal_ip_literal("10.0.0.2")
    assert is_internal_ip_literal("172.16.5.7")
    assert is_internal_ip_literal("127.0.0.1")
    assert is_internal_ip_literal("fe80::1")
    assert is_internal_ip_literal("fd00::1")
    assert not is_internal_ip_literal("8.8.8.8")
    assert not is_internal_ip_literal("example.com")
    assert not is_internal_ip_literal("203.0.113.10")


def test_internal_network_probe_requires_exact_task_authority() -> None:
    authority = _authority("network.ssh.probe")
    decision = authority.authorize(
        "network.ssh.probe",
        resource_kind="network_endpoint",
        resource_ref="192.168.11.10:22",
        effect="network_read",
    )
    assert decision.allowed is True
    assert decision.reason_code == "CAPABILITY_AUTHORIZED"

    wrong_kind = authority.authorize(
        "network.ssh.probe",
        resource_kind="url",
        resource_ref="192.168.11.10:22",
        effect="network_read",
    )
    assert wrong_kind.allowed is False
    assert wrong_kind.reason_code == "RESOURCE_KIND_NOT_AUTHORIZED"

    denied = authority.derive_child(task_id="office-it-denied", network_scope="deny")
    denied_decision = denied.authorize(
        "network.ssh.probe",
        resource_kind="network_endpoint",
        resource_ref="192.168.11.10:22",
        effect="network_read",
    )
    assert denied_decision.allowed is False
    assert denied_decision.reason_code == "NETWORK_SCOPE_NOT_AUTHORIZED"


def test_local_event_tool_is_first_class_task_capability() -> None:
    authority = _authority("windows.event.system")
    decision = authority.authorize(
        "windows.event.system",
        resource_kind="event_channel",
        resource_ref="windows:event:System",
        effect="read",
    )
    assert decision.allowed is True


def test_internal_network_tool_fails_closed_outside_internal_scope() -> None:
    with pytest.raises(TaskContractError, match="network_scope=internal_only"):
        TaskContractCompiler().compile(
            task_id="office-it-confidential-deny",
            task_type="analysis",
            sensitivity="confidential",
            allowed_tools=("network.smb.probe",),
        )
