from __future__ import annotations

import unittest

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


class OfficeITToolTests(unittest.TestCase):
    def test_registry_contains_only_the_v0_1_atomic_tools(self) -> None:
        self.assertEqual(
            tool_ids(),
            (
                "windows.event.system",
                "windows.event.application",
                "windows.event.security",
                "windows.printer.queue",
                "network.ssh.probe",
                "network.smb.probe",
                "network.printer.ipp_probe",
                "network.printer.raw_probe",
            ),
        )
        self.assertEqual(len(TOOL_SPECS), len(tool_ids()))
        self.assertTrue(all(spec.risk == "read_only" for spec in TOOL_SPECS.values()))
        self.assertTrue(all(spec.cost in {"C1", "C2"} for spec in TOOL_SPECS.values()))

    def test_security_event_metadata_marks_admin_and_sensitive_output(self) -> None:
        spec = get_tool_spec("windows.event.security")
        self.assertTrue(spec.requires_admin)
        self.assertTrue(spec.sensitive_outputs)
        self.assertEqual(spec.network_access, "none")

    def test_selector_is_targeted_and_cost_bounded(self) -> None:
        ssh = select_tools("SSH server 192.168.11.10 is unreachable", platform_name="Windows")
        self.assertEqual(tuple(spec.id for spec in ssh), ("network.ssh.probe",))

        printer = select_tools("May in mang khong in", platform_name="Windows")
        printer_ids = {spec.id for spec in printer}
        self.assertIn("windows.printer.queue", printer_ids)
        self.assertIn("network.printer.ipp_probe", printer_ids)
        self.assertIn("network.printer.raw_probe", printer_ids)
        self.assertNotIn("windows.event.security", printer_ids)

    def test_windows_event_plan_uses_fixed_channel_and_bounded_integers(self) -> None:
        plan = build_windows_event_plan("windows.event.system", hours=24, max_events=200)
        self.assertEqual(plan[:4], ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command"))
        self.assertIn("LogName='System'", plan[4])
        self.assertIn("AddHours(-24)", plan[4])
        self.assertIn("-MaxEvents 200", plan[4])
        forbidden = ("Clear-EventLog", "Restart-Service", "Stop-Service", "Set-Item", "Remove-Item")
        self.assertFalse(any(token in plan[4] for token in forbidden))

        with self.assertRaises(ValueError):
            build_windows_event_plan("windows.event.system", hours=0)
        with self.assertRaises(ValueError):
            build_windows_event_plan("windows.event.system", max_events=1001)
        with self.assertRaises(ValueError):
            build_windows_event_plan("windows.event.system;Remove-Item", hours=24)

    def test_printer_queue_plan_is_read_only(self) -> None:
        plan = build_windows_printer_queue_plan()
        self.assertIn("Get-Printer", plan[4])
        self.assertIn("ConvertTo-Json", plan[4])
        self.assertNotIn("Remove-Printer", plan[4])
        self.assertNotIn("Set-Printer", plan[4])
        self.assertNotIn("Restart-Service", plan[4])

    def test_network_targets_are_private_ip_literals_only(self) -> None:
        self.assertTrue(is_internal_ip_literal("192.168.11.196"))
        self.assertTrue(is_internal_ip_literal("10.0.0.2"))
        self.assertTrue(is_internal_ip_literal("172.16.5.7"))
        self.assertTrue(is_internal_ip_literal("127.0.0.1"))
        self.assertTrue(is_internal_ip_literal("fe80::1"))
        self.assertTrue(is_internal_ip_literal("fd00::1"))
        self.assertFalse(is_internal_ip_literal("8.8.8.8"))
        self.assertFalse(is_internal_ip_literal("example.com"))
        self.assertFalse(is_internal_ip_literal("203.0.113.10"))

    def test_internal_network_probe_requires_exact_task_authority(self) -> None:
        authority = _authority("network.ssh.probe")
        decision = authority.authorize(
            "network.ssh.probe",
            resource_kind="network_endpoint",
            resource_ref="192.168.11.10:22",
            effect="network_read",
        )
        self.assertTrue(decision.allowed)
        self.assertEqual(decision.reason_code, "CAPABILITY_AUTHORIZED")

        wrong_kind = authority.authorize(
            "network.ssh.probe",
            resource_kind="url",
            resource_ref="192.168.11.10:22",
            effect="network_read",
        )
        self.assertFalse(wrong_kind.allowed)
        self.assertEqual(wrong_kind.reason_code, "RESOURCE_KIND_NOT_AUTHORIZED")

        denied = authority.derive_child(task_id="office-it-denied", network_scope="deny")
        denied_decision = denied.authorize(
            "network.ssh.probe",
            resource_kind="network_endpoint",
            resource_ref="192.168.11.10:22",
            effect="network_read",
        )
        self.assertFalse(denied_decision.allowed)
        self.assertEqual(denied_decision.reason_code, "NETWORK_SCOPE_NOT_AUTHORIZED")

    def test_local_event_tool_is_first_class_task_capability(self) -> None:
        authority = _authority("windows.event.system")
        decision = authority.authorize(
            "windows.event.system",
            resource_kind="event_channel",
            resource_ref="windows:event:System",
            effect="read",
        )
        self.assertTrue(decision.allowed)

    def test_internal_network_tool_fails_closed_outside_internal_scope(self) -> None:
        with self.assertRaisesRegex(TaskContractError, "network_scope=internal_only"):
            TaskContractCompiler().compile(
                task_id="office-it-confidential-deny",
                task_type="analysis",
                sensitivity="confidential",
                allowed_tools=("network.smb.probe",),
            )


if __name__ == "__main__":
    unittest.main()
