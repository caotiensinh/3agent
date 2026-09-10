from __future__ import annotations

import unittest
from types import SimpleNamespace

from three_agent.adaptive_diagnostic_router import (
    office_it_micro_tool_registry,
    select_office_it_tool_metadata,
    select_office_it_tools,
)


class AdaptiveDiagnosticRouterTests(unittest.TestCase):
    def test_office_it_registry_is_reused_and_metadata_only(self) -> None:
        first = office_it_micro_tool_registry()
        second = office_it_micro_tool_registry()
        self.assertIs(first, second)
        metadata = first.metadata_view()
        self.assertEqual(len(metadata), 9)
        self.assertEqual({item["schema_version"] for item in metadata}, {"workspace-micro-tool-metadata/v1"})

    def test_ssh_request_routes_to_existing_atomic_tool(self) -> None:
        selected = select_office_it_tools(
            "SSH server 192.168.11.10 is unreachable",
            platform_name="Windows",
        )
        self.assertEqual(tuple(item.id for item in selected), ("network.ssh.probe",))

    def test_printer_request_uses_minimum_relevant_v0_1_capabilities(self) -> None:
        selected = select_office_it_tools(
            "May in mang khong in",
            platform_name="Windows",
        )
        ids = tuple(item.id for item in selected)
        self.assertIn("windows.printer.queue", ids)
        self.assertIn("network.printer.ipp_probe", ids)
        self.assertIn("network.printer.raw_probe", ids)
        self.assertNotIn("windows.event.security", ids)

    def test_authority_prefilter_never_expands_allowed_tools(self) -> None:
        authority = SimpleNamespace(
            allowed_tools=("network.ssh.probe",),
            network_scope="internal_only",
        )
        result = select_office_it_tool_metadata(
            "SSH and SMB are unavailable",
            platform_name="Windows",
            authority=authority,
        )
        self.assertEqual(result.selected_ids(), ("network.ssh.probe",))
        rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
        self.assertIn(("network.smb.probe", "AUTHORITY_TOOL_NOT_ALLOWED"), rejected)

    def test_router_never_enables_external_egress(self) -> None:
        result = select_office_it_tool_metadata(
            "SSH server unreachable",
            platform_name="Windows",
        )
        self.assertTrue(all(item.network_access != "allowlisted_egress" for item in result.selected))


if __name__ == "__main__":
    unittest.main()
