from __future__ import annotations

import os
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from three_agent.diagnostics.common_tools import (
    COMMON_TOOL_BY_ID,
    build_common_read_plan,
    common_micro_tool_registry,
    common_tool_metadata,
    execute_common_read,
)


class RecordingAuthority:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, str]] = []

    def require(
        self,
        capability: str,
        *,
        resource_kind: str,
        resource_ref: str,
        effect: str,
    ) -> None:
        self.calls.append((capability, resource_kind, resource_ref, effect))


class CommonDiagnosticToolsTests(unittest.TestCase):
    def test_registry_contains_exactly_nine_unique_atomic_tools(self) -> None:
        metadata = common_tool_metadata()
        self.assertEqual(len(metadata), 9)
        self.assertEqual(len({item.id for item in metadata}), 9)
        self.assertEqual(len(common_micro_tool_registry().metadata_view()), 9)

    def test_all_common_tools_are_local_read_only_and_never_egress(self) -> None:
        for tool in common_tool_metadata():
            self.assertEqual(tool.effect, "read")
            self.assertEqual(tool.network_access, "none")
            self.assertIn(tool.risk, {"read_only", "sensitive_read"})
            self.assertFalse(tool.id.startswith("remediate."))

    def test_sensitive_network_configuration_tools_are_marked_sensitive(self) -> None:
        for tool_id in (
            "network.interface.snapshot",
            "network.ipconfig.snapshot",
            "network.route.snapshot",
            "network.dns.snapshot",
        ):
            self.assertTrue(COMMON_TOOL_BY_ID[tool_id].sensitive_outputs)

    def test_windows_and_linux_ipconfig_plans_are_fixed_argv(self) -> None:
        self.assertEqual(
            build_common_read_plan("network.ipconfig.snapshot", platform_name="Windows"),
            ("ipconfig.exe", "/all"),
        )
        self.assertEqual(
            build_common_read_plan("network.ipconfig.snapshot", platform_name="Linux"),
            ("ip", "-j", "address", "show"),
        )

    def test_windows_and_linux_route_plans_are_fixed_argv(self) -> None:
        self.assertEqual(
            build_common_read_plan("network.route.snapshot", platform_name="Windows"),
            ("route.exe", "print"),
        )
        self.assertEqual(
            build_common_read_plan("network.route.snapshot", platform_name="Linux"),
            ("ip", "-j", "route", "show", "table", "all"),
        )

    def test_time_sync_plans_are_read_only(self) -> None:
        self.assertEqual(
            build_common_read_plan("time.sync.status", platform_name="Windows"),
            ("w32tm.exe", "/query", "/status"),
        )
        linux = build_common_read_plan("time.sync.status", platform_name="Linux")
        self.assertEqual(linux[0], "timedatectl")
        self.assertIn("--property=NTPSynchronized", linux)

    def test_service_name_injection_is_rejected_before_subprocess(self) -> None:
        with self.assertRaisesRegex(ValueError, "service_name contains unsupported characters"):
            build_common_read_plan(
                "service.status.read",
                platform_name="Linux",
                service_name="ssh; rm -rf /",
            )

    def test_service_status_plan_passes_service_as_one_argv_item(self) -> None:
        windows = build_common_read_plan(
            "service.status.read",
            platform_name="Windows",
            service_name="Spooler",
        )
        self.assertEqual(windows, ("sc.exe", "query", "Spooler"))
        linux = build_common_read_plan(
            "service.status.read",
            platform_name="Linux",
            service_name="sshd.service",
        )
        self.assertEqual(linux[0:3], ("systemctl", "show", "sshd.service"))

    def test_platform_identify_requires_authority_and_returns_structured_evidence(self) -> None:
        authority = RecordingAuthority()
        result = execute_common_read("system.platform.identify", authority=authority)  # type: ignore[arg-type]
        self.assertEqual(result["tool_id"], "system.platform.identify")
        self.assertTrue(result["system"])
        self.assertEqual(
            authority.calls,
            [("system.platform.identify", "system_inventory", "local:platform", "read")],
        )

    def test_resource_snapshot_requires_authority_and_returns_machine_state(self) -> None:
        authority = RecordingAuthority()
        result = execute_common_read("system.resource.snapshot", authority=authority)  # type: ignore[arg-type]
        self.assertEqual(result["tool_id"], "system.resource.snapshot")
        self.assertIn("cpu_count_logical", result)
        self.assertIn("memory_total_bytes", result)
        self.assertEqual(authority.calls[0][0], "system.resource.snapshot")

    @patch("three_agent.diagnostics.common_tools.shutil.disk_usage")
    def test_storage_capacity_uses_only_default_local_system_volume(self, disk_usage_mock) -> None:
        disk_usage_mock.return_value = SimpleNamespace(total=100, used=40, free=60)
        authority = RecordingAuthority()
        result = execute_common_read(
            "system.storage.capacity",
            authority=authority,  # type: ignore[arg-type]
        )
        self.assertEqual(result["tool_id"], "system.storage.capacity")
        self.assertEqual(result["scope"], "default_local_system_volume")
        self.assertEqual(result["total_bytes"], 100)
        self.assertEqual(result["used_bytes"], 40)
        self.assertEqual(result["free_bytes"], 60)
        self.assertEqual(
            authority.calls,
            [("system.storage.capacity", "filesystem_capacity", "local:storage:default", "read")],
        )
        disk_usage_mock.assert_called_once()

    @patch("three_agent.diagnostics.common_tools.shutil.disk_usage")
    def test_storage_capacity_rejects_all_custom_paths_before_authority_or_disk_access(
        self,
        disk_usage_mock,
    ) -> None:
        for candidate in (".", "/tmp", "//server/share", r"\\server\share"):
            with self.subTest(candidate=candidate):
                authority = RecordingAuthority()
                with self.assertRaisesRegex(
                    ValueError,
                    "default local system volume only",
                ):
                    execute_common_read(
                        "system.storage.capacity",
                        authority=authority,  # type: ignore[arg-type]
                        storage_path=candidate,
                    )
                self.assertEqual(authority.calls, [])
        disk_usage_mock.assert_not_called()

    @patch("three_agent.diagnostics.common_tools.shutil.disk_usage")
    def test_windows_system_drive_environment_cannot_redirect_storage_to_unc(
        self,
        disk_usage_mock,
    ) -> None:
        disk_usage_mock.return_value = SimpleNamespace(total=100, used=40, free=60)
        authority = RecordingAuthority()
        with patch("three_agent.diagnostics.common_tools.platform.system", return_value="Windows"):
            with patch.dict(os.environ, {"SystemDrive": r"\\server\share"}, clear=False):
                execute_common_read(
                    "system.storage.capacity",
                    authority=authority,  # type: ignore[arg-type]
                )
        disk_usage_mock.assert_called_once_with("C:\\")
        self.assertEqual(authority.calls[0][2], "local:storage:default")

    def test_interface_snapshot_is_local_only_and_authorized(self) -> None:
        authority = RecordingAuthority()
        result = execute_common_read("network.interface.snapshot", authority=authority)  # type: ignore[arg-type]
        self.assertEqual(result["tool_id"], "network.interface.snapshot")
        self.assertIsInstance(result["interfaces"], tuple)
        self.assertEqual(authority.calls[0][2], "local:interfaces")

    @patch("three_agent.diagnostics.common_tools.subprocess.run")
    def test_subprocess_reads_never_use_shell(self, run_mock) -> None:
        run_mock.return_value = subprocess.CompletedProcess(
            args=("ip", "-j", "address", "show"),
            returncode=0,
            stdout="[]",
            stderr="",
        )
        authority = RecordingAuthority()
        result = execute_common_read("network.ipconfig.snapshot", authority=authority)  # type: ignore[arg-type]
        self.assertEqual(result["returncode"], 0)
        self.assertTrue(run_mock.called)
        _, kwargs = run_mock.call_args
        self.assertIs(kwargs["shell"], False)
        self.assertIs(kwargs["check"], False)

    @patch("three_agent.diagnostics.common_tools.Path.exists", return_value=False)
    def test_linux_dns_snapshot_reads_local_files_without_network_call(self, _exists) -> None:
        authority = RecordingAuthority()
        with patch("three_agent.diagnostics.common_tools.platform.system", return_value="Linux"):
            result = execute_common_read("network.dns.snapshot", authority=authority)  # type: ignore[arg-type]
        self.assertEqual(result, {"tool_id": "network.dns.snapshot", "sources": ()})
        self.assertEqual(authority.calls[0][2], "local:dns")

    def test_unknown_tool_fails_closed(self) -> None:
        authority = RecordingAuthority()
        with self.assertRaisesRegex(ValueError, "unknown common diagnostic tool"):
            execute_common_read("system.magic.fix", authority=authority)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()
