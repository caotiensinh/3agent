from __future__ import annotations

import unittest

from three_agent.adaptive_diagnostic_router import select_pc_diagnostic_tool_metadata


class EnterpriseSkillToolNegativePathE2ETests(unittest.TestCase):
    """Protect cross-domain routing from over-selection and subsystem confusion."""

    def test_vpn_authentication_failure_does_not_force_route_snapshot(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "VPN login fail sau khi doi mat khau",
            platform_name="Windows",
            max_tools=4,
        )
        self.assertNotIn("network.route.snapshot", result.selected_ids())
        self.assertTrue(all(item.effect in {"read", "network_read", "compute"} for item in result.selected))

    def test_teams_camera_not_detected_selects_local_camera_inventory(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "Teams camera khong nhan",
            platform_name="Windows",
            max_tools=4,
        )
        self.assertIn("camera.devices.snapshot", result.selected_ids())
        self.assertTrue(all(item.network_access != "allowlisted_egress" for item in result.selected))

    def test_teams_no_sound_selects_audio_device_evidence(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "Teams khong co tieng",
            platform_name="Windows",
            max_tools=4,
        )
        self.assertIn("audio.devices.snapshot", result.selected_ids())

    def test_cctv_poe_failure_does_not_select_local_webcam_inventory(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "Camera mat sau khi PoE switch reboot",
            platform_name="Windows",
            max_tools=4,
        )
        self.assertNotIn("camera.devices.snapshot", result.selected_ids())
        self.assertTrue(all(item.effect in {"read", "network_read", "compute"} for item in result.selected))

    def test_blue_screen_after_windows_update_selects_system_and_update_evidence(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "May bi man hinh xanh sau Windows Update",
            platform_name="Windows",
            max_tools=4,
        )
        ids = set(result.selected_ids())
        self.assertIn("windows.event.system", ids)
        self.assertIn("windows.update.history", ids)


if __name__ == "__main__":
    unittest.main()
