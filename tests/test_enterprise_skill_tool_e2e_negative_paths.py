from __future__ import annotations

import unittest

from three_agent.adaptive_diagnostic_router import select_pc_diagnostic_tool_metadata
from three_agent.diagnostics.complaint_semantics import normalize_complaint_semantics


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

    def test_vpn_authentication_context_suppresses_incidental_gateway_route_match(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "VPN login fail sau khi doi mat khau, gateway 192.168.11.1",
            platform_name="Windows",
            max_tools=4,
        )
        self.assertNotIn("network.route.snapshot", result.selected_ids())
        rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
        self.assertIn(("network.route.snapshot", "CROSS_DOMAIN_VPN_AUTH"), rejected)

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

    def test_remote_camera_japanese_wording_suppresses_local_webcam_inventory(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "監視カメラ RTSP が見られない",
            platform_name="Windows",
            max_tools=4,
        )
        self.assertNotIn("camera.devices.snapshot", result.selected_ids())
        rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
        self.assertIn(("camera.devices.snapshot", "CROSS_DOMAIN_REMOTE_CAMERA"), rejected)

    def test_blue_screen_after_windows_update_selects_system_and_update_evidence(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "May bi man hinh xanh sau Windows Update",
            platform_name="Windows",
            max_tools=4,
        )
        ids = set(result.selected_ids())
        self.assertIn("windows.event.system", ids)
        self.assertIn("windows.update.history", ids)

    def test_router_failure_wording_remains_customer_hypothesis(self) -> None:
        semantics = normalize_complaint_semantics("Router chet roi, may toi khong vao mang duoc")
        self.assertIn("router_failure", semantics.customer_hypotheses)
        self.assertIn("expected_network_access_unavailable", semantics.canonical_symptoms)
        self.assertNotIn("router_failure", semantics.canonical_symptoms)

    def test_router_failure_hypothesis_only_selects_bounded_network_evidence(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "Router chet roi, may toi khong vao mang duoc",
            platform_name="Windows",
            max_tools=4,
        )
        ids = set(result.selected_ids())
        self.assertIn("network.ipconfig.snapshot", ids)
        self.assertTrue({"network.route.snapshot", "network.dns.snapshot"}.intersection(ids))
        self.assertTrue(all(item.effect in {"read", "network_read", "compute"} for item in result.selected))
        self.assertTrue(all(item.network_access != "allowlisted_egress" for item in result.selected))

    def test_explicit_malware_denial_is_not_promoted_to_security_hypothesis(self) -> None:
        for text in (
            "May cham nhung khong phai bi virus",
            "May cham, khong nghi la bi virus",
            "PC slow, probably not infected by malware",
        ):
            with self.subTest(text=text):
                semantics = normalize_complaint_semantics(text)
                self.assertNotIn("malware_infection", semantics.customer_hypotheses)

    def test_positive_malware_guess_is_hypothesis_not_observed_symptom(self) -> None:
        semantics = normalize_complaint_semantics("May cham, chac bi virus roi")
        self.assertIn("malware_infection", semantics.customer_hypotheses)
        self.assertNotIn("malware_infection", semantics.canonical_symptoms)

    def test_hostname_failure_with_ip_connectivity_selects_dns_evidence(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "Server vao duoc bang IP nhung hostname khong resolve",
            platform_name="Windows",
            max_tools=4,
        )
        self.assertIn("network.dns.snapshot", result.selected_ids())
        semantics = normalize_complaint_semantics("Server vao duoc bang IP nhung hostname khong resolve")
        self.assertIn("hostname_resolution_unavailable", semantics.canonical_symptoms)

    def test_gateway_reachable_but_internet_unavailable_keeps_local_network_evidence(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "Ping gateway duoc nhung khong co internet",
            platform_name="Windows",
            max_tools=4,
        )
        ids = set(result.selected_ids())
        self.assertIn("network.ipconfig.snapshot", ids)
        self.assertIn("network.dns.snapshot", ids)
        self.assertTrue(all(item.network_access != "allowlisted_egress" for item in result.selected))

    def test_file_share_access_denied_does_not_become_generic_reachability_failure(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "Shared folder tren server bao Access Denied",
            platform_name="Windows",
            max_tools=4,
        )
        ids = set(result.selected_ids())
        self.assertIn("network.smb.probe", ids)
        self.assertNotIn("network.reachability.internal", ids)

    def test_cctv_rtsp_failure_does_not_select_local_webcam_inventory(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "Camera ping duoc nhung RTSP khong xem duoc",
            platform_name="Windows",
            max_tools=4,
        )
        self.assertNotIn("camera.devices.snapshot", result.selected_ids())
        self.assertIn("network.reachability.internal", result.selected_ids())
        self.assertTrue(all(item.effect in {"read", "network_read", "compute"} for item in result.selected))

    def test_switch_failure_wording_is_hypothesis_and_does_not_grant_control(self) -> None:
        semantics = normalize_complaint_semantics("Switch chet hay sao ay, ca phong mat mang")
        self.assertIn("switch_failure", semantics.customer_hypotheses)
        result = select_pc_diagnostic_tool_metadata(
            "Switch chet hay sao ay, ca phong mat mang",
            platform_name="Windows",
            max_tools=4,
        )
        self.assertTrue(result.selected)
        self.assertTrue(all(item.effect in {"read", "network_read", "compute"} for item in result.selected))
        self.assertTrue(all(item.risk in {"read_only", "sensitive_read"} for item in result.selected))


if __name__ == "__main__":
    unittest.main()
