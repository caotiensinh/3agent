from __future__ import annotations

import unittest
from unittest.mock import MagicMock, patch

from three_agent.adaptive_diagnostic_router import select_pc_diagnostic_tool_metadata
from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.office_it_tools import TOOL_SPECS, probe_rtsp_service
from three_agent.task_contract import TaskContractCompiler


def _authority() -> TaskCapabilityAuthority:
    contract = TaskContractCompiler().compile(
        task_id="rtsp-service-probe-test",
        task_type="analysis",
        sensitivity="internal",
        allowed_tools=("network.rtsp.probe",),
    )
    return TaskCapabilityAuthority.from_contract(contract)


class RTSPServiceProbeTests(unittest.TestCase):
    def test_rtsp_probe_metadata_is_fixed_internal_read_only_evidence(self) -> None:
        spec = TOOL_SPECS["network.rtsp.probe"]
        self.assertEqual(spec.fixed_port, 554)
        self.assertEqual(spec.network_access, "internal_only")
        self.assertEqual(spec.effect, "network_read")
        self.assertTrue(spec.sensitive_outputs)
        self.assertFalse(spec.requires_admin)

    def test_rtsp_probe_rejects_hostname_and_public_ip_without_network_io(self) -> None:
        authority = _authority()
        with patch("three_agent.office_it_tools.socket.create_connection") as connect:
            with self.assertRaises(ValueError):
                probe_rtsp_service("example.com", authority=authority)
            with self.assertRaises(ValueError):
                probe_rtsp_service("8.8.8.8", authority=authority)
        connect.assert_not_called()

    def test_rtsp_probe_binds_authority_to_fixed_port_and_treats_401_as_service_evidence(self) -> None:
        authority = _authority()
        connection = MagicMock()
        connection.__enter__.return_value = connection
        connection.__exit__.return_value = False
        connection.recv.return_value = b"RTSP/1.0 401 Unauthorized\r\nCSeq: 1\r\nWWW-Authenticate: Digest realm=\"camera\"\r\n\r\n"

        with patch("three_agent.office_it_tools.socket.create_connection", return_value=connection) as connect:
            result = probe_rtsp_service(
                "192.168.11.196",
                authority=authority,
                timeout_seconds=1.0,
            )

        connect.assert_called_once_with(("192.168.11.196", 554), timeout=1.0)
        request = connection.sendall.call_args.args[0]
        self.assertIn(b"OPTIONS * RTSP/1.0", request)
        self.assertIn(b"CSeq: 1", request)
        self.assertNotIn(b"Authorization:", request)
        self.assertLessEqual(len(request), 512)
        connection.recv.assert_called_once_with(4096)

        self.assertEqual(result["tool_id"], "network.rtsp.probe")
        self.assertEqual(result["target"], "192.168.11.196")
        self.assertEqual(result["port"], 554)
        self.assertTrue(result["connected"])
        self.assertTrue(result["response_received"])
        self.assertTrue(result["rtsp_service_observed"])
        self.assertTrue(result["authentication_challenge_observed"])
        self.assertEqual(result["rtsp_status_line"], "RTSP/1.0 401 Unauthorized")
        self.assertEqual(result["interpretation"], "evidence_only")

    def test_onvif_success_but_rtsp_failure_routes_to_rtsp_service_evidence(self) -> None:
        result = select_pc_diagnostic_tool_metadata(
            "ONVIF nhan camera binh thuong nhung RTSP khong xem duoc",
            platform_name="Windows",
            max_tools=4,
        )
        ids = set(result.selected_ids())
        self.assertIn("network.rtsp.probe", ids)
        self.assertNotIn("camera.devices.snapshot", ids)
        rtsp = next(item for item in result.selected if item.id == "network.rtsp.probe")
        self.assertEqual(rtsp.network_access, "internal_only")
        self.assertEqual(rtsp.effect, "network_read")


if __name__ == "__main__":
    unittest.main()
