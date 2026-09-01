from __future__ import annotations

import inspect
import unittest
from pathlib import Path

import three_agent.chat_gateway_v18 as gateway
import three_agent.security_pcap_runner as runner
from three_agent.security_monitoring.incident_capture import CAPTURE_CONFIRMATION


ROOT = Path(__file__).resolve().parents[1]


class PcapIntegrationBoundaryTests(unittest.TestCase):
    def test_gateway_is_approval_only_and_runner_is_separate(self):
        helper = inspect.getsource(gateway.SecurityMonitoringHTTPHandler._security_pcap_approve)
        self.assertIn("self._require_admin()", helper)
        self.assertIn("approve_capture_request", helper)
        self.assertIn("persist_capture_approval", helper)
        self.assertIn("dedicated_runner_required", helper)
        self.assertNotIn("execute_capture_approval", helper)
        post = inspect.getsource(gateway.SecurityMonitoringHTTPHandler.do_POST)
        self.assertIn('/api/security/pcap/approve', post)
        self.assertNotIn('/api/security/pcap/execute', post)

    def test_dedicated_runner_has_literal_execution_confirmation_and_no_model_authority(self):
        source = inspect.getsource(runner)
        self.assertIn("CAPTURE_CONFIRMATION", source)
        self.assertEqual(CAPTURE_CONFIRMATION, "AUTHORIZE_PCAP")
        self.assertNotIn("OllamaClient", source)
        self.assertNotIn("generate_json", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("argparse.REMAINDER", source)

    def test_dedicated_service_has_bounded_packet_capabilities(self):
        service = (ROOT / "scripts/systemd/workspace-security-pcap@.service").read_text(encoding="utf-8")
        for token in (
            "User=workspace-pcap",
            "Group=workspace-pcap",
            "NoNewPrivileges=true",
            "RestrictAddressFamilies=AF_UNIX AF_PACKET",
            "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN",
            "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN",
            "IPAddressDeny=any",
            "KillMode=control-group",
            "--approval-id %i",
            "--confirmation AUTHORIZE_PCAP",
        ):
            self.assertIn(token, service)
        self.assertNotIn("AF_INET", service)
        self.assertNotIn("AF_INET6", service)
        self.assertNotIn("Restart=", service)

    def test_package_entrypoints_use_v19_overlay_and_keep_v18_security_boundary(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('workspace-chat = "three_agent.chat_gateway_v19:main"', project)
        self.assertIn('three-agent-chat = "three_agent.chat_gateway_v19:main"', project)
        self.assertIn('workspace-security-pcap = "three_agent.security_pcap_runner:main"', project)
        self.assertIn('workspace-security-monitor = "three_agent.security_monitoring_cli:main"', project)
        self.assertIn('workspace-security-report = "three_agent.security_reporting_cli:main"', project)
        v19 = (ROOT / "src/three_agent/chat_gateway_v19.py").read_text(encoding="utf-8")
        self.assertIn("from . import chat_gateway_v18 as _v18", v19)
        self.assertIn("return _v18.main()", v19)
        self.assertTrue((ROOT / "src/three_agent/chat_gateway_v18.py").is_file())


if __name__ == "__main__":
    unittest.main()
