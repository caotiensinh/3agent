from __future__ import annotations

import inspect
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import three_agent.chat_gateway_v18 as gateway
import three_agent.security_pcap_runner as runner
from three_agent.security_monitoring.incident_capture import CAPTURE_CONFIRMATION


ROOT = Path(__file__).resolve().parents[1]


class PcapRunnerBoundaryTests(unittest.TestCase):
    def test_runner_rejects_arbitrary_approval_identifier_before_execution(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = Path(tmp) / "monitoring.json"
            config.write_text("{}", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "approval_id|invalid"):
                # Normalize the implementation-specific contract exception to ValueError family.
                try:
                    runner.run_capture(
                        config_path=config.resolve(),
                        approval_id="../../approval-deadbeef",
                        confirmation=CAPTURE_CONFIRMATION,
                    )
                except Exception as exc:
                    if isinstance(exc, ValueError):
                        raise
                    raise ValueError(str(exc)) from exc

    @unittest.skipUnless(runner.os.name == "posix", "dedicated PCAP runner is POSIX-only")
    def test_runner_returns_metadata_only_and_builds_path_from_approval_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config_path = root / "monitoring.json"
            config_path.write_text("{}", encoding="utf-8")
            approvals = root / "approvals"
            captures = root / "captures"
            approvals.mkdir()
            captures.mkdir()
            policy = SimpleNamespace(
                enabled=True,
                approval_root=approvals,
            )
            receipt = SimpleNamespace(
                schema_version="workspace-security-monitoring/incident-capture-receipt-v1",
                capture_id="pcap-" + "a" * 24,
                approval_id="approval-" + "a" * 24,
                pcap_sha256="sha256:" + "b" * 64,
                captured_bytes=128,
                completed_at="2026-08-30T16:00:00+00:00",
                retention_expires_at="2026-08-30T17:00:00+00:00",
                stop_reason="packet_budget",
                evidence_ref="pcap:" + "a" * 24,
            )
            seen = {}

            def fake_execute(path, **kwargs):
                seen["path"] = path
                seen["kwargs"] = kwargs
                return receipt

            with (
                patch.object(runner, "load_runtime_config", return_value=object()),
                patch.object(runner.IncidentCapturePolicy, "from_environment", return_value=policy),
                patch.object(runner, "execute_capture_approval", side_effect=fake_execute),
            ):
                result = runner.run_capture(
                    config_path=config_path.resolve(),
                    approval_id="approval-" + "a" * 24,
                    confirmation=CAPTURE_CONFIRMATION,
                    env={},
                )
            self.assertEqual(seen["path"], approvals / ("approval-" + "a" * 24 + ".json"))
            self.assertEqual(result["status"], "completed")
            self.assertNotIn("path", result)
            self.assertNotIn("interface", result)
            self.assertNotIn("filter", result)
            self.assertNotIn("approver", result)

    def test_runner_source_has_no_model_shell_or_arbitrary_path_authority(self):
        source = inspect.getsource(runner)
        self.assertIn("_APPROVAL_ID_RE", source)
        self.assertIn("CAPTURE_CONFIRMATION", source)
        self.assertNotIn("OllamaClient", source)
        self.assertNotIn("generate_json", source)
        self.assertNotIn("shell=True", source)
        self.assertNotIn("argparse.REMAINDER", source)


class PcapGatewayBoundaryTests(unittest.TestCase):
    def test_gateway_adds_only_admin_approval_not_capture_execution(self):
        helper = inspect.getsource(gateway.SecurityApprovalHTTPHandler._security_pcap_approve)
        self.assertIn("self._require_admin()", helper)
        self.assertIn("approve_capture_request", helper)
        self.assertIn("persist_capture_approval", helper)
        self.assertNotIn("execute_capture_approval", helper)

        post = inspect.getsource(gateway.SecurityApprovalHTTPHandler.do_POST)
        self.assertIn('/api/security/pcap/approve', post)
        self.assertNotIn('/api/security/pcap/execute', post)
        self.assertNotIn("execute_capture_approval", post)

    def test_gateway_approval_response_is_metadata_only(self):
        source = inspect.getsource(gateway.SecurityApprovalHTTPHandler._security_pcap_approve)
        self.assertIn("approval.public_dict()", source)
        for forbidden in (
            "filter_expression",
            "management_host",
            "approved_by_sha256",
            "tcpdump_path",
            "capture_root",
        ):
            self.assertNotIn(forbidden, source)

    def test_optional_pcap_misconfiguration_does_not_take_down_chat(self):
        source = inspect.getsource(gateway.SecurityApprovalApplication.__init__)
        self.assertIn("self.security_pcap_policy = None", source)
        self.assertIn('self.security_pcap_state = "configuration_error"', source)


class PcapSystemdBoundaryTests(unittest.TestCase):
    def test_dedicated_service_has_bounded_packet_capabilities_and_no_restart_loop(self):
        service = (
            ROOT / "scripts/systemd/workspace-security-pcap@.service"
        ).read_text(encoding="utf-8")
        for token in (
            "User=workspace-pcap",
            "Group=workspace-pcap",
            "NoNewPrivileges=true",
            "RestrictAddressFamilies=AF_UNIX AF_PACKET",
            "CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN",
            "AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN",
            "IPAddressDeny=any",
            "KillMode=control-group",
            "TimeoutStartSec=16min",
            "TimeoutStopSec=5s",
            "--approval-id %i",
            "--confirmation AUTHORIZE_PCAP",
        ):
            self.assertIn(token, service)
        self.assertNotIn("Restart=", service)
        self.assertNotIn("AF_INET", service)
        self.assertNotIn("AF_INET6", service)

    def test_package_entrypoints_use_v18_and_expose_dedicated_runner(self):
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('workspace-chat = "three_agent.chat_gateway_v18:main"', project)
        self.assertIn('three-agent-chat = "three_agent.chat_gateway_v18:main"', project)
        self.assertIn('workspace-security-pcap = "three_agent.security_pcap_runner:main"', project)


if __name__ == "__main__":
    unittest.main()
