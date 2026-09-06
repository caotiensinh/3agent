from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from three_agent.security_local_console import build_server
from three_agent.security_monitoring.analyst_console import safe_analyst_snapshot
from three_agent.security_monitoring.demo import create_demo_environment
from three_agent.security_monitoring.runtime_config import load_runtime_config
from three_agent.security_monitoring.service import SecurityMonitoringService


class SecurityCapabilityMatrixConsoleTests(unittest.TestCase):
    def test_demo_analyst_snapshot_exposes_activation_matrix_without_execution_authority(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config_path = create_demo_environment(Path(temp))
            config = load_runtime_config(config_path)
            snapshot = safe_analyst_snapshot(config, config_saved=True)

        admin = snapshot["admin"]
        matrix = admin["capability_matrix"]
        self.assertEqual(
            matrix["schema_version"],
            "workspace-security-monitoring/capability-matrix-v1",
        )
        self.assertFalse(matrix["real_network_read_enabled"])
        operations = {item["name"]: item for item in matrix["local_operations"]}
        self.assertEqual(operations["run_hourly_readonly"]["state"], "gated")
        self.assertEqual(
            operations["run_hourly_readonly"]["reason_code"],
            "REAL_NETWORK_NOT_ALLOWED",
        )
        restricted = {item["name"]: item for item in matrix["restricted_surfaces"]}
        for name in (
            "arbitrary_target_scan",
            "credential_entry",
            "packet_capture",
            "remediation",
            "shell_execution",
        ):
            self.assertEqual(restricted[name]["state"], "disabled")

        serialized = json.dumps(matrix, sort_keys=True)
        for sensitive in (
            "demo-router-01",
            "demo-switch-01",
            "demo-camera-01",
            "demo-workstation-01",
            "192.0.2.10",
            "192.0.2.20",
            "192.0.2.30",
            "192.0.2.40",
        ):
            self.assertNotIn(sensitive, serialized)

    def test_http_analyst_snapshot_contains_matrix_and_remains_read_only(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config_path = create_demo_environment(Path(temp))
            service = SecurityMonitoringService(config_path)
            server = build_server(
                "127.0.0.1",
                0,
                service,
                csrf_token="a" * 64,
                csp_nonce="b" * 32,
                demo_mode=True,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                conn = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=3)
                conn.request(
                    "GET",
                    "/api/v1/security/monitoring/analyst-snapshot?target=192.0.2.99&capability=packet_capture",
                )
                response = conn.getresponse()
                raw = response.read().decode("utf-8")
                headers = {key.lower(): value for key, value in response.getheaders()}
                status = response.status
                conn.close()

                self.assertEqual(status, 200)
                self.assertEqual(headers["cache-control"], "no-store")
                payload = json.loads(raw)
                matrix = payload["admin"]["capability_matrix"]
                self.assertTrue(matrix["authority"]["metadata_only"])
                self.assertFalse(matrix["authority"]["browser_filters_exposed"])
                self.assertFalse(matrix["authority"]["network_execution"])
                self.assertFalse(matrix["authority"]["collector_execution"])
                self.assertFalse(matrix["authority"]["packet_capture_execution"])
                self.assertFalse(matrix["authority"]["remediation_execution"])
                self.assertNotIn("192.0.2.99", raw)
                self.assertNotIn("capability=packet_capture", raw)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
