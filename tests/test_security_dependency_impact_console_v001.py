from __future__ import annotations

import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from three_agent.security_local_console import build_server
from three_agent.security_monitoring.demo import create_demo_environment
from three_agent.security_monitoring.service import SecurityMonitoringService


class SecurityDependencyImpactConsoleV001Tests(unittest.TestCase):
    def test_existing_operator_posture_route_renders_safe_dependency_impact(self) -> None:
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
                port = server.server_port

                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                conn.request("GET", "/")
                response = conn.getresponse()
                page = response.read().decode("utf-8")
                self.assertEqual(response.status, 200)
                conn.close()

                self.assertIn('id="operator-posture"', page)
                self.assertIn('jsonGet("/api/v1/security/monitoring/operator-posture")', page)
                self.assertIn(
                    'byId("operator-posture").textContent=JSON.stringify(operator,null,2);',
                    page,
                )
                self.assertIn('"operator-posture","readiness-json"', page)

                conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                conn.request("GET", "/api/v1/security/monitoring/operator-posture")
                response = conn.getresponse()
                payload = json.loads(response.read().decode("utf-8"))
                self.assertEqual(response.status, 200)
                conn.close()

                self.assertIn("dependency_impact", payload)
                impact = payload["dependency_impact"]
                self.assertTrue(impact["configured"])
                self.assertTrue(impact["available"])
                self.assertEqual(impact["potential_affected_asset_count"], 2)
                self.assertEqual(impact["observed_max_depth"], 2)
                self.assertFalse(impact["authority"]["browser_seed_selection"])
                self.assertFalse(impact["authority"]["database_write"])
                self.assertFalse(impact["authority"]["network_execution"])
                self.assertFalse(impact["authority"]["packet_capture_execution"])
                self.assertFalse(impact["authority"]["remediation_execution"])

                serialized = json.dumps(payload, sort_keys=True)
                for sensitive in (
                    "demo-router-01",
                    "demo-switch-01",
                    "demo-camera-01",
                    "demo-workstation-01",
                    "demo-finding-critical",
                    "demo-finding-medium",
                    "dependency-",
                    "assessment_id",
                    "seed_asset_ids",
                    "potentially_affected_asset_ids",
                    '"dependency_ids":',
                    "depth_by_asset",
                    "declaration_sha256",
                    "192.0.2.",
                ):
                    self.assertNotIn(sensitive, serialized)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
