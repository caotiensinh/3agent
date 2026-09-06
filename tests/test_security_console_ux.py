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
from three_agent.security_monitoring.operator_posture_reader import safe_operator_posture_summary
from three_agent.security_monitoring.runtime_config import load_runtime_config
from three_agent.security_monitoring.service import SecurityMonitoringService


class SecurityConsoleUXTests(unittest.TestCase):
    def test_demo_dataset_exercises_real_backend_projections_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config_path = create_demo_environment(Path(temp))
            config = load_runtime_config(config_path)
            self.assertTrue(config.enabled)
            self.assertFalse(config.allow_real_network)
            self.assertFalse(config.policy.allow_active_liveness)
            self.assertEqual(config.policy.packet_analysis_mode, "passive_only")

            analyst = safe_analyst_snapshot(config)
            self.assertEqual(analyst["data_state"], "available")
            self.assertEqual(len(analyst["assets"]), 4)
            self.assertEqual(len(analyst["network"]), 4)
            self.assertEqual(len(analyst["events"]), 5)
            self.assertEqual(len(analyst["findings"]), 2)

            serialized = json.dumps(analyst, sort_keys=True)
            for sensitive in (
                "demo-router-01",
                "demo-switch-01",
                "demo-camera-01",
                "demo-workstation-01",
                "192.0.2.10",
                "192.0.2.20",
                "192.0.2.30",
                "192.0.2.40",
                "198.51.100.10",
                "198.51.100.20",
                "demo-event-dns",
                "demo-finding-critical",
                "demo-rule-multi-stage",
            ):
                self.assertNotIn(sensitive, serialized)

            authority = analyst["authority"]
            self.assertTrue(authority["database_read_only"])
            self.assertFalse(authority["database_write"])
            self.assertFalse(authority["network_execution"])
            self.assertFalse(authority["collector_execution"])
            self.assertFalse(authority["packet_capture_execution"])
            self.assertFalse(authority["remediation_execution"])

            operator = safe_operator_posture_summary(config)
            self.assertEqual(operator["data_state"], "available")
            self.assertGreater(operator["correlation"]["incident_graph_count"], 0)
            self.assertGreater(operator["correlation"]["multi_stage_graph_count"], 0)
            self.assertTrue(operator["flow"]["available"])
            self.assertGreater(operator["flow"]["flow_event_count"], 0)
            self.assertTrue(operator["timeline"]["available"])
            self.assertGreater(operator["timeline"]["entry_count"], 0)

    def test_demo_http_surface_connects_backend_and_blocks_real_network_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            config_path = create_demo_environment(Path(temp))
            service = SecurityMonitoringService(config_path)
            csrf = "a" * 64
            server = build_server(
                "127.0.0.1",
                0,
                service,
                csrf_token=csrf,
                csp_nonce="b" * 32,
                demo_mode=True,
            )
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_port

                def request(method: str, path: str, payload: dict[str, object] | None = None):
                    body = None
                    headers: dict[str, str] = {}
                    if payload is not None:
                        body = json.dumps(payload).encode("utf-8")
                        headers["Content-Type"] = "application/json"
                        headers["X-Workspace-CSRF"] = csrf
                    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                    conn.request(method, path, body=body, headers=headers)
                    response = conn.getresponse()
                    raw = response.read()
                    result = json.loads(raw.decode("utf-8")) if response.getheader("Content-Type", "").startswith("application/json") else raw.decode("utf-8")
                    status = response.status
                    conn.close()
                    return status, result

                status, health = request("GET", "/api/v1/health")
                self.assertEqual(status, 200)
                self.assertTrue(health["demo_mode"])
                self.assertFalse(health["write_authority"])

                status, analyst = request("GET", "/api/v1/security/monitoring/analyst-snapshot?asset_id=secret&limit=9999")
                self.assertEqual(status, 200)
                self.assertEqual(analyst["max_rows_per_stream"], 50)
                self.assertEqual(len(analyst["events"]), 5)

                status, operator = request("GET", "/api/v1/security/monitoring/operator-posture")
                self.assertEqual(status, 200)
                self.assertGreater(operator["correlation"]["incident_graph_count"], 0)

                status, blocked = request(
                    "POST",
                    "/api/v1/security/monitoring/run-hourly",
                    {"confirm_readonly": True},
                )
                self.assertEqual(status, 409)
                self.assertEqual(blocked["reason_code"], "DEMO_MODE_NETWORK_EXECUTION_DISABLED")

                status, initialized = request(
                    "POST",
                    "/api/v1/security/monitoring/initialize",
                    {"confirm_initialize": True},
                )
                self.assertEqual(status, 200)
                self.assertEqual(initialized["status"], "initialized")
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
