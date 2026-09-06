from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server


class _FakeOperatorService:
    def __init__(self) -> None:
        self.operator_calls = 0
        self.run_calls = 0

    def operator_posture(self) -> dict[str, object]:
        self.operator_calls += 1
        return {
            "schema_version": "workspace-security-monitoring/operator-posture-v1",
            "count_scope": "bounded_query_only_operator_projection",
            "max_correlation_events": 100,
            "database_available": True,
            "data_state": "available",
            "risk": {"today_open_high_critical": 2},
            "asset_health": {
                "enabled_asset_sample_count": 4,
                "state_counts": {"healthy": 2, "degraded": 1, "unreachable": 1, "unknown": 0},
            },
            "correlation": {
                "incident_graph_count": 1,
                "correlated_event_count": 4,
                "exact_correlation_observed": True,
            },
            "flow": {"available": True, "flow_event_count": 1},
            "timeline": {"available": True, "entry_count": 4},
            "contains_raw_evidence": False,
            "contains_raw_credentials": False,
            "authority": {
                "aggregate_only": True,
                "database_read_only": True,
                "exact_timestamps_exposed": False,
                "event_ids_exposed": False,
                "graph_ids_exposed": False,
                "entity_refs_exposed": False,
                "evidence_refs_exposed": False,
                "rule_ids_exposed": False,
                "asset_ids_exposed": False,
                "network_addresses_exposed": False,
                "raw_values_exposed": False,
                "browser_filters_exposed": False,
                "database_write": False,
                "network_execution": False,
                "collector_execution": False,
                "packet_capture_execution": False,
                "remediation_execution": False,
            },
        }

    def run_hourly(self, *, execute_readonly: bool) -> dict[str, object]:
        self.run_calls += 1
        raise AssertionError("operator posture GET must never execute monitoring")


class SecurityOperatorPostureConsoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = _FakeOperatorService()
        self.server = build_server(
            "127.0.0.1",
            0,
            self.service,  # type: ignore[arg-type]
            csrf_token="a" * 64,
            csp_nonce="b" * 32,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def _get(self, path: str) -> tuple[int, str, dict[str, str]]:
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request("GET", path)
        response = conn.getresponse()
        raw = response.read().decode("utf-8")
        headers = {key.lower(): value for key, value in response.getheaders()}
        status = response.status
        conn.close()
        return status, raw, headers

    def test_operator_posture_get_ignores_browser_selectors_and_stays_read_only(self) -> None:
        status, raw, headers = self._get(
            "/api/v1/security/monitoring/operator-posture?limit=9999&event_id=secret&asset_id=secret&target=192.0.2.1"
        )
        self.assertEqual(status, 200)
        payload = json.loads(raw)
        self.assertEqual(payload["schema_version"], "workspace-security-monitoring/operator-posture-v1")
        self.assertEqual(payload["max_correlation_events"], 100)
        self.assertEqual(self.service.operator_calls, 1)
        self.assertEqual(self.service.run_calls, 0)
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(headers["x-frame-options"], "DENY")
        serialized = json.dumps(payload, sort_keys=True)
        for leaked in ("192.0.2.1", "event_id=secret", "asset_id=secret", "limit=9999"):
            self.assertNotIn(leaked, serialized)
        authority = payload["authority"]
        self.assertTrue(authority["aggregate_only"])
        self.assertTrue(authority["database_read_only"])
        self.assertFalse(authority["browser_filters_exposed"])
        self.assertFalse(authority["database_write"])
        self.assertFalse(authority["network_execution"])
        self.assertFalse(authority["collector_execution"])
        self.assertFalse(authority["packet_capture_execution"])
        self.assertFalse(authority["remediation_execution"])

    def test_root_contains_operator_posture_panel_and_uses_text_content(self) -> None:
        status, page, headers = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("Operator Posture", page)
        self.assertIn("/api/v1/security/monitoring/operator-posture", page)
        self.assertIn("正確な時刻は表示しません", page)
        self.assertIn("operator-posture", page)
        self.assertIn("textContent", page)
        self.assertNotIn("innerHTML", page)
        self.assertIn("content-security-policy", headers)
        self.assertEqual(self.service.operator_calls, 0)
        self.assertEqual(self.service.run_calls, 0)


if __name__ == "__main__":
    unittest.main()
