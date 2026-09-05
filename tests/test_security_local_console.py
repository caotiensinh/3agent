from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server, validate_loopback_host


class _FakeService:
    def __init__(self) -> None:
        self.run_calls = 0
        self.asset_intelligence_calls = 0
        self.evidence_summary_calls = 0

    def summary(self) -> dict[str, object]:
        return {
            "enabled": True,
            "allow_real_network": True,
            "enabled_asset_count": 2,
            "contains_raw_credentials": False,
        }

    def readiness(self) -> dict[str, object]:
        return {
            "ready": True,
            "issues": [],
            "warnings": [],
            "network_test_executed": False,
            "secret_values_read": False,
            "packet_capture_executed": False,
            "remediation_executed": False,
        }

    def asset_intelligence(self) -> dict[str, object]:
        self.asset_intelligence_calls += 1
        return {
            "schema_version": "workspace-security-monitoring/asset-intelligence-summary-v1",
            "count_scope": "enabled_assets",
            "asset_count": 3,
            "enabled_asset_count": 2,
            "disabled_asset_count": 1,
            "unique_role_count": 2,
            "capability_counts": {"icmp_echo": 1, "tcp_connect": 1},
            "data_class_counts": {"confidential": 1, "restricted": 1},
            "credential_ref_asset_count": 1,
            "explicit_tcp_port_binding_count": 1,
            "contains_raw_credentials": False,
            "authority": {
                "aggregate_only": True,
                "config_is_authoritative": True,
                "asset_ids_exposed": False,
                "management_hosts_exposed": False,
                "credential_refs_exposed": False,
                "allowed_tcp_ports_exposed": False,
                "database_write": False,
                "network_execution": False,
                "collector_execution": False,
                "packet_capture_execution": False,
                "remediation_execution": False,
            },
        }

    def evidence_summary(self) -> dict[str, object]:
        self.evidence_summary_calls += 1
        return {
            "schema_version": "workspace-security-monitoring/recent-evidence-summary-v1",
            "count_scope": "recent_bounded_records",
            "max_records_per_stream": 100,
            "database_available": True,
            "health": "attention",
            "reason_codes": ["HIGH_CRITICAL_FINDINGS"],
            "observation_sample_count": 4,
            "observation_evidence_linked_count": 3,
            "event_sample_count": 2,
            "event_evidence_linked_count": 1,
            "finding_sample_count": 2,
            "finding_evidence_linked_count": 2,
            "report_sample_count": 1,
            "open_finding_count": 2,
            "high_critical_count": 1,
            "latest_hourly": {
                "status": "completed",
                "coverage_pct": 100.0,
                "expected_assets": 2,
                "observed_assets": 2,
                "observed_at": "2026-09-05T14:00:00+00:00",
                "age_seconds": 60.0,
            },
            "contains_raw_evidence": False,
            "contains_raw_credentials": False,
            "authority": {
                "aggregate_only": True,
                "database_read_only": True,
                "raw_evidence_exposed": False,
                "asset_ids_exposed": False,
                "source_ids_exposed": False,
                "finding_ids_exposed": False,
                "evidence_refs_exposed": False,
                "bundle_refs_exposed": False,
                "database_write": False,
                "network_execution": False,
                "collector_execution": False,
                "packet_capture_execution": False,
                "remediation_execution": False,
            },
        }

    def run_hourly(self, *, execute_readonly: bool) -> dict[str, object]:
        if not execute_readonly:
            raise AssertionError("console must only request explicit read-only execution")
        self.run_calls += 1
        return {
            "status": "completed",
            "failure_codes": [],
            "execute_mode": "readonly",
        }


class SecurityLocalConsoleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.service = _FakeService()
        self.csrf = "a" * 64
        self.server = build_server(
            "127.0.0.1",
            0,
            self.service,  # type: ignore[arg-type]
            csrf_token=self.csrf,
            csp_nonce="b" * 32,
        )
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.server.server_port

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, object] | str, dict[str, str]]:
        body = None
        request_headers = dict(headers or {})
        if payload is not None:
            body = json.dumps(payload).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=3)
        conn.request(method, path, body=body, headers=request_headers)
        response = conn.getresponse()
        raw = response.read()
        response_headers = {key.lower(): value for key, value in response.getheaders()}
        content_type = response_headers.get("content-type", "")
        if content_type.startswith("application/json"):
            decoded: dict[str, object] | str = json.loads(raw.decode("utf-8"))
        else:
            decoded = raw.decode("utf-8")
        status = response.status
        conn.close()
        return status, decoded, response_headers

    def test_health_is_local_readonly_surface(self) -> None:
        status, payload, headers = self.request("GET", "/api/v1/health")
        self.assertEqual(status, 200)
        self.assertIsInstance(payload, dict)
        assert isinstance(payload, dict)
        self.assertEqual(payload["status"], "ok")
        self.assertTrue(payload["local_only"])
        self.assertFalse(payload["write_authority"])
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertEqual(headers["x-frame-options"], "DENY")

    def test_summary_and_readiness_are_connected_to_service(self) -> None:
        status, summary, _ = self.request(
            "GET", "/api/v1/security/monitoring/summary"
        )
        self.assertEqual(status, 200)
        assert isinstance(summary, dict)
        self.assertEqual(summary["enabled_asset_count"], 2)

        status, readiness, _ = self.request(
            "GET", "/api/v1/security/monitoring/readiness"
        )
        self.assertEqual(status, 200)
        assert isinstance(readiness, dict)
        self.assertTrue(readiness["ready"])
        self.assertFalse(readiness["packet_capture_executed"])
        self.assertFalse(readiness["remediation_executed"])

    def test_asset_intelligence_is_aggregate_only_readonly_service_surface(self) -> None:
        status, payload, headers = self.request(
            "GET", "/api/v1/security/monitoring/asset-intelligence"
        )
        self.assertEqual(status, 200)
        assert isinstance(payload, dict)
        self.assertEqual(
            payload["schema_version"],
            "workspace-security-monitoring/asset-intelligence-summary-v1",
        )
        self.assertEqual(payload["asset_count"], 3)
        self.assertEqual(payload["enabled_asset_count"], 2)
        self.assertEqual(payload["disabled_asset_count"], 1)
        self.assertEqual(payload["unique_role_count"], 2)
        self.assertEqual(payload["credential_ref_asset_count"], 1)
        self.assertEqual(payload["explicit_tcp_port_binding_count"], 1)
        self.assertEqual(self.service.asset_intelligence_calls, 1)
        self.assertEqual(self.service.run_calls, 0)
        self.assertEqual(headers["cache-control"], "no-store")

        serialized = json.dumps(payload, sort_keys=True)
        for sensitive_value in (
            "router-core-01",
            "192.0.2.10",
            "secret-ref:router-core-01",
            "443",
        ):
            self.assertNotIn(sensitive_value, serialized)
        authority = payload["authority"]
        assert isinstance(authority, dict)
        self.assertTrue(authority["aggregate_only"])
        self.assertFalse(authority["database_write"])
        self.assertFalse(authority["network_execution"])
        self.assertFalse(authority["collector_execution"])
        self.assertFalse(authority["packet_capture_execution"])
        self.assertFalse(authority["remediation_execution"])

    def test_evidence_summary_is_bounded_readonly_service_surface(self) -> None:
        status, payload, headers = self.request(
            "GET",
            "/api/v1/security/monitoring/evidence-summary?limit=9999&asset_id=secret",
        )
        self.assertEqual(status, 200)
        assert isinstance(payload, dict)
        self.assertEqual(
            payload["schema_version"],
            "workspace-security-monitoring/recent-evidence-summary-v1",
        )
        self.assertEqual(payload["count_scope"], "recent_bounded_records")
        self.assertEqual(payload["max_records_per_stream"], 100)
        self.assertEqual(payload["observation_sample_count"], 4)
        self.assertEqual(payload["observation_evidence_linked_count"], 3)
        self.assertEqual(payload["event_sample_count"], 2)
        self.assertEqual(payload["finding_sample_count"], 2)
        self.assertEqual(payload["report_sample_count"], 1)
        self.assertEqual(payload["open_finding_count"], 2)
        self.assertEqual(payload["high_critical_count"], 1)
        self.assertEqual(self.service.evidence_summary_calls, 1)
        self.assertEqual(self.service.run_calls, 0)
        self.assertEqual(headers["cache-control"], "no-store")

        serialized = json.dumps(payload, sort_keys=True)
        for sensitive_value in (
            "asset_id",
            "source_id",
            "finding_id",
            "evidence_ref",
            "bundle_ref",
            "secret",
        ):
            self.assertNotIn(sensitive_value, serialized)
        authority = payload["authority"]
        assert isinstance(authority, dict)
        self.assertTrue(authority["aggregate_only"])
        self.assertTrue(authority["database_read_only"])
        self.assertFalse(authority["raw_evidence_exposed"])
        self.assertFalse(authority["database_write"])
        self.assertFalse(authority["network_execution"])
        self.assertFalse(authority["collector_execution"])
        self.assertFalse(authority["packet_capture_execution"])
        self.assertFalse(authority["remediation_execution"])

    def test_readonly_execution_requires_csrf_and_explicit_confirmation(self) -> None:
        status, payload, _ = self.request(
            "POST",
            "/api/v1/security/monitoring/run-hourly",
            payload={"confirm_readonly": True},
        )
        self.assertEqual(status, 403)
        assert isinstance(payload, dict)
        self.assertEqual(payload["reason_code"], "CSRF_TOKEN_REQUIRED")
        self.assertEqual(self.service.run_calls, 0)

        status, payload, _ = self.request(
            "POST",
            "/api/v1/security/monitoring/run-hourly",
            payload={"confirm_readonly": False},
            headers={"X-Workspace-CSRF": self.csrf},
        )
        self.assertEqual(status, 409)
        assert isinstance(payload, dict)
        self.assertEqual(payload["reason_code"], "USER_CONFIRMATION_REQUIRED")
        self.assertEqual(self.service.run_calls, 0)

        status, payload, _ = self.request(
            "POST",
            "/api/v1/security/monitoring/run-hourly",
            payload={"confirm_readonly": True},
            headers={"X-Workspace-CSRF": self.csrf},
        )
        self.assertEqual(status, 200)
        assert isinstance(payload, dict)
        self.assertEqual(payload["status"], "completed")
        self.assertEqual(self.service.run_calls, 1)

    def test_browser_request_cannot_add_path_target_or_command_fields(self) -> None:
        status, payload, _ = self.request(
            "POST",
            "/api/v1/security/monitoring/run-hourly",
            payload={"confirm_readonly": True, "target": "192.0.2.10"},
            headers={"X-Workspace-CSRF": self.csrf},
        )
        self.assertEqual(status, 400)
        assert isinstance(payload, dict)
        self.assertEqual(payload["reason_code"], "UNSUPPORTED_REQUEST_FIELDS")
        self.assertEqual(self.service.run_calls, 0)

    def test_host_header_and_bind_address_are_loopback_only(self) -> None:
        self.assertEqual(validate_loopback_host("127.0.0.1"), "127.0.0.1")
        self.assertEqual(validate_loopback_host("localhost"), "localhost")
        with self.assertRaisesRegex(ValueError, "SECURITY_CONSOLE_LOOPBACK_ONLY"):
            validate_loopback_host("0.0.0.0")

        status, payload, _ = self.request(
            "GET",
            "/api/v1/security/monitoring/asset-intelligence",
            headers={"Host": "example.test"},
        )
        self.assertEqual(status, 421)
        assert isinstance(payload, dict)
        self.assertEqual(payload["reason_code"], "LOOPBACK_HOST_REQUIRED")
        self.assertEqual(self.service.asset_intelligence_calls, 0)

    def test_root_serves_self_contained_japanese_console(self) -> None:
        status, payload, headers = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIsInstance(payload, str)
        assert isinstance(payload, str)
        self.assertIn("WorkSpace Security Console", payload)
        self.assertIn("Asset Intelligence", payload)
        self.assertIn("Evidence / Result History", payload)
        self.assertIn(
            "アセットID、ソースID、Finding ID、Evidence参照、Bundle参照、RAW値は表示しません",
            payload,
        )
        self.assertIn("/api/v1/security/monitoring/asset-intelligence", payload)
        self.assertIn("/api/v1/security/monitoring/evidence-summary", payload)
        self.assertIn("読み取り専用監視を実行", payload)
        self.assertNotIn("__CSRF_TOKEN__", payload)
        self.assertIn("content-security-policy", headers)


if __name__ == "__main__":
    unittest.main()
