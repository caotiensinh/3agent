from __future__ import annotations

import http.client
import json
import threading
import unittest

from three_agent.security_local_console import build_server


class SecurityConsoleReadinessRedactionTests(unittest.TestCase):
    def test_browser_readiness_redacts_internal_identifiers_and_fingerprint(self) -> None:
        sensitive_asset = "core-router-prod-01"
        second_sensitive_asset = "distribution-switch-prod-02"
        sensitive_fingerprint = "policy-fingerprint-private-123"
        sensitive_unknown_code = f"PRIVATE_DETAIL:{sensitive_asset}"

        class ReadinessService:
            def readiness(self) -> dict[str, object]:
                return {
                    "schema_version": "workspace-security-monitoring/readiness-v1",
                    "ready": False,
                    "status": "blocked",
                    "config_saved": True,
                    "policy_fingerprint": sensitive_fingerprint,
                    "enabled_asset_count": 2,
                    "issues": [
                        {
                            "code": "SECRET_REF_UNRESOLVED",
                            "message": (
                                f"{sensitive_asset}: credential reference is not present "
                                "in the local secret boundary."
                            ),
                        },
                        {
                            "code": "SECRET_REF_UNRESOLVED",
                            "message": (
                                f"{second_sensitive_asset}: credential reference is not "
                                "present in the local secret boundary."
                            ),
                        },
                        {
                            "code": sensitive_unknown_code,
                            "message": f"internal readiness detail for {sensitive_asset}",
                        },
                    ],
                    "warnings": [
                        {
                            "code": "MONITORING_DISABLED",
                            "message": "Monitoring is currently disabled.",
                        }
                    ],
                    "network_test_executed": False,
                    "secret_values_read": False,
                    "packet_capture_executed": False,
                    "remediation_executed": False,
                }

        service = ReadinessService()
        internal = service.readiness()
        internal_raw = json.dumps(internal, sort_keys=True)
        self.assertIn(sensitive_asset, internal_raw)
        self.assertIn(second_sensitive_asset, internal_raw)
        self.assertIn(sensitive_fingerprint, internal_raw)
        self.assertIn(sensitive_unknown_code, internal_raw)

        server = build_server(
            "127.0.0.1",
            0,
            service,  # type: ignore[arg-type]
            csrf_token="a" * 64,
            csp_nonce="b" * 32,
            demo_mode=False,
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            conn = http.client.HTTPConnection(
                "127.0.0.1", server.server_port, timeout=3
            )
            conn.request("GET", "/api/v1/security/monitoring/readiness")
            response = conn.getresponse()
            raw = response.read().decode("utf-8")
            payload = json.loads(raw)
            status = response.status
            conn.close()

            self.assertEqual(status, 200)
            self.assertFalse(payload["ready"])
            self.assertEqual(payload["status"], "blocked")
            self.assertEqual(payload["enabled_asset_count"], 2)
            self.assertNotIn("policy_fingerprint", payload)
            self.assertNotIn(sensitive_asset, raw)
            self.assertNotIn(second_sensitive_asset, raw)
            self.assertNotIn(sensitive_fingerprint, raw)
            self.assertNotIn(sensitive_unknown_code, raw)
            self.assertEqual(
                payload["issues"],
                [
                    {
                        "code": "SECRET_REF_UNRESOLVED",
                        "message": (
                            "An approved SNMPv3 credential reference is unavailable "
                            "in the local secret boundary."
                        ),
                    },
                    {
                        "code": "READINESS_BLOCKED",
                        "message": "Monitoring readiness requires local operator attention.",
                    },
                ],
            )
            self.assertEqual(
                payload["warnings"],
                [
                    {
                        "code": "MONITORING_DISABLED",
                        "message": "Monitoring is currently disabled.",
                    }
                ],
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
