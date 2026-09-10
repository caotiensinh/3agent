from __future__ import annotations

from dataclasses import replace
import unittest

from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.network_protocol_forensics import build_network_protocol_forensics


def _event(category: str, *, source_type: str) -> CanonicalEvent:
    return CanonicalEvent(
        event_id="evt-protocol-01",
        source_id="sensor-protocol-01",
        source_type=source_type,
        observed_at="2026-09-03T00:20:00+09:00",
        category=category,
        severity="info",
        message_sha256=sha256_fingerprint({"category": category}),
        parser_version="workspace-json-sensor/v1",
        evidence_ref="event:protocol-evidence-01",
    ).validate()


class SecurityNetworkProtocolForensicsV020Tests(unittest.TestCase):
    def test_tls_metadata_is_deterministic_and_privacy_preserving(self) -> None:
        event = _event("zeek.ssl", source_type="zeek_json")
        projection = {
            "server_name": "internal-api.example.local",
            "tls_version": "TLSv13",
            "certificate_sha256": "a" * 64,
            "ja3": "771,4865-4866,0-11-10,29-23,0",
        }
        first = build_network_protocol_forensics(event, projection)
        second = build_network_protocol_forensics(event, dict(reversed(tuple(projection.items()))))
        self.assertEqual(first.public_dict(), second.public_dict())
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.protocol, "tls")
        self.assertEqual(first.certificate_sha256, "sha256:" + "a" * 64)
        rendered = str(first.public_dict())
        self.assertNotIn("internal-api.example.local", rendered)
        self.assertNotIn("771,4865", rendered)
        self.assertTrue(first.server_name_sha256.startswith("sha256:"))
        self.assertTrue(first.ja3_sha256.startswith("sha256:"))
        self.assertEqual(first.authority, "advisory")

    def test_http_metadata_keeps_method_status_but_hashes_sensitive_strings(self) -> None:
        event = _event("suricata.http", source_type="suricata_eve")
        projection = {
            "method": "GET",
            "host": "portal.example.local",
            "uri": "/admin/export?case=secret",
            "user_agent": "SensitiveAgent/1.0",
            "status_code": 403,
        }
        metadata = build_network_protocol_forensics(event, projection)
        self.assertEqual(metadata.protocol, "http")
        self.assertEqual(metadata.http_method, "GET")
        self.assertEqual(metadata.http_status_code, 403)
        rendered = str(metadata.public_dict())
        self.assertNotIn("portal.example.local", rendered)
        self.assertNotIn("/admin/export", rendered)
        self.assertNotIn("SensitiveAgent", rendered)
        self.assertTrue(metadata.http_host_sha256.startswith("sha256:"))
        self.assertTrue(metadata.http_uri_sha256.startswith("sha256:"))

    def test_unknown_projection_fields_and_wrong_category_fail_closed(self) -> None:
        tls = _event("suricata.tls", source_type="suricata_eve")
        with self.assertRaisesRegex(MonitoringContractError, "unsupported fields"):
            build_network_protocol_forensics(tls, {"server_name": "x", "raw_certificate": "not-allowed"})
        wrong = _event("suricata.flow", source_type="suricata_eve")
        with self.assertRaisesRegex(MonitoringContractError, "not a supported TLS/HTTP"):
            build_network_protocol_forensics(wrong, {})

    def test_invalid_certificate_method_status_and_missing_evidence_are_rejected(self) -> None:
        tls = _event("suricata.tls", source_type="suricata_eve")
        with self.assertRaisesRegex(MonitoringContractError, "certificate_sha256"):
            build_network_protocol_forensics(tls, {"certificate_sha256": "not-a-hash"})
        http = _event("zeek.http", source_type="zeek_json")
        with self.assertRaisesRegex(MonitoringContractError, "HTTP method"):
            build_network_protocol_forensics(http, {"method": "BREW"})
        with self.assertRaisesRegex(MonitoringContractError, "status code"):
            build_network_protocol_forensics(http, {"method": "GET", "status_code": 700})
        with self.assertRaisesRegex(MonitoringContractError, "requires evidence_ref"):
            build_network_protocol_forensics(replace(tls, evidence_ref=None), {})


if __name__ == "__main__":
    unittest.main()
