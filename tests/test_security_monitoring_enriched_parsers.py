from __future__ import annotations

import json
import unittest

from three_agent.security_monitoring.enriched_parsers import (
    ParsedCanonicalEvent,
    parse_json_sensor_event_enriched,
    parse_workspace_audit_event,
)
from three_agent.security_monitoring.entity_context import opaque_entity_ref
from three_agent.security_monitoring.parsers import QuarantinedRecord, parse_json_sensor_event


class EnrichedParserTests(unittest.TestCase):
    def test_existing_json_sensor_parser_api_remains_unchanged(self):
        raw = json.dumps(
            {
                "timestamp": "2026-09-01T00:00:00+00:00",
                "event_type": "flow",
                "src_ip": "10.0.0.10",
                "dest_ip": "203.0.113.8",
                "dest_port": 443,
                "proto": "TCP",
            }
        )
        event = parse_json_sensor_event(source_id="sensor-1", source_type="suricata_eve", raw_line=raw)
        self.assertNotIsInstance(event, QuarantinedRecord)
        self.assertEqual(event.category, "suricata.flow")
        self.assertFalse(hasattr(event, "entity_context"))

    def test_suricata_enrichment_hashes_ip_dns_and_service_and_keeps_approved_asset_only(self):
        raw = json.dumps(
            {
                "timestamp": "2026-09-01T00:00:00+00:00",
                "event_type": "dns",
                "src_ip": "10.0.0.10",
                "dest_ip": "8.8.8.8",
                "dest_port": 53,
                "proto": "UDP",
                "dns": {
                    "rrname": "Internal.EXAMPLE.com.",
                    "answers": [{"rdata": "203.0.113.44"}, {"rdata": "not-an-ip"}],
                },
                "http": {"hostname": "must-not-enter-context.example"},
            }
        )
        parsed = parse_json_sensor_event_enriched(
            source_id="sensor-suricata",
            source_type="suricata_eve",
            raw_line=raw,
            approved_asset_id="gateway-rd-01",
        )
        self.assertIsInstance(parsed, ParsedCanonicalEvent)
        rendered = json.dumps(parsed.entity_context.public_dict(), sort_keys=True)
        for forbidden in (
            "10.0.0.10",
            "8.8.8.8",
            "203.0.113.44",
            "internal.example.com",
            "must-not-enter-context.example",
        ):
            self.assertNotIn(forbidden, rendered.lower())
        self.assertIn("asset:gateway-rd-01", rendered)
        self.assertIn(opaque_entity_ref("dns", "internal.example.com"), rendered)
        self.assertIn(opaque_entity_ref("ip", "203.0.113.44"), rendered)
        self.assertIn(opaque_entity_ref("service", "udp:53"), rendered)

    def test_zeek_conn_and_dns_fields_use_exact_allowlisted_entities(self):
        raw = json.dumps(
            {
                "ts": 1788220800.0,
                "_path": "dns",
                "id.orig_h": "192.0.2.11",
                "id.resp_h": "192.0.2.53",
                "id.resp_p": 53,
                "proto": "udp",
                "query": "updates.example.org",
                "answers": ["198.51.100.9", "alias.example.org"],
                "uid": "C-raw-value-must-not-be-an-entity",
            }
        )
        parsed = parse_json_sensor_event_enriched(
            source_id="sensor-zeek",
            source_type="zeek_json",
            raw_line=raw,
        )
        self.assertIsInstance(parsed, ParsedCanonicalEvent)
        refs = {ref.entity_ref for ref in parsed.entity_context.references}
        self.assertIn(opaque_entity_ref("ip", "192.0.2.11"), refs)
        self.assertIn(opaque_entity_ref("dns", "updates.example.org"), refs)
        self.assertIn(opaque_entity_ref("ip", "198.51.100.9"), refs)
        rendered = json.dumps(parsed.entity_context.public_dict(), sort_keys=True)
        self.assertNotIn("C-raw-value", rendered)
        self.assertNotIn("alias.example.org", rendered)

    def test_workspace_audit_auth_is_strict_metadata_only_and_trusted_asset_bound(self):
        raw = json.dumps(
            {
                "timestamp": "2026-09-01T09:00:00+09:00",
                "event_type": "auth_success",
                "asset_id": "server-rd-01",
                "user": "CORP\\alice",
                "source_ip": "192.0.2.20",
                "destination_ip": "192.0.2.30",
                "service": "ssh",
                "outcome": "success",
            }
        )
        parsed = parse_workspace_audit_event(
            source_id="audit-server-rd-01",
            raw_line=raw,
            approved_asset_id="server-rd-01",
        )
        self.assertIsInstance(parsed, ParsedCanonicalEvent)
        self.assertEqual(parsed.event.category, "workspace_audit.auth_success")
        rendered = json.dumps(parsed.entity_context.public_dict(), sort_keys=True)
        self.assertIn("asset:server-rd-01", rendered)
        self.assertIn(opaque_entity_ref("user", "CORP\\alice"), rendered)
        self.assertIn(opaque_entity_ref("service", "tcp:22"), rendered)
        self.assertNotIn("alice", rendered.lower())
        self.assertNotIn("192.0.2.20", rendered)

        mismatch = parse_workspace_audit_event(
            source_id="audit-server-rd-01",
            raw_line=raw,
            approved_asset_id="server-rd-02",
        )
        self.assertIsInstance(mismatch, QuarantinedRecord)
        self.assertEqual(mismatch.reason_code, "WORKSPACE_AUDIT_INVALID")

    def test_workspace_audit_process_links_asset_user_and_process_without_raw_path(self):
        raw = json.dumps(
            {
                "timestamp": "2026-09-01T09:00:05+09:00",
                "event_type": "process_start",
                "asset_id": "server-rd-01",
                "user": "CORP\\alice",
                "process_image": "C:\\Windows\\System32\\whoami.exe",
            }
        )
        parsed = parse_workspace_audit_event(
            source_id="audit-server-rd-01",
            raw_line=raw,
            approved_asset_id="server-rd-01",
        )
        self.assertIsInstance(parsed, ParsedCanonicalEvent)
        rendered = json.dumps(parsed.entity_context.public_dict(), sort_keys=True)
        self.assertIn(opaque_entity_ref("process", "C:\\Windows\\System32\\whoami.exe"), rendered)
        self.assertNotIn("whoami.exe", rendered.lower())
        self.assertNotIn("alice", rendered.lower())

    def test_secret_or_unknown_audit_fields_fail_closed(self):
        for forbidden_key in ("password", "token", "command_line", "cookie", "session"):
            payload = {
                "timestamp": "2026-09-01T09:00:00+09:00",
                "event_type": "auth_success",
                "asset_id": "server-rd-01",
                "user": "alice",
                "service": "ssh",
                "outcome": "success",
                forbidden_key: "super-secret-value",
            }
            result = parse_workspace_audit_event(
                source_id="audit-1",
                raw_line=json.dumps(payload),
                approved_asset_id="server-rd-01",
            )
            self.assertIsInstance(result, QuarantinedRecord)
            self.assertEqual(result.reason_code, "WORKSPACE_AUDIT_INVALID")

    def test_auth_service_and_outcome_must_be_explicitly_supported(self):
        unsupported = {
            "timestamp": "2026-09-01T09:00:00+09:00",
            "event_type": "auth_success",
            "asset_id": "server-rd-01",
            "user": "alice",
            "service": "custom-admin-protocol",
            "outcome": "success",
        }
        self.assertIsInstance(
            parse_workspace_audit_event(
                source_id="audit-1",
                raw_line=json.dumps(unsupported),
                approved_asset_id="server-rd-01",
            ),
            QuarantinedRecord,
        )
        mismatch = dict(unsupported, service="ssh", outcome="failure")
        self.assertIsInstance(
            parse_workspace_audit_event(
                source_id="audit-1",
                raw_line=json.dumps(mismatch),
                approved_asset_id="server-rd-01",
            ),
            QuarantinedRecord,
        )

    def test_malformed_relevant_sensor_entity_quarantines_enrichment(self):
        raw = json.dumps(
            {
                "timestamp": "2026-09-01T00:00:00+00:00",
                "event_type": "flow",
                "src_ip": "not-an-ip",
                "dest_ip": "203.0.113.1",
            }
        )
        result = parse_json_sensor_event_enriched(
            source_id="sensor-1",
            source_type="suricata_eve",
            raw_line=raw,
        )
        self.assertIsInstance(result, QuarantinedRecord)
        self.assertEqual(result.reason_code, "ENTITY_CONTEXT_INVALID")


if __name__ == "__main__":
    unittest.main()
