from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import (
    AssetInventoryRecord,
    MonitoringContractError,
)
from three_agent.security_monitoring.dns_behavior_storage import DNSBehaviorFeatureStore
from three_agent.security_monitoring.entity_context_storage import EventEntityContextStore
from three_agent.security_monitoring.ingest import SourceMapping
from three_agent.security_monitoring.storage import MonitoringStore
from three_agent.security_monitoring.structured_behavior_ingest import StructuredBehaviorIngestor


class StructuredBehaviorIngestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = MonitoringStore(Path(self.temp.name) / "monitoring.sqlite3")
        self.entities = EventEntityContextStore(self.store)
        self.entities.initialize()
        self.dns = DNSBehaviorFeatureStore(self.store)
        self.dns.initialize()
        self.ingestor = StructuredBehaviorIngestor(
            store=self.store,
            entity_store=self.entities,
            dns_store=self.dns,
        )
        self.store.upsert_asset(
            AssetInventoryRecord(
                asset_id="server-rd-01",
                role="correlation_endpoint",
                management_host="192.0.2.100",
                collector_capabilities=(),
            ).validate()
        )

    def tearDown(self):
        self.temp.cleanup()

    def test_valid_dns_persists_event_entity_and_feature_and_replay_is_idempotent(self):
        source = SourceMapping(
            source_id="zeek-rd",
            source_type="zeek_json",
            sender_address="192.0.2.50",
        )
        raw = json.dumps(
            {
                "ts": 1788220800.0,
                "_path": "dns",
                "id.orig_h": "192.0.2.10",
                "id.resp_h": "192.0.2.53",
                "id.resp_p": 53,
                "proto": "udp",
                "query": "A8f9-x7.Internal.Example.com",
                "rcode_name": "NXDOMAIN",
                "qtype_name": "A",
                "answers": [],
            },
            sort_keys=True,
        )
        first = self.ingestor.ingest_line(source=source, raw_line=raw)
        second = self.ingestor.ingest_line(source=source, raw_line=raw)
        self.assertEqual(first, second)
        self.assertEqual(first.status, "accepted")
        self.assertEqual(first.dns_feature_status, "persisted")
        self.assertEqual(self.store.count("canonical_events"), 1)
        with self.store.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM dns_behavior_features").fetchone()[0], 1)
        persisted = self.dns.get(first.event_id)
        self.assertIsNotNone(persisted)
        self.assertNotIn(
            "a8f9-x7.internal.example.com",
            json.dumps(persisted.public_dict(), sort_keys=True).lower(),
        )

    def test_malformed_behavior_dns_fails_before_canonical_persistence(self):
        source = SourceMapping(
            source_id="zeek-rd",
            source_type="zeek_json",
            sender_address="192.0.2.50",
        )
        raw = json.dumps(
            {
                "ts": 1788220800.0,
                "_path": "dns",
                "id.orig_h": "192.0.2.10",
                "id.resp_h": "192.0.2.53",
            }
        )
        with self.assertRaises(MonitoringContractError):
            self.ingestor.ingest_line(source=source, raw_line=raw)
        self.assertEqual(self.store.count("canonical_events"), 0)
        with self.store.connect() as conn:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM event_entities").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM dns_behavior_features").fetchone()[0], 0)

    def test_non_dns_sensor_remains_backward_compatible_and_has_no_feature(self):
        source = SourceMapping(
            source_id="suricata-rd",
            source_type="suricata_eve",
            sender_address="192.0.2.50",
        )
        raw = json.dumps(
            {
                "timestamp": "2026-09-01T00:00:00+00:00",
                "event_type": "flow",
                "src_ip": "192.0.2.10",
                "dest_ip": "198.51.100.20",
                "dest_port": 443,
                "proto": "TCP",
            }
        )
        receipt = self.ingestor.ingest_line(source=source, raw_line=raw)
        self.assertEqual(receipt.status, "accepted")
        self.assertEqual(receipt.dns_feature_status, "not_applicable")
        self.assertIsNone(self.dns.get(receipt.event_id))

    def test_workspace_audit_uses_existing_ingest_boundary_without_dns_feature(self):
        source = SourceMapping(
            source_id="audit-rd",
            source_type="workspace_audit",
            sender_address="127.0.0.1",
        )
        raw = json.dumps(
            {
                "timestamp": "2026-09-01T09:00:00+09:00",
                "event_type": "auth_success",
                "asset_id": "server-rd-01",
                "user": "alice",
                "service": "ssh",
                "outcome": "success",
            }
        )
        receipt = self.ingestor.ingest_line(
            source=source,
            raw_line=raw,
            approved_asset_id="server-rd-01",
        )
        self.assertEqual(receipt.status, "accepted")
        self.assertEqual(receipt.dns_feature_status, "not_applicable")

    def test_existing_parser_quarantine_remains_quarantine(self):
        source = SourceMapping(
            source_id="zeek-rd",
            source_type="zeek_json",
            sender_address="192.0.2.50",
        )
        receipt = self.ingestor.ingest_line(source=source, raw_line="not-json")
        self.assertEqual(receipt.status, "quarantined")
        self.assertEqual(receipt.dns_feature_status, "not_persisted_quarantine")
        self.assertEqual(self.store.count("canonical_events"), 0)
        self.assertEqual(self.store.count("quarantine"), 1)


if __name__ == "__main__":
    unittest.main()
