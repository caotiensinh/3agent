from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import MonitoringContractError
from three_agent.security_monitoring.entity_context_storage import EventEntityContextStore
from three_agent.security_monitoring.ingest import SourceMapping
from three_agent.security_monitoring.storage import MonitoringStore
from three_agent.security_monitoring.structured_entity_ingest import StructuredEntityIngestor


class StructuredEntityIngestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = MonitoringStore(Path(self.temp.name) / "monitoring.sqlite3")
        self.entity_store = EventEntityContextStore(self.store)
        self.ingestor = StructuredEntityIngestor(store=self.store, entity_store=self.entity_store)

    def tearDown(self):
        self.temp.cleanup()

    def test_suricata_event_and_context_are_persisted_and_replay_is_idempotent(self):
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
                "dest_port": 22,
                "proto": "TCP",
            }
        )
        first = self.ingestor.ingest_line(source=source, raw_line=raw, asset_id="gateway-rd-01")
        second = self.ingestor.ingest_line(source=source, raw_line=raw, asset_id="gateway-rd-01")
        self.assertEqual(first, second)
        self.assertEqual(first.status, "accepted")
        self.assertGreater(first.entity_count, 0)
        self.assertEqual(self.store.count("canonical_events"), 1)
        with self.store.connect() as conn:
            entity_rows = conn.execute("SELECT COUNT(*) FROM event_entities").fetchone()[0]
        self.assertEqual(entity_rows, first.entity_count)
        self.assertIsNotNone(self.entity_store.get(first.event_id))

    def test_workspace_audit_secret_field_is_quarantined_without_canonical_event(self):
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
                "token": "must-never-enter-metadata",
            }
        )
        receipt = self.ingestor.ingest_line(source=source, raw_line=raw)
        self.assertEqual(receipt.status, "quarantined")
        self.assertEqual(receipt.quarantine_reason, "WORKSPACE_AUDIT_INVALID")
        self.assertEqual(self.store.count("canonical_events"), 0)
        self.assertEqual(self.store.count("quarantine"), 1)

    def test_workspace_audit_asset_override_is_forbidden(self):
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
        with self.assertRaises(MonitoringContractError):
            self.ingestor.ingest_line(source=source, raw_line=raw, asset_id="other-server")

    def test_unsupported_source_and_oversized_line_fail_closed(self):
        syslog = SourceMapping(
            source_id="syslog-rd",
            source_type="syslog",
            sender_address="192.0.2.60",
        )
        with self.assertRaises(MonitoringContractError):
            self.ingestor.ingest_line(source=syslog, raw_line="x" * 1024)

        strict = StructuredEntityIngestor(
            store=self.store,
            entity_store=self.entity_store,
            max_line_bytes=1024,
        )
        suricata = SourceMapping(
            source_id="suricata-rd",
            source_type="suricata_eve",
            sender_address="192.0.2.50",
        )
        with self.assertRaises(MonitoringContractError):
            strict.ingest_line(source=suricata, raw_line="x" * 1025)

    def test_sensor_event_without_usable_entities_fails_correlation_ingest(self):
        source = SourceMapping(
            source_id="suricata-rd",
            source_type="suricata_eve",
            sender_address="192.0.2.50",
        )
        raw = json.dumps(
            {
                "timestamp": "2026-09-01T00:00:00+00:00",
                "event_type": "stats",
            }
        )
        with self.assertRaises(MonitoringContractError):
            self.ingestor.ingest_line(source=source, raw_line=raw)


if __name__ == "__main__":
    unittest.main()
