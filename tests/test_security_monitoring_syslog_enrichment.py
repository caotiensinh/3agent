from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import AssetInventoryRecord, MonitoringContractError
from three_agent.security_monitoring.entity_context_storage import EventEntityContextStore
from three_agent.security_monitoring.ingest import SourceMapping
from three_agent.security_monitoring.parsers import QuarantinedRecord
from three_agent.security_monitoring.storage import MonitoringStore
from three_agent.security_monitoring.structured_entity_ingest import StructuredEntityIngestor
from three_agent.security_monitoring.syslog_enrichment import parse_syslog_line_enriched


class SyslogEnrichmentTests(unittest.TestCase):
    def test_syslog_enrichment_binds_only_trusted_asset_and_never_message_entities(self):
        line = (
            "<34>2026-09-01T10:15:00+09:00 switch-rd-01 sshd[1234]: "
            "alice connected from 192.0.2.44 token=must-not-enter-context"
        )
        parsed = parse_syslog_line_enriched(
            source_id="syslog-switch-rd-01",
            line=line,
            approved_asset_id="switch-rd-01",
        )
        self.assertNotIsInstance(parsed, QuarantinedRecord)
        self.assertEqual(parsed.event.category, "syslog.sshd")
        public = json.dumps(parsed.entity_context.public_dict(), sort_keys=True)
        self.assertIn("asset:switch-rd-01", public)
        self.assertEqual(len(parsed.entity_context.references), 1)
        for forbidden in ("alice", "192.0.2.44", "must-not-enter-context", "token="):
            self.assertNotIn(forbidden, public)

    def test_invalid_syslog_remains_quarantined_by_authoritative_parser(self):
        parsed = parse_syslog_line_enriched(
            source_id="syslog-switch-rd-01",
            line="not-rfc5424-enough",
            approved_asset_id="switch-rd-01",
        )
        self.assertIsInstance(parsed, QuarantinedRecord)
        self.assertEqual(parsed.reason_code, "SYSLOG_PARSE_FAILED")

    def test_structured_syslog_requires_enabled_inventory_asset_and_persists_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = MonitoringStore(Path(tmp) / "monitoring.sqlite3")
            store.initialize()
            store.upsert_asset(
                AssetInventoryRecord(
                    asset_id="switch-rd-01",
                    role="switch",
                    management_host="192.0.2.10",
                    collector_capabilities=(),
                ).validate()
            )
            entity_store = EventEntityContextStore(store)
            ingestor = StructuredEntityIngestor(store=store, entity_store=entity_store)
            source = SourceMapping(
                source_id="syslog-switch-rd-01",
                source_type="syslog",
                sender_address="192.0.2.10",
            )
            line = "<34>2026-09-01T10:15:00+09:00 switch-rd-01 sshd[1234]: login accepted"

            with self.assertRaises(MonitoringContractError):
                ingestor.ingest_line(source=source, raw_line=line)

            receipt = ingestor.ingest_line(
                source=source,
                raw_line=line,
                approved_asset_id="switch-rd-01",
            )
            self.assertEqual(receipt.status, "accepted")
            self.assertEqual(receipt.entity_count, 1)
            self.assertEqual(store.count("canonical_events"), 1)
            context = entity_store.get(receipt.event_id)
            self.assertIsNotNone(context)
            self.assertEqual(context.refs_for_role("asset"), ("asset:switch-rd-01",))


if __name__ == "__main__":
    unittest.main()
