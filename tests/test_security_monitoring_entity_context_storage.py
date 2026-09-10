from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import (
    AssetInventoryRecord,
    CanonicalEvent,
    MonitoringContractError,
)
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.entity_context_storage import EventEntityContextStore
from three_agent.security_monitoring.storage import MonitoringStore


def event(event_id: str = "evt-storage-001") -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id,
        source_id="sensor-storage",
        source_type="suricata_eve",
        observed_at="2026-09-01T00:00:00+00:00",
        category="suricata.flow",
        severity="info",
        message_sha256="sha256:" + "a" * 64,
        parser_version="workspace-json-sensor/v1",
        evidence_ref="event:" + "a" * 32,
    ).validate()


def asset(asset_id: str, host: str, *, enabled: bool = True) -> AssetInventoryRecord:
    return AssetInventoryRecord(
        asset_id=asset_id,
        role="correlation_endpoint",
        management_host=host,
        collector_capabilities=(),
        enabled=enabled,
    ).validate()


class EventEntityContextStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = MonitoringStore(Path(self.temp.name) / "monitoring.sqlite3")
        self.entities = EventEntityContextStore(self.store)
        self.entities.initialize()
        self.store.upsert_asset(asset("server-rd-01", "192.0.2.2"))
        self.store.upsert_asset(asset("disabled-rd-01", "192.0.2.3", enabled=False))

    def tearDown(self):
        self.temp.cleanup()

    def test_migration_is_additive_and_preserves_core_schema(self):
        self.assertEqual(self.store.schema_version(), 1)
        self.assertEqual(self.entities.schema_version(), 1)
        self.assertEqual(self.store.count("canonical_events"), 0)
        with self.store.connect() as conn:
            names = {
                row[0]
                for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            }
        self.assertIn("canonical_events", names)
        self.assertIn("findings", names)
        self.assertIn("event_entities", names)

    def test_context_requires_existing_event_and_round_trips_exactly(self):
        context = EventEntityContext(
            event_id="evt-storage-001",
            references=(
                EventEntityReference.approved_asset(role="asset", asset_id="server-rd-01"),
                EventEntityReference.opaque(kind="ip", role="source_ip", value="192.0.2.10"),
            ),
        ).validate()
        with self.assertRaises(MonitoringContractError):
            self.entities.put(context)

        self.store.add_event(event())
        self.entities.put(context)
        loaded = self.entities.get("evt-storage-001")
        self.assertEqual(loaded, context)
        self.assertEqual(
            self.entities.event_ids_for_entity(context.refs_for_role("source_ip")[0]),
            ("evt-storage-001",),
        )

    def test_asset_reference_requires_enabled_approved_inventory_record(self):
        self.store.add_event(event())
        for asset_id in ("unknown-rd-01", "disabled-rd-01"):
            context = EventEntityContext(
                event_id="evt-storage-001",
                references=(EventEntityReference.approved_asset(role="asset", asset_id=asset_id),),
            ).validate()
            with self.assertRaises(MonitoringContractError):
                self.entities.put(context)

    def test_exact_replay_is_idempotent_but_mutation_fails_closed(self):
        self.store.add_event(event())
        original = EventEntityContext(
            event_id="evt-storage-001",
            references=(EventEntityReference.opaque(kind="ip", role="source_ip", value="192.0.2.10"),),
        ).validate()
        self.entities.put(original)
        self.entities.put(original)
        with self.store.connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM event_entities").fetchone()[0]
        self.assertEqual(count, 1)

        mutated = EventEntityContext(
            event_id="evt-storage-001",
            references=(EventEntityReference.opaque(kind="ip", role="source_ip", value="192.0.2.11"),),
        ).validate()
        with self.assertRaises(MonitoringContractError):
            self.entities.put(mutated)

    def test_schema_tamper_fails_closed_for_get_and_exact_replay(self):
        self.store.add_event(event())
        context = EventEntityContext(
            event_id="evt-storage-001",
            references=(EventEntityReference.opaque(kind="ip", role="source_ip", value="192.0.2.10"),),
        ).validate()
        self.entities.put(context)
        with self.store.connect() as conn:
            conn.execute(
                "UPDATE event_entities SET schema_version='tampered/v9' WHERE event_id=?",
                ("evt-storage-001",),
            )
        with self.assertRaises(MonitoringContractError):
            self.entities.get("evt-storage-001")
        with self.assertRaises(MonitoringContractError):
            self.entities.put(context)

    def test_historical_exact_replay_survives_later_asset_disable(self):
        self.store.add_event(event())
        context = EventEntityContext(
            event_id="evt-storage-001",
            references=(EventEntityReference.approved_asset(role="asset", asset_id="server-rd-01"),),
        ).validate()
        self.entities.put(context)
        self.store.upsert_asset(asset("server-rd-01", "192.0.2.2", enabled=False))
        self.entities.put(context)
        self.assertEqual(self.entities.get("evt-storage-001"), context)

    def test_existing_monitoring_database_can_be_extended_in_place(self):
        second_path = Path(self.temp.name) / "existing.sqlite3"
        old_store = MonitoringStore(second_path)
        old_store.initialize()
        old_store.upsert_asset(asset("gateway-01", "192.0.2.10"))
        old_store.add_event(event("evt-before-extension"))
        extension = EventEntityContextStore(old_store)
        extension.initialize()
        context = EventEntityContext(
            event_id="evt-before-extension",
            references=(EventEntityReference.approved_asset(role="asset", asset_id="gateway-01"),),
        ).validate()
        extension.put(context)
        self.assertEqual(extension.get("evt-before-extension"), context)
        self.assertEqual(old_store.count("canonical_events"), 1)

    def test_empty_context_and_lookup_bounds_fail_closed(self):
        self.store.add_event(event())
        with self.assertRaises(MonitoringContractError):
            self.entities.put(EventEntityContext(event_id="evt-storage-001", references=()).validate())
        with self.assertRaises(MonitoringContractError):
            self.entities.event_ids_for_entity("entity:ip:sha256:" + "a" * 64, limit=0)
        with self.assertRaises(MonitoringContractError):
            self.entities.event_ids_for_entity("entity:ip:sha256:" + "a" * 64, limit=10001)


if __name__ == "__main__":
    unittest.main()
