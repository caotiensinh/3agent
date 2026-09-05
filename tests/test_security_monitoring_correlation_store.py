from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import (
    AssetInventoryRecord,
    CanonicalEvent,
    MonitoringContractError,
)
from three_agent.security_monitoring.correlation_graph import CorrelationGraphConfig
from three_agent.security_monitoring.correlation_store import CorrelationStoreReader, CorrelationWindow
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.entity_context_storage import EventEntityContextStore
from three_agent.security_monitoring.storage import MonitoringStore


def approved_asset(asset_id: str) -> AssetInventoryRecord:
    return AssetInventoryRecord(
        asset_id=asset_id,
        role="correlation_endpoint",
        management_host="192.0.2.100",
        collector_capabilities=(),
    ).validate()


def event(
    event_id: str,
    source_type: str,
    category: str,
    observed_at: str,
    refs: tuple[EventEntityReference, ...],
) -> tuple[CanonicalEvent, EventEntityContext]:
    marker = "abcdef0123456789"[sum(ord(ch) for ch in event_id) % 16]
    canonical = CanonicalEvent(
        event_id=event_id,
        source_id="source-" + event_id,
        source_type=source_type,
        observed_at=observed_at,
        category=category,
        severity="info",
        message_sha256="sha256:" + marker * 64,
        parser_version="test-parser/v1",
        evidence_ref="event:" + event_id,
    ).validate()
    return canonical, EventEntityContext(event_id=event_id, references=refs).validate()


class CorrelationStoreReaderTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = MonitoringStore(Path(self.temp.name) / "monitoring.sqlite3")
        self.store.initialize()
        self.store.upsert_asset(approved_asset("server-rd-01"))
        self.entities = EventEntityContextStore(self.store)
        self.entities.initialize()

    def tearDown(self):
        self.temp.cleanup()

    def _put(self, pair: tuple[CanonicalEvent, EventEntityContext]) -> None:
        canonical, context = pair
        self.store.add_event(canonical)
        self.entities.put(context)

    def test_reader_builds_exact_multi_stage_graph_from_existing_store(self):
        client = "192.0.2.10"
        server = "198.51.100.20"
        user = "CORP\\alice"
        self._put(
            event(
                "evt-dns-store",
                "zeek_json",
                "zeek.dns",
                "2026-09-01T00:00:00+00:00",
                (
                    EventEntityReference.opaque(kind="ip", role="source_ip", value=client),
                    EventEntityReference.opaque(kind="ip", role="dns_answer", value=server),
                ),
            )
        )
        self._put(
            event(
                "evt-flow-store",
                "zeek_json",
                "zeek.conn",
                "2026-09-01T09:00:05+09:00",
                (
                    EventEntityReference.opaque(kind="ip", role="source_ip", value=client),
                    EventEntityReference.opaque(kind="ip", role="destination_ip", value=server),
                    EventEntityReference.opaque(kind="service", role="service", value="tcp:22"),
                ),
            )
        )
        self._put(
            event(
                "evt-auth-store",
                "workspace_audit",
                "workspace_audit.auth_success",
                "2026-09-01T00:00:08Z",
                (
                    EventEntityReference.approved_asset(role="asset", asset_id="server-rd-01"),
                    EventEntityReference.opaque(kind="ip", role="source_ip", value=client),
                    EventEntityReference.opaque(kind="ip", role="destination_ip", value=server),
                    EventEntityReference.opaque(kind="service", role="service", value="tcp:22"),
                    EventEntityReference.opaque(kind="user", role="auth_user", value=user),
                ),
            )
        )
        self._put(
            event(
                "evt-process-store",
                "workspace_audit",
                "workspace_audit.process_start",
                "2026-09-01T00:00:12+00:00",
                (
                    EventEntityReference.approved_asset(role="asset", asset_id="server-rd-01"),
                    EventEntityReference.opaque(kind="user", role="auth_user", value=user),
                    EventEntityReference.opaque(kind="process", role="process_image", value="/usr/bin/id"),
                ),
            )
        )
        reader = CorrelationStoreReader(store=self.store, entity_store=self.entities)
        graphs = reader.correlate_window(
            CorrelationWindow(
                starts_at="2026-09-01T08:59:59+09:00",
                ends_at="2026-09-01T09:00:20+09:00",
            )
        )
        self.assertEqual(len(graphs), 1)
        self.assertEqual(graphs[0].stage_types, ("DNS", "FLOW", "AUTH", "PROCESS"))
        self.assertEqual(graphs[0].priority, "high")
        self.assertEqual(graphs[0].authority, "advisory")

    def test_reader_ignores_events_without_entity_context(self):
        orphan, _ = event(
            "evt-orphan-store",
            "suricata_eve",
            "suricata.flow",
            "2026-09-01T00:00:00+00:00",
            (EventEntityReference.opaque(kind="ip", role="source_ip", value="192.0.2.1"),),
        )
        self.store.add_event(orphan)
        reader = CorrelationStoreReader(store=self.store, entity_store=self.entities)
        self.assertEqual(
            reader.read_window(
                CorrelationWindow(
                    starts_at="2026-09-01T00:00:00+00:00",
                    ends_at="2026-09-01T00:01:00+00:00",
                )
            ),
            (),
        )

    def test_reader_event_entity_and_time_bounds_fail_closed(self):
        for index in range(2):
            self._put(
                event(
                    f"evt-bound-{index}",
                    "zeek_json",
                    "zeek.conn",
                    f"2026-09-01T00:00:0{index}+00:00",
                    (
                        EventEntityReference.opaque(
                            kind="ip", role="source_ip", value=f"192.0.2.{index + 1}"
                        ),
                        EventEntityReference.opaque(
                            kind="ip", role="destination_ip", value="198.51.100.10"
                        ),
                    ),
                )
            )
        window = CorrelationWindow(
            starts_at="2026-09-01T00:00:00+00:00",
            ends_at="2026-09-01T00:01:00+00:00",
        )
        with self.assertRaises(MonitoringContractError):
            CorrelationStoreReader(
                store=self.store,
                entity_store=self.entities,
                config=CorrelationGraphConfig(max_events=1),
            ).read_window(window)
        with self.assertRaises(MonitoringContractError):
            CorrelationStoreReader(
                store=self.store,
                entity_store=self.entities,
                config=CorrelationGraphConfig(max_entities=1),
            ).read_window(window)
        with self.assertRaises(MonitoringContractError):
            CorrelationStoreReader(
                store=self.store,
                entity_store=self.entities,
                config=CorrelationGraphConfig(window_seconds=30),
            ).read_window(window)

    def test_window_validation_is_timezone_aware_and_fail_closed(self):
        with self.assertRaises(MonitoringContractError):
            CorrelationWindow(
                starts_at="2026-09-01T00:00:00",
                ends_at="2026-09-01T00:01:00+00:00",
            ).validate()
        with self.assertRaises(MonitoringContractError):
            CorrelationWindow(
                starts_at="2026-09-01T00:02:00+00:00",
                ends_at="2026-09-01T00:01:00+00:00",
            ).validate()


if __name__ == "__main__":
    unittest.main()
