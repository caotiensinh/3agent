from __future__ import annotations

import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError
from three_agent.security_monitoring.dns_behavior import extract_dns_behavior_features
from three_agent.security_monitoring.dns_behavior_storage import DNSBehaviorFeatureStore
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.entity_context_storage import EventEntityContextStore
from three_agent.security_monitoring.storage import MonitoringStore


def canonical(event_id: str = "evt-dns-store-001") -> CanonicalEvent:
    return CanonicalEvent(
        event_id=event_id,
        source_id="zeek-dns-store",
        source_type="zeek_json",
        observed_at="2026-09-01T00:00:00+00:00",
        category="zeek.dns",
        severity="info",
        message_sha256="sha256:" + "a" * 64,
        parser_version="workspace-json-sensor/v1",
        evidence_ref="event:" + "a" * 32,
    ).validate()


def feature(event_id: str = "evt-dns-store-001"):
    return extract_dns_behavior_features(
        event_id=event_id,
        source_type="zeek_json",
        raw_line=json.dumps(
            {
                "_path": "dns",
                "query": "updates.example.org",
                "rcode_name": "NOERROR",
                "qtype_name": "AAAA",
                "answers": ["198.51.100.20"],
            }
        ),
    )


class DNSBehaviorFeatureStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.store = MonitoringStore(Path(self.temp.name) / "monitoring.sqlite3")
        self.entities = EventEntityContextStore(self.store)
        self.entities.initialize()
        self.features = DNSBehaviorFeatureStore(self.store)
        self.features.initialize()

    def tearDown(self):
        self.temp.cleanup()

    def _bind_event(self, current=None):
        current = current or feature()
        self.store.add_event(canonical(current.event_id))
        self.entities.put(
            EventEntityContext(
                event_id=current.event_id,
                references=(
                    EventEntityReference(
                        kind="dns",
                        role="dns_query",
                        entity_ref=current.query_entity_ref,
                    ).validate(),
                ),
            ).validate()
        )
        return current

    def test_additive_schema_round_trip_and_exact_replay(self):
        current = self._bind_event()
        self.features.put(current)
        self.features.put(current)
        self.assertEqual(self.features.get(current.event_id), current)
        self.assertEqual(self.store.schema_version(), 1)
        self.assertEqual(self.features.schema_version(), 1)
        with self.store.connect() as conn:
            count = conn.execute("SELECT COUNT(*) FROM dns_behavior_features").fetchone()[0]
        self.assertEqual(count, 1)

    def test_feature_requires_existing_event_and_exact_dns_entity_binding(self):
        current = feature()
        with self.assertRaises(MonitoringContractError):
            self.features.put(current)

        self.store.add_event(canonical())
        wrong = EventEntityReference.opaque(
            kind="dns", role="dns_query", value="different.example.org"
        )
        self.entities.put(
            EventEntityContext(event_id=current.event_id, references=(wrong,)).validate()
        )
        with self.assertRaises(MonitoringContractError):
            self.features.put(current)

    def test_conflicting_replay_is_rejected(self):
        current = self._bind_event()
        self.features.put(current)
        mutated = replace(current, answer_count=current.answer_count + 1)
        with self.assertRaises(MonitoringContractError):
            self.features.put(mutated)

    def test_stored_schema_or_parser_tamper_fails_closed_on_read_and_replay(self):
        current = self._bind_event()
        self.features.put(current)
        for column in ("schema_version", "parser_version"):
            with self.store.connect() as conn:
                conn.execute(
                    f"UPDATE dns_behavior_features SET {column}='tampered' WHERE event_id=?",
                    (current.event_id,),
                )
            with self.assertRaises(MonitoringContractError):
                self.features.get(current.event_id)
            with self.assertRaises(MonitoringContractError):
                self.features.put(current)
            with self.store.connect() as conn:
                conn.execute("DELETE FROM dns_behavior_features WHERE event_id=?", (current.event_id,))
            self.features.put(current)

    def test_non_dns_canonical_event_cannot_receive_dns_feature(self):
        current = feature()
        bad_event = replace(canonical(), category="zeek.conn")
        self.store.add_event(bad_event)
        self.entities.put(
            EventEntityContext(
                event_id=current.event_id,
                references=(
                    EventEntityReference(
                        kind="dns", role="dns_query", entity_ref=current.query_entity_ref
                    ).validate(),
                ),
            ).validate()
        )
        with self.assertRaises(MonitoringContractError):
            self.features.put(current)


if __name__ == "__main__":
    unittest.main()
