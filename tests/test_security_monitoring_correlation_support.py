from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError
from three_agent.security_monitoring.correlation_graph import (
    CorrelationEvent,
    DeterministicIncidentCorrelator,
)
from three_agent.security_monitoring.correlation_store import CorrelationStoreReader, CorrelationWindow
from three_agent.security_monitoring.correlation_support import (
    CorrelationSupportConfig,
    attach_supporting_evidence,
)
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.entity_context_storage import EventEntityContextStore
from three_agent.security_monitoring.storage import MonitoringStore


def item(
    *,
    event_id: str,
    source_type: str,
    category: str,
    observed_at: str,
    refs: tuple[EventEntityReference, ...],
) -> CorrelationEvent:
    marker = "abcdef0123456789"[sum(ord(ch) for ch in event_id) % 16]
    event = CanonicalEvent(
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
    context = EventEntityContext(event_id=event_id, references=refs).validate()
    return CorrelationEvent(event=event, context=context).validate()


def asset(asset_id: str) -> EventEntityReference:
    return EventEntityReference.approved_asset(role="asset", asset_id=asset_id)


def opaque(kind: str, role: str, value: str) -> EventEntityReference:
    return EventEntityReference.opaque(kind=kind, role=role, value=value)


def auth_process_graph():
    user = "CORP\\alice"
    auth = item(
        event_id="evt-auth-support",
        source_type="workspace_audit",
        category="workspace_audit.auth_success",
        observed_at="2026-09-01T00:00:08+00:00",
        refs=(asset("server-rd-01"), opaque("user", "auth_user", user)),
    )
    process = item(
        event_id="evt-process-support",
        source_type="workspace_audit",
        category="workspace_audit.process_start",
        observed_at="2026-09-01T00:00:12+00:00",
        refs=(
            asset("server-rd-01"),
            opaque("user", "auth_user", user),
            opaque("process", "process_image", "/usr/bin/id"),
        ),
    )
    graph = DeterministicIncidentCorrelator().correlate((auth, process))[0]
    return graph, auth, process


class CorrelationSupportTests(unittest.TestCase):
    def test_monitoring_support_attaches_by_exact_asset_without_mutating_graph(self):
        graph, auth, process = auth_process_graph()
        health = item(
            event_id="evt-health-support",
            source_type="monitoring_observation",
            category="monitoring.snmpv3_read",
            observed_at="2026-09-01T00:00:13+00:00",
            refs=(
                asset("server-rd-01"),
                opaque("interface", "interface", "Ethernet1/1"),
            ),
        )
        original = graph.public_dict()
        support = attach_supporting_evidence((graph,), (auth, process, health))
        self.assertEqual(len(support), 1)
        self.assertEqual(support[0].graph_id, graph.graph_id)
        self.assertEqual(support[0].event_ids, ("evt-health-support",))
        self.assertEqual(support[0].relation, "supporting_context_only")
        self.assertEqual(support[0].authority, "advisory")
        self.assertIn("asset:server-rd-01", support[0].shared_entity_refs)
        self.assertEqual(graph.public_dict(), original)

    def test_time_proximity_or_wrong_asset_never_attaches_support(self):
        graph, auth, process = auth_process_graph()
        wrong = item(
            event_id="evt-health-wrong",
            source_type="monitoring_observation",
            category="monitoring.icmp_echo",
            observed_at="2026-09-01T00:00:13+00:00",
            refs=(asset("server-rd-02"),),
        )
        self.assertEqual(
            attach_supporting_evidence((graph,), (auth, process, wrong)),
            (),
        )

    def test_exact_interface_can_attach_without_becoming_causal_stage(self):
        client = "192.0.2.10"
        server = "198.51.100.20"
        interface = "Ethernet1/1"
        dns = item(
            event_id="evt-dns-interface",
            source_type="zeek_json",
            category="zeek.dns",
            observed_at="2026-09-01T00:00:00+00:00",
            refs=(
                opaque("ip", "source_ip", client),
                opaque("ip", "dns_answer", server),
            ),
        )
        flow = item(
            event_id="evt-flow-interface",
            source_type="zeek_json",
            category="zeek.conn",
            observed_at="2026-09-01T00:00:05+00:00",
            refs=(
                opaque("ip", "source_ip", client),
                opaque("ip", "destination_ip", server),
                opaque("interface", "interface", interface),
            ),
        )
        health = item(
            event_id="evt-interface-health",
            source_type="monitoring_observation",
            category="monitoring.snmpv3_read",
            observed_at="2026-09-01T00:00:06+00:00",
            refs=(
                asset("switch-rd-01"),
                opaque("interface", "interface", interface),
            ),
        )
        graph = DeterministicIncidentCorrelator().correlate((dns, flow, health))[0]
        self.assertEqual(graph.stage_types, ("DNS", "FLOW"))
        support = attach_supporting_evidence((graph,), (dns, flow, health))[0]
        self.assertEqual(support.event_ids, ("evt-interface-health",))
        self.assertEqual(
            support.shared_entity_refs,
            (opaque("interface", "interface", interface).entity_ref,),
        )

    def test_support_bounds_fail_closed(self):
        graph, auth, process = auth_process_graph()
        support_items = tuple(
            item(
                event_id=f"evt-health-{index}",
                source_type="monitoring_observation",
                category="monitoring.icmp_echo",
                observed_at=f"2026-09-01T00:00:{13 + index:02d}+00:00",
                refs=(asset("server-rd-01"),),
            )
            for index in range(2)
        )
        with self.assertRaises(MonitoringContractError):
            attach_supporting_evidence(
                (graph,),
                (auth, process, *support_items),
                config=CorrelationSupportConfig(max_support_events=1),
            )

    def test_store_reader_returns_separate_support_bundle_and_support_alone_creates_no_graph(self):
        graph, auth, process = auth_process_graph()
        health = item(
            event_id="evt-health-store-support",
            source_type="monitoring_observation",
            category="monitoring.icmp_echo",
            observed_at="2026-09-01T00:00:13+00:00",
            refs=(asset("server-rd-01"),),
        )
        with tempfile.TemporaryDirectory() as tmp:
            store = MonitoringStore(Path(tmp) / "monitoring.sqlite3")
            store.initialize()
            entities = EventEntityContextStore(store)
            entities.initialize()
            for entry in (auth, process, health):
                store.add_event(entry.event)
                entities.put(entry.context)

            reader = CorrelationStoreReader(store=store, entity_store=entities)
            bundles = reader.correlate_window_with_support(
                CorrelationWindow(
                    starts_at="2026-09-01T00:00:00+00:00",
                    ends_at="2026-09-01T00:00:20+00:00",
                )
            )
            self.assertEqual(len(bundles), 1)
            self.assertEqual(bundles[0].graph, graph)
            self.assertIsNotNone(bundles[0].support)
            self.assertEqual(
                bundles[0].support.event_ids,
                ("evt-health-store-support",),
            )

        only_health_graphs = DeterministicIncidentCorrelator().correlate((health,))
        self.assertEqual(only_health_graphs, ())


if __name__ == "__main__":
    unittest.main()
