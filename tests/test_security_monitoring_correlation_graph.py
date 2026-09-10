from __future__ import annotations

import inspect
import json
import unittest

import three_agent.security_monitoring.correlation_graph as graph_module
from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError
from three_agent.security_monitoring.correlation_graph import (
    RULE_AUTH_PROCESS,
    RULE_DNS_FLOW,
    RULE_FLOW_AUTH,
    RULE_IDS_CORROBORATION,
    CorrelationEvent,
    CorrelationGraphConfig,
    DeterministicIncidentCorrelator,
)
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference


def ref(kind: str, role: str, value: str) -> EventEntityReference:
    return EventEntityReference.opaque(kind=kind, role=role, value=value)


def asset(asset_id: str) -> EventEntityReference:
    return EventEntityReference.approved_asset(role="asset", asset_id=asset_id)


def correlation_event(
    *,
    event_id: str,
    category: str,
    source_type: str,
    observed_at: str,
    refs: tuple[EventEntityReference, ...],
    severity: str = "info",
) -> CorrelationEvent:
    hex_char = "abcdef0123456789"[sum(ord(ch) for ch in event_id) % 16]
    event = CanonicalEvent(
        event_id=event_id,
        source_id="source-" + event_id,
        source_type=source_type,
        observed_at=observed_at,
        category=category,
        severity=severity,
        message_sha256="sha256:" + hex_char * 64,
        parser_version="test-parser/v1",
        evidence_ref="event:" + event_id,
    ).validate()
    context = EventEntityContext(event_id=event_id, references=refs).validate()
    return CorrelationEvent(event=event, context=context).validate()


def chain_events():
    client = "192.0.2.10"
    server = "198.51.100.20"
    user = "CORP\\alice"
    dns = correlation_event(
        event_id="evt-dns",
        category="zeek.dns",
        source_type="zeek_json",
        observed_at="2026-09-01T00:00:00+00:00",
        refs=(
            ref("ip", "source_ip", client),
            ref("dns", "dns_query", "admin.example.internal"),
            ref("ip", "dns_answer", server),
        ),
    )
    flow = correlation_event(
        event_id="evt-flow",
        category="zeek.conn",
        source_type="zeek_json",
        observed_at="2026-09-01T00:00:05+00:00",
        refs=(
            ref("ip", "source_ip", client),
            ref("ip", "destination_ip", server),
            ref("service", "service", "tcp:22"),
        ),
        severity="low",
    )
    auth = correlation_event(
        event_id="evt-auth",
        category="workspace_audit.auth_success",
        source_type="workspace_audit",
        observed_at="2026-09-01T00:00:08+00:00",
        refs=(
            asset("server-rd-01"),
            ref("ip", "source_ip", client),
            ref("ip", "destination_ip", server),
            ref("service", "service", "tcp:22"),
            ref("user", "auth_user", user),
        ),
    )
    process = correlation_event(
        event_id="evt-process",
        category="workspace_audit.process_start",
        source_type="workspace_audit",
        observed_at="2026-09-01T00:00:12+00:00",
        refs=(
            asset("server-rd-01"),
            ref("user", "auth_user", user),
            ref("process", "process_image", "/usr/bin/id"),
        ),
    )
    return dns, flow, auth, process


class CorrelationGraphTests(unittest.TestCase):
    def test_dns_flow_requires_exact_initiator_and_resolved_address(self):
        dns, flow, _, _ = chain_events()
        graphs = DeterministicIncidentCorrelator().correlate((dns, flow))
        self.assertEqual(len(graphs), 1)
        self.assertEqual(graphs[0].rule_ids, (RULE_DNS_FLOW,))
        self.assertEqual(graphs[0].stage_types, ("DNS", "FLOW"))

        wrong_destination = correlation_event(
            event_id="evt-flow-wrong",
            category="zeek.conn",
            source_type="zeek_json",
            observed_at="2026-09-01T00:00:05+00:00",
            refs=(
                ref("ip", "source_ip", "192.0.2.10"),
                ref("ip", "destination_ip", "198.51.100.99"),
                ref("service", "service", "tcp:22"),
            ),
        )
        self.assertEqual(DeterministicIncidentCorrelator().correlate((dns, wrong_destination)), ())

        wrong_initiator = correlation_event(
            event_id="evt-flow-other-client",
            category="zeek.conn",
            source_type="zeek_json",
            observed_at="2026-09-01T00:00:05+00:00",
            refs=(
                ref("ip", "source_ip", "192.0.2.99"),
                ref("ip", "destination_ip", "198.51.100.20"),
                ref("service", "service", "tcp:22"),
            ),
        )
        self.assertEqual(DeterministicIncidentCorrelator().correlate((dns, wrong_initiator)), ())

    def test_flow_auth_requires_exact_endpoints_and_service(self):
        _, flow, auth, _ = chain_events()
        graph = DeterministicIncidentCorrelator().correlate((flow, auth))[0]
        self.assertEqual(graph.rule_ids, (RULE_FLOW_AUTH,))

        wrong_service = correlation_event(
            event_id="evt-auth-rdp",
            category="workspace_audit.auth_success",
            source_type="workspace_audit",
            observed_at="2026-09-01T00:00:08+00:00",
            refs=(
                asset("server-rd-01"),
                ref("ip", "source_ip", "192.0.2.10"),
                ref("ip", "destination_ip", "198.51.100.20"),
                ref("service", "service", "tcp:3389"),
                ref("user", "auth_user", "CORP\\alice"),
            ),
        )
        self.assertEqual(DeterministicIncidentCorrelator().correlate((flow, wrong_service)), ())

    def test_auth_process_requires_exact_asset_and_user(self):
        _, _, auth, process = chain_events()
        graph = DeterministicIncidentCorrelator().correlate((auth, process))[0]
        self.assertEqual(graph.rule_ids, (RULE_AUTH_PROCESS,))

        other_user = correlation_event(
            event_id="evt-process-bob",
            category="workspace_audit.process_start",
            source_type="workspace_audit",
            observed_at="2026-09-01T00:00:12+00:00",
            refs=(
                asset("server-rd-01"),
                ref("user", "auth_user", "CORP\\bob"),
                ref("process", "process_image", "/usr/bin/id"),
            ),
        )
        self.assertEqual(DeterministicIncidentCorrelator().correlate((auth, other_user)), ())

    def test_multi_stage_chain_is_high_priority_advisory_and_metadata_only(self):
        dns, flow, auth, process = chain_events()
        graph = DeterministicIncidentCorrelator().correlate((dns, flow, auth, process))[0]
        self.assertEqual(graph.stage_types, ("DNS", "FLOW", "AUTH", "PROCESS"))
        self.assertEqual(set(graph.rule_ids), {RULE_DNS_FLOW, RULE_FLOW_AUTH, RULE_AUTH_PROCESS})
        self.assertEqual(graph.priority, "high")
        self.assertEqual(graph.severity, "high")
        self.assertEqual(graph.authority, "advisory")
        rendered = json.dumps(graph.public_dict(), sort_keys=True)
        for forbidden in (
            "192.0.2.10",
            "198.51.100.20",
            "admin.example.internal",
            "alice",
            "/usr/bin/id",
            "password",
            "token",
        ):
            self.assertNotIn(forbidden, rendered.lower())
        self.assertIn("asset:server-rd-01", rendered)

    def test_time_proximity_alone_never_creates_an_edge(self):
        left = correlation_event(
            event_id="evt-near-dns",
            category="zeek.dns",
            source_type="zeek_json",
            observed_at="2026-09-01T00:00:00+00:00",
            refs=(ref("ip", "source_ip", "192.0.2.1"), ref("ip", "dns_answer", "198.51.100.1")),
        )
        right = correlation_event(
            event_id="evt-near-flow",
            category="zeek.conn",
            source_type="zeek_json",
            observed_at="2026-09-01T00:00:01+00:00",
            refs=(ref("ip", "source_ip", "192.0.2.2"), ref("ip", "destination_ip", "198.51.100.2")),
        )
        self.assertEqual(DeterministicIncidentCorrelator().correlate((left, right)), ())

    def test_outside_time_window_does_not_correlate_even_with_exact_entities(self):
        dns, flow, _, _ = chain_events()
        late_flow = correlation_event(
            event_id="evt-flow-late",
            category="zeek.conn",
            source_type="zeek_json",
            observed_at="2026-09-01T01:00:00+00:00",
            refs=flow.context.references,
        )
        correlator = DeterministicIncidentCorrelator(CorrelationGraphConfig(window_seconds=30))
        self.assertEqual(correlator.correlate((dns, late_flow)), ())

    def test_ids_corroboration_requires_exact_entity(self):
        _, flow, _, _ = chain_events()
        ids = correlation_event(
            event_id="evt-ids",
            category="suricata.alert",
            source_type="suricata_eve",
            observed_at="2026-09-01T00:00:06+00:00",
            refs=(
                ref("ip", "source_ip", "192.0.2.10"),
                ref("ip", "destination_ip", "198.51.100.20"),
            ),
            severity="high",
        )
        graph = DeterministicIncidentCorrelator().correlate((flow, ids))[0]
        self.assertEqual(graph.rule_ids, (RULE_IDS_CORROBORATION,))
        self.assertEqual(graph.severity, "high")

    def test_replay_does_not_inflate_and_conflicting_duplicate_fails_closed(self):
        dns, flow, _, _ = chain_events()
        first = DeterministicIncidentCorrelator().correlate((dns, flow, dns, flow))
        second = DeterministicIncidentCorrelator().correlate((dns, flow))
        self.assertEqual(first, second)
        self.assertEqual(len(first[0].event_ids), 2)

        tampered = CorrelationEvent(
            event=dns.event,
            context=EventEntityContext(
                event_id=dns.event.event_id,
                references=(ref("ip", "source_ip", "192.0.2.250"),),
            ).validate(),
        ).validate()
        with self.assertRaises(MonitoringContractError):
            DeterministicIncidentCorrelator().correlate((dns, tampered, flow))

    def test_bounds_fail_closed(self):
        dns, flow, _, _ = chain_events()
        with self.assertRaises(MonitoringContractError):
            DeterministicIncidentCorrelator(CorrelationGraphConfig(max_events=1)).correlate((dns, flow))
        with self.assertRaises(MonitoringContractError):
            DeterministicIncidentCorrelator(CorrelationGraphConfig(max_entities=1)).correlate((dns,))
        with self.assertRaises(MonitoringContractError):
            DeterministicIncidentCorrelator(CorrelationGraphConfig(max_edges=1)).correlate(chain_events())

    def test_engine_has_no_network_model_shell_pcap_or_remediation_authority(self):
        source = inspect.getsource(graph_module)
        for forbidden in (
            "import socket",
            "subprocess",
            "urlopen",
            "requests.",
            "OllamaClient",
            "generate_json",
            "tcpdump",
            "approve_capture",
            "execute_capture",
            "firewall",
            "quarantine_host",
        ):
            self.assertNotIn(forbidden, source)


if __name__ == "__main__":
    unittest.main()
