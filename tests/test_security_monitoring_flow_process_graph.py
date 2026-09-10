from __future__ import annotations

import inspect
import json
import unittest

import three_agent.security_monitoring as monitoring
import three_agent.security_monitoring.flow_process_graph as bridge_module
from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError
from three_agent.security_monitoring.correlation_graph import (
    RULE_AUTH_PROCESS,
    CorrelationEvent,
    DeterministicIncidentCorrelator,
)
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.flow_process_attribution import (
    FlowTupleEvidence,
    SocketProcessObservation,
)
from three_agent.security_monitoring.flow_process_engine import (
    DeterministicFlowProcessAttributor,
    FlowProcessAttributionConfig,
)
from three_agent.security_monitoring.flow_process_graph import (
    FLOW_PROCESS_GRAPH_CATEGORY,
    FLOW_PROCESS_GRAPH_PARSER_VERSION,
    FLOW_PROCESS_GRAPH_SOURCE_ID,
    FLOW_PROCESS_GRAPH_SOURCE_TYPE,
    attribution_to_correlation_event,
)


def flow(
    *,
    event_id: str = "flow-1",
    src_port: int = 50123,
    dst_port: int = 443,
) -> FlowTupleEvidence:
    return FlowTupleEvidence.build(
        event_id=event_id,
        observed_at="2026-09-01T14:00:00Z",
        protocol="tcp",
        source_ip="192.0.2.10",
        source_port=src_port,
        destination_ip="198.51.100.20",
        destination_port=dst_port,
        evidence_ref=f"evidence:{event_id}",
    )


def socket(
    *,
    evidence_ref: str = "evidence:socket-1",
    process_image: str = "browser.exe",
    user: str | None = "alice",
) -> SocketProcessObservation:
    return SocketProcessObservation.build(
        approved_asset_id="workstation-01",
        observed_at="2026-09-01T14:00:01Z",
        protocol="tcp",
        local_ip="192.0.2.10",
        local_port=50123,
        remote_ip="198.51.100.20",
        remote_port=443,
        process_image=process_image,
        user=user,
        evidence_ref=evidence_ref,
    )


def assessment_for(
    flow_item: FlowTupleEvidence,
    sockets: tuple[SocketProcessObservation, ...],
):
    engine = DeterministicFlowProcessAttributor(
        FlowProcessAttributionConfig(max_time_skew_seconds=5)
    )
    return engine.attribute(flows=(flow_item,), socket_observations=sockets)[0]


def reference(item: CorrelationEvent, role: str) -> str:
    values = item.context.refs_for_role(role)
    if len(values) != 1:
        raise AssertionError(f"expected exactly one {role} reference")
    return values[0]


class FlowProcessGraphBridgeTests(unittest.TestCase):
    def test_exact_attribution_emits_process_stage_with_typed_refs_only(self) -> None:
        f = flow()
        assessment = assessment_for(f, (socket(),))
        item = attribution_to_correlation_event(flow=f, assessment=assessment)
        self.assertIsNotNone(item)
        assert item is not None

        self.assertEqual(item.stage, "PROCESS")
        self.assertEqual(item.event.source_id, FLOW_PROCESS_GRAPH_SOURCE_ID)
        self.assertEqual(item.event.source_type, FLOW_PROCESS_GRAPH_SOURCE_TYPE)
        self.assertEqual(item.event.category, FLOW_PROCESS_GRAPH_CATEGORY)
        self.assertEqual(item.event.parser_version, FLOW_PROCESS_GRAPH_PARSER_VERSION)
        self.assertEqual(item.event.message_sha256, assessment.fingerprint)
        self.assertEqual(item.event.evidence_ref, assessment.attribution_id)
        self.assertEqual(item.event.severity, "info")
        self.assertEqual(reference(item, "asset"), "asset:workstation-01")
        self.assertTrue(reference(item, "process_image").startswith("entity:process:sha256:"))
        self.assertTrue(reference(item, "auth_user").startswith("entity:user:sha256:"))

        rendered = json.dumps(
            {"event": item.event.__dict__, "context": item.context.public_dict()},
            sort_keys=True,
        ).lower()
        for forbidden in (
            "192.0.2.10",
            "198.51.100.20",
            "browser.exe",
            "alice",
            "password",
            "token",
        ):
            self.assertNotIn(forbidden, rendered)

    def test_ambiguous_and_unmatched_assessments_emit_no_process_event(self) -> None:
        f = flow()
        unmatched = assessment_for(f, ())
        self.assertEqual(unmatched.status, "unmatched")
        self.assertIsNone(attribution_to_correlation_event(flow=f, assessment=unmatched))

        ambiguous = assessment_for(
            f,
            (
                socket(evidence_ref="evidence:socket-a", process_image="browser.exe"),
                socket(evidence_ref="evidence:socket-b", process_image="updater.exe"),
            ),
        )
        self.assertEqual(ambiguous.status, "ambiguous")
        self.assertIsNone(attribution_to_correlation_event(flow=f, assessment=ambiguous))

    def test_assessment_must_bind_exact_flow_identity_and_evidence(self) -> None:
        original = flow()
        assessment = assessment_for(original, (socket(),))
        other = flow(event_id="flow-2", src_port=50124)
        with self.assertRaises(MonitoringContractError):
            attribution_to_correlation_event(flow=other, assessment=assessment)

    def test_attributed_process_reuses_existing_auth_process_graph_rule(self) -> None:
        f = flow()
        assessment = assessment_for(f, (socket(),))
        process_event = attribution_to_correlation_event(flow=f, assessment=assessment)
        assert process_event is not None

        auth_event = CanonicalEvent(
            event_id="auth-1",
            source_id="audit-source",
            source_type="workspace_audit",
            observed_at="2026-09-01T13:59:59Z",
            category="workspace_audit.auth_success",
            severity="info",
            message_sha256="sha256:" + "a" * 64,
            parser_version="test/v1",
            evidence_ref="evidence:auth-1",
        ).validate()
        auth_context = EventEntityContext(
            event_id=auth_event.event_id,
            references=(
                EventEntityReference(
                    kind="asset",
                    role="asset",
                    entity_ref=reference(process_event, "asset"),
                ).validate(),
                EventEntityReference(
                    kind="user",
                    role="auth_user",
                    entity_ref=reference(process_event, "auth_user"),
                ).validate(),
            ),
        ).validate()
        auth = CorrelationEvent(event=auth_event, context=auth_context).validate()

        graphs = DeterministicIncidentCorrelator().correlate((auth, process_event))
        self.assertEqual(len(graphs), 1)
        self.assertEqual(graphs[0].rule_ids, (RULE_AUTH_PROCESS,))
        self.assertEqual(graphs[0].stage_types, ("AUTH", "PROCESS"))
        self.assertEqual(graphs[0].authority, "advisory")

    def test_same_inputs_are_byte_deterministic(self) -> None:
        f = flow()
        assessment = assessment_for(f, (socket(),))
        left = attribution_to_correlation_event(flow=f, assessment=assessment)
        right = attribution_to_correlation_event(flow=f, assessment=assessment)
        assert left is not None and right is not None
        self.assertEqual(left, right)
        self.assertEqual(left.event.__dict__, right.event.__dict__)
        self.assertEqual(left.context.public_dict(), right.context.public_dict())

    def test_public_package_exports_stable_phase6_api(self) -> None:
        for name in (
            "FlowTupleEvidence",
            "SocketProcessObservation",
            "FlowProcessAttributionAssessment",
            "FlowProcessAttributionConfig",
            "DeterministicFlowProcessAttributor",
            "attribution_to_correlation_event",
        ):
            self.assertTrue(hasattr(monitoring, name), name)

    def test_bridge_has_no_collection_shell_pcap_or_remediation_authority(self) -> None:
        source = inspect.getsource(bridge_module)
        for forbidden in (
            "import socket",
            "subprocess",
            "urlopen",
            "requests.",
            "tcpdump",
            "pcap",
            "firewall",
            "quarantine_host",
            "kill_process",
        ):
            self.assertNotIn(forbidden, source.lower())


if __name__ == "__main__":
    unittest.main()
