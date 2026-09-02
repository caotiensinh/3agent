from __future__ import annotations

import unittest
from dataclasses import replace

from three_agent.security_monitoring.capability_registry import SecurityCapabilityRegistry
from three_agent.security_monitoring.capability_router import SecurityCapabilityRouter
from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.incident_timeline import IncidentTimeline, build_incident_timeline
from three_agent.security_monitoring.incident_timeline_binding import (
    INCIDENT_TIMELINE_HANDLER_ID,
    INCIDENT_TIMELINE_OUTPUT_KIND,
    IncidentTimelineSecurityOperationBindingRegistry,
    reviewed_incident_timeline_runtime_handler_exists,
)
from three_agent.security_monitoring.incident_timeline_invocation import (
    IncidentTimelineInvocationRequest,
    IncidentTimelineSecurityOperationInvoker,
)
from three_agent.security_monitoring.operation_binding import (
    SecurityOperationBindingRegistry,
    SecurityOperationHandlerUnbound,
)
from three_agent.security_monitoring.operation_invocation import (
    DNSAnalysisInvocationRequest,
    SecurityOperationInvocationDenied,
    SecurityOperationInvoker,
)
from three_agent.security_monitoring.operation_plan import SecurityOperationPlanCompiler, SecurityOperationPlanError


def _event(
    event_id: str,
    *,
    category: str,
    observed_at: str,
    source_ip: str = "10.20.0.10",
    destination_ip: str = "10.20.0.20",
    dns_answer: str | None = None,
    evidence_ref: str | None = None,
    message_marker: str | None = None,
) -> CorrelationEvent:
    refs = [
        EventEntityReference.approved_asset(role="asset", asset_id="asset-timeline-1"),
        EventEntityReference.opaque(kind="ip", role="source_ip", value=source_ip),
    ]
    if category == "suricata.flow":
        refs.append(EventEntityReference.opaque(kind="ip", role="destination_ip", value=destination_ip))
    if dns_answer is not None:
        refs.append(EventEntityReference.opaque(kind="ip", role="dns_answer", value=dns_answer))
    event = CanonicalEvent(
        event_id=event_id,
        source_id="sensor-timeline-1",
        source_type="suricata_eve",
        observed_at=observed_at,
        category=category,
        severity="medium",
        message_sha256=sha256_fingerprint({"event": message_marker or event_id}),
        parser_version="parser-v1",
        evidence_ref=evidence_ref if evidence_ref is not None else f"evidence:{event_id}",
    ).validate()
    context = EventEntityContext(event_id=event_id, references=tuple(refs)).validate()
    return CorrelationEvent(event=event, context=context).validate()


def _dns_flow_pair() -> tuple[CorrelationEvent, CorrelationEvent]:
    dns = _event(
        "evt-timeline-dns",
        category="suricata.dns",
        observed_at="2026-09-02T11:00:00+00:00",
        dns_answer="10.20.0.20",
    )
    flow = _event(
        "evt-timeline-flow",
        category="suricata.flow",
        observed_at="2026-09-02T11:00:07+00:00",
        destination_ip="10.20.0.20",
    )
    return dns, flow


def _timeline_plan(registry: SecurityCapabilityRegistry):
    decision = SecurityCapabilityRouter(registry).route("build incident timeline")
    if decision.status != "routed":
        raise AssertionError("timeline test fixture did not route")
    selected = {(row.capability_id, row.operation_id) for row in decision.selections}
    timeline_key = ("security.incident_triage.analyze", "build_incident_timeline")
    if timeline_key not in selected:
        raise AssertionError(f"timeline route missing reviewed operation: {selected!r}")
    plan = SecurityOperationPlanCompiler(registry).compile(decision)
    timeline_steps = [
        step
        for step in plan.steps
        if (step.capability_id, step.operation_id) == timeline_key
    ]
    if len(timeline_steps) != 1:
        raise AssertionError(f"unexpected timeline step count: {len(timeline_steps)}")
    return plan, timeline_steps[0]


class SecurityIncidentTimelineV010Tests(unittest.TestCase):
    def test_timeline_is_deterministic_chronological_evidence_bound_and_advisory(self) -> None:
        dns, flow = _dns_flow_pair()
        first = build_incident_timeline((flow, dns))
        second = build_incident_timeline((dns, flow))

        self.assertIsInstance(first, IncidentTimeline)
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.public_dict(), second.public_dict())
        self.assertEqual(first.entry_count, 2)
        self.assertEqual(first.graph_count, 1)
        self.assertEqual(tuple(entry.event_id for entry in first.entries), ("evt-timeline-dns", "evt-timeline-flow"))
        self.assertEqual(tuple(entry.stage for entry in first.entries), ("DNS", "FLOW"))
        self.assertEqual(first.stage_types, ("DNS", "FLOW"))
        self.assertEqual(first.first_seen, "2026-09-02T11:00:00+00:00")
        self.assertEqual(first.last_seen, "2026-09-02T11:00:07+00:00")
        self.assertEqual(first.authority, "advisory")
        self.assertEqual(
            first.reason_codes,
            (
                "INCIDENT_TIMELINE_BUILT_DETERMINISTICALLY",
                "INCIDENT_TIMELINE_REQUIRES_EXACT_CORRELATION",
            ),
        )
        rendered = str(first.public_dict())
        self.assertNotIn("10.20.0.10", rendered)
        self.assertNotIn("10.20.0.20", rendered)

    def test_timeline_rejects_uncorrelated_events_instead_of_manufacturing_incident(self) -> None:
        dns, _flow = _dns_flow_pair()
        unrelated_flow = _event(
            "evt-timeline-unrelated-flow",
            category="suricata.flow",
            observed_at="2026-09-02T11:00:08+00:00",
            source_ip="10.20.0.99",
            destination_ip="10.20.0.77",
        )
        with self.assertRaisesRegex(MonitoringContractError, "requires deterministically correlated incident evidence"):
            build_incident_timeline((dns, unrelated_flow))

    def test_timeline_deduplicates_exact_event_and_rejects_conflicting_event_id(self) -> None:
        dns, flow = _dns_flow_pair()
        timeline = build_incident_timeline((dns, flow, flow))
        self.assertEqual(timeline.entry_count, 2)

        conflicting = _event(
            "evt-timeline-flow",
            category="suricata.flow",
            observed_at="2026-09-02T11:00:07+00:00",
            destination_ip="10.20.0.20",
            message_marker="conflicting-message-hash",
        )
        with self.assertRaisesRegex(MonitoringContractError, "conflicting timeline evidence"):
            build_incident_timeline((dns, flow, conflicting))

    def test_timeline_rejects_missing_evidence_anchor(self) -> None:
        dns, flow = _dns_flow_pair()
        flow_without_evidence = CorrelationEvent(event=replace(flow.event, evidence_ref=None), context=flow.context)
        with self.assertRaisesRegex(MonitoringContractError, "requires evidence_ref"):
            build_incident_timeline((dns, flow_without_evidence))

    def test_timeline_entries_exactly_cover_correlated_graph_events(self) -> None:
        dns, flow = _dns_flow_pair()
        extra = _event(
            "evt-timeline-extra",
            category="suricata.flow",
            observed_at="2026-09-02T11:00:10+00:00",
            source_ip="10.20.0.55",
            destination_ip="10.20.0.66",
        )
        timeline = build_incident_timeline((extra, flow, dns))
        correlated = {event_id for graph in timeline.incident_graphs for event_id in graph.event_ids}
        self.assertEqual(correlated, {entry.event_id for entry in timeline.entries})
        self.assertNotIn("evt-timeline-extra", correlated)
        self.assertNotIn("evt-timeline-extra", {entry.event_id for entry in timeline.entries})

    def test_default_binding_remains_fail_closed_and_opt_in_replaces_exactly_one_operation(self) -> None:
        registry = SecurityCapabilityRegistry()
        default = SecurityOperationBindingRegistry(registry)
        reviewed = IncidentTimelineSecurityOperationBindingRegistry(registry)

        with self.assertRaises(SecurityOperationHandlerUnbound) as caught:
            default.require_bound("security.incident_triage.analyze", "build_incident_timeline")
        self.assertEqual(caught.exception.reason_code, "UNBOUND_TIMELINE_ADAPTER_REQUIRED")

        binding = reviewed.require_bound("security.incident_triage.analyze", "build_incident_timeline")
        self.assertEqual(binding.handler_id, INCIDENT_TIMELINE_HANDLER_ID)
        self.assertEqual(binding.handler_kind, "pure_function")
        self.assertEqual(binding.output_kind, INCIDENT_TIMELINE_OUTPUT_KIND)
        self.assertNotEqual(reviewed.fingerprint, default.fingerprint)
        coverage = reviewed.coverage()
        self.assertEqual(coverage.total_operations, 15)
        self.assertEqual(coverage.bound_operations, 6)
        self.assertEqual(coverage.unbound_operations, 9)
        self.assertEqual(coverage.bound_percent, 40.0)

        for capability in registry.list_approved():
            for operation in capability.operations:
                key = (capability.capability_id, operation.operation_id)
                if key == ("security.incident_triage.analyze", "build_incident_timeline"):
                    continue
                self.assertEqual(reviewed.resolve(*key).public_dict(), default.resolve(*key).public_dict())

    def test_reviewed_timeline_runtime_attestation_is_closed(self) -> None:
        self.assertTrue(reviewed_incident_timeline_runtime_handler_exists(INCIDENT_TIMELINE_HANDLER_ID))
        self.assertFalse(reviewed_incident_timeline_runtime_handler_exists("analysis.incident_timeline.dynamic"))

    def test_opt_in_timeline_invocation_uses_internal_authority_and_emits_receipt(self) -> None:
        registry = SecurityCapabilityRegistry()
        plan, timeline_step = _timeline_plan(registry)
        dns, flow = _dns_flow_pair()
        request = IncidentTimelineInvocationRequest(events=(flow, dns))
        invoker = IncidentTimelineSecurityOperationInvoker(registry=registry)

        result = invoker.invoke(plan, step_id=timeline_step.step_id, request=request)

        self.assertIsInstance(result.output, IncidentTimeline)
        self.assertEqual(result.output.authority, "advisory")
        self.assertEqual(result.receipt.handler_id, INCIDENT_TIMELINE_HANDLER_ID)
        self.assertEqual(result.receipt.handler_kind, "pure_function")
        self.assertEqual(result.receipt.output_kind, INCIDENT_TIMELINE_OUTPUT_KIND)
        self.assertEqual(result.receipt.authority_domain, "internal")
        self.assertEqual(result.receipt.authority_reason_code, "SECURITY_INTERNAL_OPERATION_AUTHORIZED")
        self.assertEqual(result.receipt.input_fingerprint, request.fingerprint)
        self.assertEqual(result.receipt.output_fingerprint, result.output.fingerprint)
        self.assertEqual(result.receipt.binding_fingerprint, invoker.binding_registry.fingerprint)
        self.assertIsNone(timeline_step.backend_capability)
        self.assertEqual(timeline_step.effect, "compute")
        self.assertEqual(timeline_step.preflight_state, "ready_internal")

    def test_default_invoker_still_rejects_timeline_operation(self) -> None:
        registry = SecurityCapabilityRegistry()
        plan, timeline_step = _timeline_plan(registry)
        dns, flow = _dns_flow_pair()
        request = IncidentTimelineInvocationRequest(events=(dns, flow))
        with self.assertRaises(SecurityOperationHandlerUnbound) as caught:
            SecurityOperationInvoker(registry=registry).invoke(
                plan,
                step_id=timeline_step.step_id,
                request=request,  # type: ignore[arg-type]
            )
        self.assertEqual(caught.exception.reason_code, "UNBOUND_TIMELINE_ADAPTER_REQUIRED")

    def test_timeline_invocation_rejects_wrong_request_type_and_tampered_plan(self) -> None:
        registry = SecurityCapabilityRegistry()
        plan, timeline_step = _timeline_plan(registry)
        invoker = IncidentTimelineSecurityOperationInvoker(registry=registry)
        wrong_request = DNSAnalysisInvocationRequest(
            event_id="evt-dns-wrong-timeline-type",
            source_type="suricata_eve",
            raw_line='{"dns":{"rrname":"example.invalid"}}',
        )
        with self.assertRaisesRegex(SecurityOperationInvocationDenied, "INVOCATION_REQUEST_TYPE_MISMATCH"):
            invoker.invoke(plan, step_id=timeline_step.step_id, request=wrong_request)

        dns, flow = _dns_flow_pair()
        tampered = replace(plan, plan_fingerprint="sha256:" + "0" * 64)
        with self.assertRaisesRegex(SecurityOperationPlanError, "INVOCATION_PLAN_FINGERPRINT_TAMPERED"):
            invoker.invoke(
                tampered,
                step_id=timeline_step.step_id,
                request=IncidentTimelineInvocationRequest(events=(dns, flow)),
            )

    def test_timeline_invocation_request_fingerprint_is_order_invariant(self) -> None:
        dns, flow = _dns_flow_pair()
        left = IncidentTimelineInvocationRequest(events=(dns, flow)).fingerprint
        right = IncidentTimelineInvocationRequest(events=(flow, dns)).fingerprint
        self.assertEqual(left, right)


if __name__ == "__main__":
    unittest.main()
