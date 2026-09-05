from __future__ import annotations

import unittest
from dataclasses import replace

from three_agent.security_monitoring.capability_registry import SecurityCapabilityRegistry
from three_agent.security_monitoring.capability_router import SecurityCapabilityRouter
from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.flow_analysis import FlowEvidenceAnalysis, analyze_flow_evidence
from three_agent.security_monitoring.flow_analysis_invocation import (
    FLOW_ANALYSIS_HANDLER_ID,
    FLOW_ANALYSIS_OUTPUT_KIND,
    FLOW_ANALYSIS_REVIEWED_BINDING,
    FlowAnalysisInvocationRequest,
    FlowAnalysisReviewedOperationBinding,
    FlowAnalysisSecurityOperationBindingRegistry,
    FlowAnalysisSecurityOperationInvoker,
    reviewed_flow_analysis_runtime_handler_exists,
)
from three_agent.security_monitoring.operation_binding import SecurityOperationBindingRegistry
from three_agent.security_monitoring.operation_invocation import (
    DNSAnalysisInvocationRequest,
    SecurityOperationInvocationDenied,
    SecurityOperationInvocationError,
    SecurityOperationInvoker,
)
from three_agent.security_monitoring.operation_plan import (
    SecurityOperationPlanCompiler,
    SecurityOperationPlanError,
)


def _event(
    event_id: str,
    *,
    source_type: str,
    category: str,
    observed_at: str,
    source_ip: str = "10.10.0.10",
    destination_ip: str = "10.10.0.20",
    dns_answer: str | None = None,
    evidence_ref: str | None = None,
    message_marker: str | None = None,
) -> CorrelationEvent:
    refs = [
        EventEntityReference.approved_asset(role="asset", asset_id="asset-edge-1"),
        EventEntityReference.opaque(kind="ip", role="source_ip", value=source_ip),
    ]
    if category in {"suricata.flow", "zeek.conn"}:
        refs.append(EventEntityReference.opaque(kind="ip", role="destination_ip", value=destination_ip))
    if dns_answer is not None:
        refs.append(EventEntityReference.opaque(kind="ip", role="dns_answer", value=dns_answer))
    event = CanonicalEvent(
        event_id=event_id,
        source_id="sensor-edge-1",
        source_type=source_type,
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
        "evt-dns-1",
        source_type="suricata_eve",
        category="suricata.dns",
        observed_at="2026-09-02T10:00:00+00:00",
        dns_answer="10.10.0.20",
    )
    flow = _event(
        "evt-flow-1",
        source_type="suricata_eve",
        category="suricata.flow",
        observed_at="2026-09-02T10:00:05+00:00",
        destination_ip="10.10.0.20",
    )
    return dns, flow


def _flow_plan(registry: SecurityCapabilityRegistry):
    decision = SecurityCapabilityRouter(registry).route("analyze netflow evidence")
    if decision.status != "routed":
        raise AssertionError("flow test fixture did not route")
    selected = [(row.capability_id, row.operation_id) for row in decision.selections]
    if selected != [("network.flow.analyze", "analyze_flow_evidence")]:
        raise AssertionError(f"unexpected flow route: {selected!r}")
    return SecurityOperationPlanCompiler(registry).compile(decision)


class SecurityFlowAnalysisV09Tests(unittest.TestCase):
    def test_flow_analysis_is_deterministic_evidence_bound_and_advisory(self) -> None:
        dns, flow = _dns_flow_pair()

        first = analyze_flow_evidence((flow, dns))
        second = analyze_flow_evidence((dns, flow))

        self.assertIsInstance(first, FlowEvidenceAnalysis)
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.public_dict(), second.public_dict())
        self.assertEqual(first.event_count, 2)
        self.assertEqual(first.flow_event_count, 1)
        self.assertEqual(first.flow_event_ids, ("evt-flow-1",))
        self.assertEqual(first.stage_types, ("DNS", "FLOW"))
        self.assertEqual(first.authority, "advisory")
        self.assertEqual(
            first.reason_codes,
            (
                "FLOW_EVIDENCE_ANALYZED_DETERMINISTICALLY",
                "FLOW_CROSS_STAGE_CORRELATION_OBSERVED",
            ),
        )
        self.assertEqual(len(first.incident_graphs), 1)
        rendered = str(first.public_dict())
        self.assertNotIn("10.10.0.10", rendered)
        self.assertNotIn("10.10.0.20", rendered)

    def test_flow_analysis_deduplicates_exact_duplicate_but_rejects_conflict(self) -> None:
        _dns, flow = _dns_flow_pair()
        exact = analyze_flow_evidence((flow, flow))
        self.assertEqual(exact.event_count, 1)
        self.assertEqual(exact.flow_event_count, 1)

        conflicting = _event(
            "evt-flow-1",
            source_type="suricata_eve",
            category="suricata.flow",
            observed_at="2026-09-02T10:00:05+00:00",
            destination_ip="10.10.0.20",
            message_marker="different-evidence",
        )
        with self.assertRaisesRegex(MonitoringContractError, "conflicting flow evidence"):
            analyze_flow_evidence((flow, conflicting))

    def test_flow_analysis_rejects_missing_flow_stage_and_missing_evidence_anchor(self) -> None:
        dns, _flow = _dns_flow_pair()
        with self.assertRaisesRegex(MonitoringContractError, "at least one FLOW event"):
            analyze_flow_evidence((dns,))

        flow_without_evidence = _event(
            "evt-flow-no-evidence",
            source_type="suricata_eve",
            category="suricata.flow",
            observed_at="2026-09-02T10:01:00+00:00",
            evidence_ref="evidence:placeholder",
        )
        flow_without_evidence = CorrelationEvent(
            event=replace(flow_without_evidence.event, evidence_ref=None),
            context=flow_without_evidence.context,
        )
        with self.assertRaisesRegex(MonitoringContractError, "requires evidence_ref"):
            analyze_flow_evidence((flow_without_evidence,))

    def test_default_binding_is_canonical_and_compatibility_profile_is_a_closed_facade(self) -> None:
        registry = SecurityCapabilityRegistry()
        default = SecurityOperationBindingRegistry(registry)
        compatibility = FlowAnalysisSecurityOperationBindingRegistry(registry)

        self.assertTrue(issubclass(FlowAnalysisSecurityOperationBindingRegistry, SecurityOperationBindingRegistry))
        binding = default.require_bound("network.flow.analyze", "analyze_flow_evidence")
        compatibility_binding = compatibility.require_bound(
            "network.flow.analyze",
            "analyze_flow_evidence",
        )
        self.assertEqual(binding.handler_id, FLOW_ANALYSIS_HANDLER_ID)
        self.assertEqual(binding.handler_kind, "pure_function")
        self.assertIsInstance(compatibility_binding, FlowAnalysisReviewedOperationBinding)
        self.assertEqual(compatibility_binding.output_kind, FLOW_ANALYSIS_OUTPUT_KIND)
        self.assertEqual(compatibility.fingerprint, default.fingerprint)
        coverage = default.coverage()
        self.assertEqual(coverage.total_operations, 15)
        self.assertEqual(coverage.bound_operations, 6)
        self.assertEqual(coverage.unbound_operations, 9)
        self.assertEqual(coverage.bound_percent, 40.0)
        with self.assertRaises(TypeError):
            FlowAnalysisSecurityOperationBindingRegistry(registry=registry, bindings=())  # type: ignore[call-arg]

    def test_legacy_reviewed_binding_data_contract_remains_available(self) -> None:
        self.assertIsInstance(FLOW_ANALYSIS_REVIEWED_BINDING, FlowAnalysisReviewedOperationBinding)
        self.assertEqual(FLOW_ANALYSIS_REVIEWED_BINDING.capability_id, "network.flow.analyze")
        self.assertEqual(FLOW_ANALYSIS_REVIEWED_BINDING.operation_id, "analyze_flow_evidence")
        self.assertEqual(FLOW_ANALYSIS_REVIEWED_BINDING.status, "bound")
        self.assertEqual(FLOW_ANALYSIS_REVIEWED_BINDING.handler_id, FLOW_ANALYSIS_HANDLER_ID)
        self.assertEqual(FLOW_ANALYSIS_REVIEWED_BINDING.handler_kind, "pure_function")
        self.assertEqual(FLOW_ANALYSIS_REVIEWED_BINDING.output_kind, FLOW_ANALYSIS_OUTPUT_KIND)
        self.assertEqual(
            FLOW_ANALYSIS_REVIEWED_BINDING.public_dict()["output_kind"],
            FLOW_ANALYSIS_OUTPUT_KIND,
        )

    def test_reviewed_flow_runtime_attestation_is_closed(self) -> None:
        self.assertTrue(reviewed_flow_analysis_runtime_handler_exists(FLOW_ANALYSIS_HANDLER_ID))
        self.assertFalse(reviewed_flow_analysis_runtime_handler_exists("analysis.flow_evidence.dynamic"))

    def test_canonical_flow_invocation_uses_internal_authority_and_emits_evidence_receipt(self) -> None:
        registry = SecurityCapabilityRegistry()
        plan = _flow_plan(registry)
        dns, flow = _dns_flow_pair()
        request = FlowAnalysisInvocationRequest(events=(flow, dns))
        invoker = SecurityOperationInvoker(registry=registry)

        result = invoker.invoke(plan, step_id=plan.steps[0].step_id, request=request)

        self.assertIsInstance(result.output, FlowEvidenceAnalysis)
        self.assertEqual(result.output.authority, "advisory")
        self.assertEqual(result.receipt.handler_id, FLOW_ANALYSIS_HANDLER_ID)
        self.assertEqual(result.receipt.handler_kind, "pure_function")
        self.assertEqual(result.receipt.output_kind, FLOW_ANALYSIS_OUTPUT_KIND)
        self.assertEqual(result.receipt.authority_domain, "internal")
        self.assertEqual(result.receipt.authority_reason_code, "SECURITY_INTERNAL_OPERATION_AUTHORIZED")
        self.assertEqual(result.receipt.input_fingerprint, request.fingerprint)
        self.assertEqual(result.receipt.output_fingerprint, result.output.fingerprint)
        self.assertEqual(result.receipt.binding_fingerprint, invoker.binding_registry.fingerprint)
        self.assertIsNone(plan.steps[0].backend_capability)
        self.assertEqual(plan.steps[0].effect, "compute")
        self.assertEqual(plan.steps[0].preflight_state, "ready_internal")
        self.assertEqual(set(FlowAnalysisInvocationRequest.__dataclass_fields__), {"events"})

    def test_compatibility_invoker_delegates_canonically_and_rejects_binding_injection(self) -> None:
        self.assertTrue(issubclass(FlowAnalysisSecurityOperationInvoker, SecurityOperationInvoker))
        registry = SecurityCapabilityRegistry()
        plan = _flow_plan(registry)
        dns, flow = _dns_flow_pair()
        invoker = FlowAnalysisSecurityOperationInvoker(registry=registry)
        self.assertIsInstance(invoker.binding_registry, FlowAnalysisSecurityOperationBindingRegistry)
        result = invoker.invoke(
            plan,
            step_id=plan.steps[0].step_id,
            request=FlowAnalysisInvocationRequest(events=(dns, flow)),
        )
        self.assertEqual(result.receipt.output_fingerprint, result.output.fingerprint)
        with self.assertRaisesRegex(
            SecurityOperationInvocationError,
            "flow analysis invoker owns its reviewed binding profile",
        ):
            FlowAnalysisSecurityOperationInvoker(
                registry=registry,
                binding_registry=SecurityOperationBindingRegistry(registry),
            )

    def test_flow_invocation_rejects_wrong_request_type_and_tampered_plan(self) -> None:
        registry = SecurityCapabilityRegistry()
        plan = _flow_plan(registry)
        invoker = SecurityOperationInvoker(registry=registry)

        wrong_request = DNSAnalysisInvocationRequest(
            event_id="evt-dns-wrong-type",
            source_type="suricata_eve",
            raw_line='{"dns":{"rrname":"example.invalid"}}',
        )
        with self.assertRaisesRegex(SecurityOperationInvocationDenied, "INVOCATION_REQUEST_TYPE_MISMATCH"):
            invoker.invoke(plan, step_id=plan.steps[0].step_id, request=wrong_request)

        tampered = replace(plan, plan_fingerprint="sha256:" + "0" * 64)
        with self.assertRaisesRegex(SecurityOperationPlanError, "INVOCATION_PLAN_FINGERPRINT_TAMPERED"):
            invoker.invoke(
                tampered,
                step_id=tampered.steps[0].step_id,
                request=FlowAnalysisInvocationRequest(events=(_dns_flow_pair()[1],)),
            )

    def test_flow_invocation_request_fingerprint_is_order_invariant(self) -> None:
        dns, flow = _dns_flow_pair()
        left = FlowAnalysisInvocationRequest(events=(dns, flow)).fingerprint
        right = FlowAnalysisInvocationRequest(events=(flow, dns)).fingerprint
        self.assertEqual(left, right)


if __name__ == "__main__":
    unittest.main()
