from __future__ import annotations

from dataclasses import replace

import pytest

from three_agent.security_monitoring.capability_registry import SecurityCapabilityRegistry
from three_agent.security_monitoring.capability_router import SecurityCapabilityRouter
from three_agent.security_monitoring.contracts import CanonicalEvent, MonitoringContractError, sha256_fingerprint
from three_agent.security_monitoring.correlation_graph import CorrelationEvent
from three_agent.security_monitoring.entity_context import EventEntityContext, EventEntityReference
from three_agent.security_monitoring.flow_analysis import FlowEvidenceAnalysis, analyze_flow_evidence
from three_agent.security_monitoring.flow_analysis_invocation import (
    FLOW_ANALYSIS_HANDLER_ID,
    FLOW_ANALYSIS_OUTPUT_KIND,
    FlowAnalysisInvocationRequest,
    FlowAnalysisSecurityOperationBindingRegistry,
    FlowAnalysisSecurityOperationInvoker,
    reviewed_flow_analysis_runtime_handler_exists,
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
    router = SecurityCapabilityRouter(registry)
    decision = router.route("analyze netflow evidence")
    assert decision.status == "routed"
    assert [(row.capability_id, row.operation_id) for row in decision.selections] == [
        ("network.flow.analyze", "analyze_flow_evidence")
    ]
    return SecurityOperationPlanCompiler(registry).compile(decision)


def test_flow_analysis_is_deterministic_evidence_bound_and_advisory() -> None:
    dns, flow = _dns_flow_pair()

    first = analyze_flow_evidence((flow, dns))
    second = analyze_flow_evidence((dns, flow))

    assert isinstance(first, FlowEvidenceAnalysis)
    assert first.fingerprint == second.fingerprint
    assert first.public_dict() == second.public_dict()
    assert first.event_count == 2
    assert first.flow_event_count == 1
    assert first.flow_event_ids == ("evt-flow-1",)
    assert first.stage_types == ("DNS", "FLOW")
    assert first.authority == "advisory"
    assert first.reason_codes == (
        "FLOW_EVIDENCE_ANALYZED_DETERMINISTICALLY",
        "FLOW_CROSS_STAGE_CORRELATION_OBSERVED",
    )
    assert len(first.incident_graphs) == 1
    rendered = str(first.public_dict())
    assert "10.10.0.10" not in rendered
    assert "10.10.0.20" not in rendered


def test_flow_analysis_deduplicates_exact_duplicate_but_rejects_conflict() -> None:
    _dns, flow = _dns_flow_pair()
    exact = analyze_flow_evidence((flow, flow))
    assert exact.event_count == 1
    assert exact.flow_event_count == 1

    conflicting = _event(
        "evt-flow-1",
        source_type="suricata_eve",
        category="suricata.flow",
        observed_at="2026-09-02T10:00:05+00:00",
        destination_ip="10.10.0.20",
        message_marker="different-evidence",
    )
    with pytest.raises(MonitoringContractError, match="conflicting flow evidence"):
        analyze_flow_evidence((flow, conflicting))


def test_flow_analysis_rejects_missing_flow_stage_and_missing_evidence_anchor() -> None:
    dns, _flow = _dns_flow_pair()
    with pytest.raises(MonitoringContractError, match="at least one FLOW event"):
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
    with pytest.raises(MonitoringContractError, match="requires evidence_ref"):
        analyze_flow_evidence((flow_without_evidence,))


def test_default_binding_remains_fail_closed_and_opt_in_replaces_exactly_one_operation() -> None:
    registry = SecurityCapabilityRegistry()
    default = SecurityOperationBindingRegistry(registry)
    reviewed = FlowAnalysisSecurityOperationBindingRegistry(registry)

    with pytest.raises(SecurityOperationHandlerUnbound) as exc:
        default.require_bound("network.flow.analyze", "analyze_flow_evidence")
    assert exc.value.reason_code == "UNBOUND_GENERIC_FLOW_ANALYSIS_CONTRACT_REQUIRED"

    binding = reviewed.require_bound("network.flow.analyze", "analyze_flow_evidence")
    assert binding.handler_id == FLOW_ANALYSIS_HANDLER_ID
    assert binding.handler_kind == "pure_function"
    assert binding.output_kind == FLOW_ANALYSIS_OUTPUT_KIND
    assert reviewed.fingerprint != default.fingerprint
    coverage = reviewed.coverage()
    assert coverage.total_operations == 15
    assert coverage.bound_operations == 6
    assert coverage.unbound_operations == 9
    assert coverage.bound_percent == 40.0

    for capability in registry.list_approved():
        for operation in capability.operations:
            key = (capability.capability_id, operation.operation_id)
            if key == ("network.flow.analyze", "analyze_flow_evidence"):
                continue
            assert reviewed.resolve(*key).public_dict() == default.resolve(*key).public_dict()


def test_reviewed_flow_runtime_attestation_is_closed() -> None:
    assert reviewed_flow_analysis_runtime_handler_exists(FLOW_ANALYSIS_HANDLER_ID)
    assert not reviewed_flow_analysis_runtime_handler_exists("analysis.flow_evidence.dynamic")


def test_opt_in_flow_invocation_uses_existing_internal_authority_and_emits_receipt() -> None:
    registry = SecurityCapabilityRegistry()
    plan = _flow_plan(registry)
    dns, flow = _dns_flow_pair()
    request = FlowAnalysisInvocationRequest(events=(flow, dns))
    invoker = FlowAnalysisSecurityOperationInvoker(registry=registry)

    result = invoker.invoke(plan, step_id=plan.steps[0].step_id, request=request)

    assert isinstance(result.output, FlowEvidenceAnalysis)
    assert result.output.authority == "advisory"
    assert result.receipt.handler_id == FLOW_ANALYSIS_HANDLER_ID
    assert result.receipt.handler_kind == "pure_function"
    assert result.receipt.output_kind == FLOW_ANALYSIS_OUTPUT_KIND
    assert result.receipt.authority_domain == "internal"
    assert result.receipt.authority_reason_code == "SECURITY_INTERNAL_OPERATION_AUTHORIZED"
    assert result.receipt.input_fingerprint == request.fingerprint
    assert result.receipt.output_fingerprint == result.output.fingerprint
    assert result.receipt.binding_fingerprint == invoker.binding_registry.fingerprint
    assert plan.steps[0].backend_capability is None
    assert plan.steps[0].effect == "compute"
    assert plan.steps[0].preflight_state == "ready_internal"


def test_default_invoker_still_rejects_generic_flow_operation() -> None:
    registry = SecurityCapabilityRegistry()
    plan = _flow_plan(registry)
    dns, flow = _dns_flow_pair()
    request = FlowAnalysisInvocationRequest(events=(dns, flow))

    with pytest.raises(SecurityOperationHandlerUnbound) as exc:
        SecurityOperationInvoker(registry=registry).invoke(
            plan,
            step_id=plan.steps[0].step_id,
            request=request,  # type: ignore[arg-type]
        )
    assert exc.value.reason_code == "UNBOUND_GENERIC_FLOW_ANALYSIS_CONTRACT_REQUIRED"


def test_flow_invocation_rejects_wrong_request_type_and_tampered_plan() -> None:
    registry = SecurityCapabilityRegistry()
    plan = _flow_plan(registry)
    invoker = FlowAnalysisSecurityOperationInvoker(registry=registry)

    wrong_request = DNSAnalysisInvocationRequest(
        event_id="evt-dns-wrong-type",
        source_type="suricata_eve",
        raw_line='{"dns":{"rrname":"example.invalid"}}',
    )
    with pytest.raises(SecurityOperationInvocationDenied, match="INVOCATION_REQUEST_TYPE_MISMATCH"):
        invoker.invoke(plan, step_id=plan.steps[0].step_id, request=wrong_request)

    tampered = replace(plan, plan_fingerprint="sha256:" + "0" * 64)
    with pytest.raises(SecurityOperationPlanError, match="INVOCATION_PLAN_FINGERPRINT_TAMPERED"):
        invoker.invoke(
            tampered,
            step_id=tampered.steps[0].step_id,
            request=FlowAnalysisInvocationRequest(events=(_dns_flow_pair()[1],)),
        )


def test_flow_invocation_request_fingerprint_is_order_invariant() -> None:
    dns, flow = _dns_flow_pair()
    assert FlowAnalysisInvocationRequest(events=(dns, flow)).fingerprint == FlowAnalysisInvocationRequest(
        events=(flow, dns)
    ).fingerprint
