from __future__ import annotations

from pathlib import Path

import pytest

from three_agent.capability_authority import CapabilityAuthorityDenied, TaskCapabilityAuthority
from three_agent.capability_invocation_adapter import (
    CapabilityInvocationAdapterError,
    CapabilityInvocationRequest,
    current_runtime_invocation_identity,
    invoke_runtime_tool,
    reviewed_runtime_handler_ids,
)
from three_agent.diagnostics.capability_promotion import promote_planned_route
from three_agent.diagnostics.catalog_compiler import compile_planned_routes
from three_agent.diagnostics.runtime_registry import (
    default_runtime_capability_bindings,
    runtime_micro_tool_registry,
)
from three_agent.diagnostics.vpn_tools import VPN_STATUS_TOOL_ID
from three_agent.task_contract import TaskContractCompiler


def _vpn_contract(*, task_id: str = "vpn-status-test"):
    return TaskContractCompiler().compile(
        task_id=task_id,
        task_type="analysis",
        sensitivity="internal",
        risk_level="low",
        allowed_tools=(VPN_STATUS_TOOL_ID,),
    )


def test_default_task_contract_does_not_auto_grant_vpn_status() -> None:
    contract = TaskContractCompiler().compile(task_id="vpn-default", task_type="analysis")
    assert VPN_STATUS_TOOL_ID not in contract.allowed_tools


def test_explicit_vpn_status_authority_is_exact_local_read_only() -> None:
    authority = TaskCapabilityAuthority.from_contract(_vpn_contract())
    decision = authority.require(
        VPN_STATUS_TOOL_ID,
        resource_kind="vpn_status",
        resource_ref="local:vpn:status",
        effect="read",
    )
    assert decision.allowed is True
    assert decision.reason_code == "CAPABILITY_AUTHORIZED"

    with pytest.raises(CapabilityAuthorityDenied) as wrong_kind:
        authority.require(
            VPN_STATUS_TOOL_ID,
            resource_kind="network_endpoint",
            resource_ref="local:vpn:status",
            effect="read",
        )
    assert wrong_kind.value.reason_code == "RESOURCE_KIND_NOT_AUTHORIZED"

    with pytest.raises(CapabilityAuthorityDenied) as wrong_ref:
        authority.require(
            VPN_STATUS_TOOL_ID,
            resource_kind="vpn_status",
            resource_ref="local:vpn:other",
            effect="read",
        )
    assert wrong_ref.value.reason_code == "RESOURCE_REF_NOT_AUTHORIZED"

    with pytest.raises(CapabilityAuthorityDenied) as widened_effect:
        authority.require(
            VPN_STATUS_TOOL_ID,
            resource_kind="vpn_status",
            resource_ref="local:vpn:status",
            effect="network_read",
        )
    assert widened_effect.value.reason_code == "CAPABILITY_EFFECT_NOT_ALLOWED"


def test_vpn_status_is_source_reviewed_by_canonical_invocation_adapter() -> None:
    assert VPN_STATUS_TOOL_ID in reviewed_runtime_handler_ids()
    snapshot_fingerprint, descriptor_fingerprint = current_runtime_invocation_identity(
        VPN_STATUS_TOOL_ID
    )
    assert snapshot_fingerprint.startswith("sha256:")
    assert descriptor_fingerprint.startswith("sha256:")


def test_canonical_invocation_uses_exact_authority_and_bounded_parameters(monkeypatch) -> None:
    task_id = "vpn-runtime"
    authority = TaskCapabilityAuthority.from_contract(_vpn_contract(task_id=task_id))
    snapshot_fingerprint, descriptor_fingerprint = current_runtime_invocation_identity(
        VPN_STATUS_TOOL_ID
    )
    calls: list[dict[str, object]] = []

    def fake_read_vpn_status(*, authority, timeout=8.0):
        calls.append({"authority": authority, "timeout": timeout})
        return {
            "tool_id": VPN_STATUS_TOOL_ID,
            "observed_count": 0,
            "vpn_health_claimed": False,
            "root_cause_claimed": False,
            "interpretation": "evidence_only",
        }

    monkeypatch.setattr(
        "three_agent.capability_invocation_adapter.read_vpn_status",
        fake_read_vpn_status,
    )
    request = CapabilityInvocationRequest.create(
        task_id=task_id,
        tool_id=VPN_STATUS_TOOL_ID,
        snapshot_fingerprint=snapshot_fingerprint,
        descriptor_fingerprint=descriptor_fingerprint,
        parameters={"timeout": 4.0},
    )
    result = invoke_runtime_tool(request, authority=authority)

    assert result.tool_id == VPN_STATUS_TOOL_ID
    assert result.decision_receipt.decision_allowed is True
    assert calls == [{"authority": authority, "timeout": 4.0}]
    assert "evidence_only" in result.bounded_payload.text


def test_canonical_invocation_rejects_remote_target_parameter_before_handler(monkeypatch) -> None:
    task_id = "vpn-no-remote-target"
    authority = TaskCapabilityAuthority.from_contract(_vpn_contract(task_id=task_id))
    snapshot_fingerprint, descriptor_fingerprint = current_runtime_invocation_identity(
        VPN_STATUS_TOOL_ID
    )
    called = False

    def fake_read_vpn_status(**kwargs):
        nonlocal called
        called = True
        return {}

    monkeypatch.setattr(
        "three_agent.capability_invocation_adapter.read_vpn_status",
        fake_read_vpn_status,
    )
    request = CapabilityInvocationRequest.create(
        task_id=task_id,
        tool_id=VPN_STATUS_TOOL_ID,
        snapshot_fingerprint=snapshot_fingerprint,
        descriptor_fingerprint=descriptor_fingerprint,
        parameters={"host": "192.168.11.1"},
    )
    with pytest.raises(CapabilityInvocationAdapterError, match="UNSUPPORTED_INVOCATION_PARAMETERS"):
        invoke_runtime_tool(request, authority=authority)
    assert called is False


def test_vpn_remote_routes_it_0146_through_it_0165_are_fully_promotable() -> None:
    root = Path(__file__).resolve().parents[1]
    routes = compile_planned_routes(
        (
            root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_1.md",
            root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_2_EXPANSION.md",
            root / "docs" / "OFFICE_IT_SUPPORT_REAL_WORLD_ISSUE_CATALOG_V0_3_EXPANSION.md",
        )
    )
    target_ids = {f"IT-{number:04d}" for number in range(146, 166)}
    selected = [route for route in routes if route.route_id in target_ids]
    assert len(selected) == 20

    registry = runtime_micro_tool_registry()
    bindings = default_runtime_capability_bindings()
    for route in selected:
        result = promote_planned_route(route, registry, bindings=bindings)
        assert result.promotable is True, (route.route_id, result.unresolved_capability_tags)
        assert VPN_STATUS_TOOL_ID in result.selected_tool_ids
