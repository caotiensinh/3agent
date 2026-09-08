from __future__ import annotations

import unittest
from dataclasses import replace

from three_agent.capability_authority import TaskCapabilityAuthority, _EFFECTS
from three_agent.diagnostics.runtime_registry import (
    default_runtime_capability_bindings,
    runtime_tool_metadata,
)
from three_agent.invocation_decision_receipt import receipt_from_capability_decision
from three_agent.micro_tool_registry import ToolMetadata
from three_agent.security_monitoring.contracts import sha256_fingerprint
from three_agent.security_monitoring.diagnostic_lineage import normalize_diagnostic_lineage
from three_agent.security_monitoring.diagnostic_observation import DiagnosticObservation
from three_agent.task_contract import TOOLS, TaskContractCompiler, TaskContractError


def _assert_runtime_consistency(metadata: tuple[ToolMetadata, ...]) -> None:
    runtime_ids = {item.id for item in metadata}
    unknown = runtime_ids - TOOLS
    if unknown:
        raise AssertionError(f"unknown runtime tool ids: {sorted(unknown)}")

    missing_effects = runtime_ids - set(_EFFECTS)
    if missing_effects:
        raise AssertionError(f"runtime tool ids missing authority effects: {sorted(missing_effects)}")

    effect_drift = {
        item.id: (item.effect, _EFFECTS[item.id])
        for item in metadata
        if _EFFECTS[item.id] != item.effect
    }
    if effect_drift:
        raise AssertionError(f"runtime/authority effect drift: {effect_drift}")

    binding_targets = {
        tool_id
        for binding in default_runtime_capability_bindings()
        for tool_id in binding.tool_ids
    }
    missing_runtime = binding_targets - runtime_ids
    if missing_runtime:
        raise AssertionError(
            f"runtime capability bindings target missing tools: {sorted(missing_runtime)}"
        )


def _runtime_snapshot_fingerprint(metadata: tuple[ToolMetadata, ...]) -> str:
    return sha256_fingerprint([item.to_dict() for item in metadata])


class CapabilityCrossLayerConsistencyTests(unittest.TestCase):
    def test_runtime_registry_matches_authority_vocabulary_and_effects(self) -> None:
        metadata = runtime_tool_metadata()
        _assert_runtime_consistency(metadata)

        runtime_ids = {item.id for item in metadata}
        self.assertTrue(runtime_ids)
        self.assertTrue(runtime_ids.issubset(TOOLS))
        self.assertEqual(
            runtime_ids,
            {item.id for item in runtime_tool_metadata()},
        )

    def test_deliberate_unknown_registry_drift_is_caught(self) -> None:
        baseline = runtime_tool_metadata()
        drift = ToolMetadata(
            id="diagnostic.unknown.fixture",
            platform="any",
            category="diagnostic",
            keywords=("fixture",),
            cost="C0",
            risk="read_only",
            requires_admin=False,
            network_access="none",
            sensitive_outputs=False,
            effect="read",
        ).validate()

        with self.assertRaisesRegex(AssertionError, "unknown runtime tool ids"):
            _assert_runtime_consistency(baseline + (drift,))

    def test_deliberate_effect_drift_is_caught(self) -> None:
        metadata = runtime_tool_metadata()
        baseline = next(item for item in metadata if item.id == "system.platform.identify")
        drifted = replace(baseline, effect="compute").validate()
        fixture = tuple(drifted if item.id == baseline.id else item for item in metadata)

        with self.assertRaisesRegex(AssertionError, "runtime/authority effect drift"):
            _assert_runtime_consistency(fixture)

    def test_unknown_tool_cannot_enter_task_authority(self) -> None:
        with self.assertRaises(TaskContractError):
            TaskContractCompiler().compile(
                task_id="TASK-L20-UNKNOWN",
                task_type="analysis",
                sensitivity="internal",
                allowed_tools=("diagnostic.unknown.fixture",),
            )

    def test_authority_receipt_observation_and_lineage_reconcile(self) -> None:
        metadata = runtime_tool_metadata()
        _assert_runtime_consistency(metadata)
        by_id = {item.id: item for item in metadata}
        tool = by_id["network.quality.internal"]

        contract = TaskContractCompiler().compile(
            task_id="TASK-L20-NETWORK-QUALITY",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=(tool.id,),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        decision = authority.require(
            tool.id,
            resource_kind="network_endpoint",
            resource_ref="192.168.11.10:icmp-quality",
            effect=tool.effect,
        )

        task_ref = sha256_fingerprint(contract.to_dict())
        request_ref = sha256_fingerprint(
            {
                "task_id": contract.task_id,
                "request": "bounded-network-quality-evidence",
            }
        )
        descriptor_fingerprint = sha256_fingerprint(tool.to_dict())
        snapshot_fingerprint = _runtime_snapshot_fingerprint(metadata)

        receipt = receipt_from_capability_decision(
            decision=decision,
            task_ref_sha256=task_ref,
            request_ref_sha256=request_ref,
            tool_id=tool.id,
            descriptor_fingerprint=descriptor_fingerprint,
            snapshot_fingerprint=snapshot_fingerprint,
        )

        payload = '{"latency_ms":12,"reachable":true}'
        observation = DiagnosticObservation(
            source_tool=tool.id,
            source_capability=decision.capability,
            task_ref_sha256=task_ref,
            request_ref_sha256=request_ref,
            observed_at="2026-09-08T14:30:00Z",
            status="succeeded",
            summary="Bounded internal network quality observation",
            payload=payload,
            content_type="application/json",
            original_payload_bytes=len(payload.encode("utf-8")),
        ).validate()
        evidence_fingerprint = sha256_fingerprint(
            {
                "kind": "diagnostic-evidence",
                "observation_fingerprint": observation.fingerprint,
            }
        )
        lineage = normalize_diagnostic_lineage(
            decision=decision,
            task_ref_sha256=task_ref,
            request_ref_sha256=request_ref,
            source_tool=tool.id,
            observation_fingerprint=observation.fingerprint,
            evidence_fingerprint=evidence_fingerprint,
        )

        self.assertEqual(receipt.task_id, contract.task_id)
        self.assertEqual(receipt.task_ref_sha256, observation.task_ref_sha256)
        self.assertEqual(receipt.request_ref_sha256, observation.request_ref_sha256)
        self.assertEqual(receipt.tool_id, observation.source_tool)
        self.assertEqual(receipt.capability_id, observation.source_capability)
        self.assertEqual(receipt.authority_fingerprint, decision.authority_fingerprint)
        self.assertEqual(receipt.descriptor_fingerprint, descriptor_fingerprint)
        self.assertEqual(receipt.snapshot_fingerprint, snapshot_fingerprint)
        self.assertEqual(lineage.task_id, contract.task_id)
        self.assertEqual(lineage.source_tool, receipt.tool_id)
        self.assertEqual(lineage.source_capability, receipt.capability_id)
        self.assertEqual(lineage.provenance_status, "complete")
        self.assertEqual(lineage.trust_status, "unverified")
        self.assertEqual(receipt.authority, "advisory")
        self.assertEqual(observation.authority, "advisory")
        self.assertEqual(lineage.authority, "advisory")
        self.assertFalse(receipt.automatic_action_allowed)
        self.assertFalse(observation.automatic_action_allowed)
        self.assertFalse(lineage.automatic_action_allowed)

    def test_descriptor_or_snapshot_mutation_changes_receipt_identity(self) -> None:
        metadata = runtime_tool_metadata()
        tool = next(item for item in metadata if item.id == "network.quality.internal")
        contract = TaskContractCompiler().compile(
            task_id="TASK-L20-MUTATION",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=(tool.id,),
        )
        decision = TaskCapabilityAuthority.from_contract(contract).require(
            tool.id,
            resource_kind="network_endpoint",
            resource_ref="192.168.11.10:icmp-quality",
            effect=tool.effect,
        )
        task_ref = sha256_fingerprint(contract.to_dict())
        request_ref = sha256_fingerprint({"task_id": contract.task_id, "request": "fixture"})
        descriptor = sha256_fingerprint(tool.to_dict())
        snapshot = _runtime_snapshot_fingerprint(metadata)

        baseline = receipt_from_capability_decision(
            decision=decision,
            task_ref_sha256=task_ref,
            request_ref_sha256=request_ref,
            tool_id=tool.id,
            descriptor_fingerprint=descriptor,
            snapshot_fingerprint=snapshot,
        )
        descriptor_changed = receipt_from_capability_decision(
            decision=decision,
            task_ref_sha256=task_ref,
            request_ref_sha256=request_ref,
            tool_id=tool.id,
            descriptor_fingerprint=sha256_fingerprint({"fixture": "descriptor-drift"}),
            snapshot_fingerprint=snapshot,
        )
        snapshot_changed = receipt_from_capability_decision(
            decision=decision,
            task_ref_sha256=task_ref,
            request_ref_sha256=request_ref,
            tool_id=tool.id,
            descriptor_fingerprint=descriptor,
            snapshot_fingerprint=sha256_fingerprint({"fixture": "snapshot-drift"}),
        )

        self.assertNotEqual(baseline.fingerprint, descriptor_changed.fingerprint)
        self.assertNotEqual(baseline.fingerprint, snapshot_changed.fingerprint)


if __name__ == "__main__":
    unittest.main()
