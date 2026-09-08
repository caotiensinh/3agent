from __future__ import annotations

import unittest

from three_agent.capability_authority import (
    CapabilityAuthorityDenied,
    TaskCapabilityAuthority,
)
from three_agent.diagnostics.runtime_registry import runtime_tool_metadata
from three_agent.task_contract import TOOLS, TaskContractCompiler, TaskContractError


class DiagnosticCapabilityAuthorityTests(unittest.TestCase):
    def test_default_internal_analysis_does_not_auto_grant_diagnostic_tools(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-DEFAULT",
            task_type="analysis",
            sensitivity="internal",
        )
        for tool_id in (
            "system.resource.snapshot",
            "network.reachability.internal",
            "network.quality.internal",
            "identity.session.snapshot",
            "audio.devices.snapshot",
            "process.top.snapshot",
            "hardware.usb.snapshot",
            "camera.devices.snapshot",
        ):
            self.assertNotIn(tool_id, contract.allowed_tools)
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"):
            authority.require(
                "system.resource.snapshot",
                resource_kind="performance_snapshot",
                resource_ref="local:resources",
                effect="read",
            )
        with self.assertRaisesRegex(CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"):
            authority.require(
                "network.quality.internal",
                resource_kind="network_endpoint",
                resource_ref="192.168.11.10:icmp-quality",
                effect="network_read",
            )
        with self.assertRaisesRegex(CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"):
            authority.require(
                "identity.session.snapshot",
                resource_kind="identity_session",
                resource_ref="local:identity:current",
                effect="read",
            )
        with self.assertRaisesRegex(CapabilityAuthorityDenied, "CAPABILITY_NOT_ALLOWED"):
            authority.require(
                "audio.devices.snapshot",
                resource_kind="audio_devices",
                resource_ref="local:audio:devices",
                effect="read",
            )

    def test_explicit_local_read_tool_can_be_authorized_without_write_or_egress(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-LOCAL",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("system.resource.snapshot",),
        )
        self.assertEqual(contract.allowed_tools, ("system.resource.snapshot",))
        self.assertEqual(contract.write_scope, "none")
        authority = TaskCapabilityAuthority.from_contract(contract)
        decision = authority.require(
            "system.resource.snapshot",
            resource_kind="performance_snapshot",
            resource_ref="local:resources",
            effect="read",
        )
        self.assertTrue(decision.allowed)

    def test_explicit_identity_session_read_can_be_authorized_without_write_or_egress(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-IDENTITY",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("identity.session.snapshot",),
        )
        self.assertEqual(contract.allowed_tools, ("identity.session.snapshot",))
        self.assertEqual(contract.write_scope, "none")
        self.assertNotEqual(contract.network_scope, "allowlisted_egress")
        authority = TaskCapabilityAuthority.from_contract(contract)
        decision = authority.require(
            "identity.session.snapshot",
            resource_kind="identity_session",
            resource_ref="local:identity:current",
            effect="read",
        )
        self.assertTrue(decision.allowed)

    def test_explicit_audio_device_read_can_be_authorized_without_write_or_egress(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-AUDIO",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("audio.devices.snapshot",),
        )
        self.assertEqual(contract.allowed_tools, ("audio.devices.snapshot",))
        self.assertEqual(contract.write_scope, "none")
        self.assertNotEqual(contract.network_scope, "allowlisted_egress")
        authority = TaskCapabilityAuthority.from_contract(contract)
        decision = authority.require(
            "audio.devices.snapshot",
            resource_kind="audio_devices",
            resource_ref="local:audio:devices",
            effect="read",
        )
        self.assertTrue(decision.allowed)

    def test_local_endpoint_evidence_tools_require_explicit_read_authority(self) -> None:
        cases = (
            ("process.top.snapshot", "process_inventory", "local:processes:top"),
            ("hardware.usb.snapshot", "usb_devices", "local:usb:devices"),
            ("camera.devices.snapshot", "camera_devices", "local:camera:devices"),
        )
        for tool_id, resource_kind, resource_ref in cases:
            with self.subTest(tool_id=tool_id):
                contract = TaskContractCompiler().compile(
                    task_id=f"TASK-DIAG-{tool_id}",
                    task_type="analysis",
                    sensitivity="internal",
                    allowed_tools=(tool_id,),
                )
                self.assertEqual(contract.allowed_tools, (tool_id,))
                self.assertEqual(contract.write_scope, "none")
                self.assertNotEqual(contract.network_scope, "allowlisted_egress")
                authority = TaskCapabilityAuthority.from_contract(contract)
                decision = authority.require(
                    tool_id,
                    resource_kind=resource_kind,
                    resource_ref=resource_ref,
                    effect="read",
                )
                self.assertTrue(decision.allowed)

    def test_local_endpoint_evidence_tools_reject_effect_widening(self) -> None:
        cases = (
            ("process.top.snapshot", "process_inventory", "local:processes:top"),
            ("hardware.usb.snapshot", "usb_devices", "local:usb:devices"),
            ("camera.devices.snapshot", "camera_devices", "local:camera:devices"),
        )
        for tool_id, resource_kind, resource_ref in cases:
            with self.subTest(tool_id=tool_id):
                contract = TaskContractCompiler().compile(
                    task_id=f"TASK-DIAG-EFFECT-{tool_id}",
                    task_type="analysis",
                    sensitivity="internal",
                    allowed_tools=(tool_id,),
                )
                authority = TaskCapabilityAuthority.from_contract(contract)
                for widened_effect in ("network_read", "execute"):
                    with self.assertRaisesRegex(
                        CapabilityAuthorityDenied,
                        "CAPABILITY_EFFECT_NOT_ALLOWED",
                    ):
                        authority.require(
                            tool_id,
                            resource_kind=resource_kind,
                            resource_ref=resource_ref,
                            effect=widened_effect,
                        )

    def test_identity_session_rejects_effect_widening(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-IDENTITY-EFFECT",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("identity.session.snapshot",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "CAPABILITY_EFFECT_NOT_ALLOWED",
        ):
            authority.require(
                "identity.session.snapshot",
                resource_kind="identity_session",
                resource_ref="local:identity:current",
                effect="network_read",
            )

    def test_audio_device_read_rejects_effect_widening(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-AUDIO-EFFECT",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("audio.devices.snapshot",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "CAPABILITY_EFFECT_NOT_ALLOWED",
        ):
            authority.require(
                "audio.devices.snapshot",
                resource_kind="audio_devices",
                resource_ref="local:audio:devices",
                effect="network_read",
            )

    def test_local_read_tool_rejects_effect_widening(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-EFFECT",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("windows.group_policy.result",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "CAPABILITY_EFFECT_NOT_ALLOWED",
        ):
            authority.require(
                "windows.group_policy.result",
                resource_kind="group_policy",
                resource_ref="local:gpresult:user",
                effect="execute",
            )

    def test_internal_reachability_requires_explicit_tool_and_internal_network_scope(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-PING",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("network.reachability.internal",),
        )
        self.assertEqual(contract.network_scope, "internal_only")
        authority = TaskCapabilityAuthority.from_contract(contract)
        decision = authority.require(
            "network.reachability.internal",
            resource_kind="network_endpoint",
            resource_ref="192.168.11.10:icmp",
            effect="network_read",
        )
        self.assertTrue(decision.allowed)

    def test_internal_network_quality_requires_explicit_tool_and_internal_network_scope(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-QUALITY",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("network.quality.internal",),
        )
        self.assertEqual(contract.allowed_tools, ("network.quality.internal",))
        self.assertEqual(contract.network_scope, "internal_only")
        authority = TaskCapabilityAuthority.from_contract(contract)
        decision = authority.require(
            "network.quality.internal",
            resource_kind="network_endpoint",
            resource_ref="192.168.11.10:icmp-quality",
            effect="network_read",
        )
        self.assertTrue(decision.allowed)

    def test_internal_reachability_rejects_wrong_resource_kind(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-PING-KIND",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("network.reachability.internal",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "RESOURCE_KIND_NOT_AUTHORIZED",
        ):
            authority.require(
                "network.reachability.internal",
                resource_kind="url",
                resource_ref="192.168.11.10:icmp",
                effect="network_read",
            )

    def test_internal_network_quality_rejects_wrong_resource_kind(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-QUALITY-KIND",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("network.quality.internal",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "RESOURCE_KIND_NOT_AUTHORIZED",
        ):
            authority.require(
                "network.quality.internal",
                resource_kind="url",
                resource_ref="192.168.11.10:icmp-quality",
                effect="network_read",
            )

    def test_internal_network_quality_rejects_effect_substitution(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-QUALITY-EFFECT",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("network.quality.internal",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "CAPABILITY_EFFECT_NOT_ALLOWED",
        ):
            authority.require(
                "network.quality.internal",
                resource_kind="network_endpoint",
                resource_ref="192.168.11.10:icmp-quality",
                effect="read",
            )

    def test_public_task_cannot_smuggle_internal_reachability(self) -> None:
        with self.assertRaisesRegex(
            TaskContractError,
            "Internal diagnostic network tools require network_scope=internal_only",
        ):
            TaskContractCompiler().compile(
                task_id="TASK-DIAG-PUBLIC-PING",
                task_type="analysis",
                sensitivity="public",
                allowed_tools=("network.reachability.internal",),
            )

    def test_public_task_cannot_smuggle_internal_network_quality(self) -> None:
        with self.assertRaisesRegex(
            TaskContractError,
            "Internal diagnostic network tools require network_scope=internal_only",
        ):
            TaskContractCompiler().compile(
                task_id="TASK-DIAG-PUBLIC-QUALITY",
                task_type="analysis",
                sensitivity="public",
                allowed_tools=("network.quality.internal",),
            )

    def test_child_authority_cannot_add_diagnostic_tool_not_in_parent(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DIAG-PARENT",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("system.platform.identify",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "CHILD_CAPABILITY_ESCALATION",
        ):
            authority.derive_child(
                task_id="TASK-DIAG-CHILD",
                allowed_tools=(
                    "system.platform.identify",
                    "system.resource.snapshot",
                ),
            )

    def test_runtime_diagnostic_registry_is_fully_known_to_task_contract_vocabulary(self) -> None:
        runtime_ids = {item.id for item in runtime_tool_metadata()}
        self.assertTrue(runtime_ids)
        self.assertTrue(runtime_ids.issubset(TOOLS))


if __name__ == "__main__":
    unittest.main()
