from __future__ import annotations

import unittest
from types import SimpleNamespace

from three_agent.micro_tool_registry import (
    EscalationContext,
    MicroToolRegistry,
    RegistryPolicyError,
    RegistryValidationError,
    ToolMetadata,
    ToolPreset,
    ToolSelectionRequest,
    decide_escalation,
)


def _tool(
    tool_id: str,
    *,
    keywords: tuple[str, ...],
    cost: str = "C1",
    risk: str = "read_only",
    platform: str = "windows",
    network_access: str = "none",
    effect: str = "read",
    requires_admin: bool = False,
    sensitive_outputs: bool = False,
    implemented: bool = True,
) -> ToolMetadata:
    return ToolMetadata(
        id=tool_id,
        platform=platform,
        category="event",
        keywords=keywords,
        cost=cost,
        risk=risk,
        requires_admin=requires_admin,
        network_access=network_access,
        sensitive_outputs=sensitive_outputs,
        effect=effect,
        implemented=implemented,
    )


class MicroToolRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tools = (
            _tool("windows.event.kernel_power", keywords=("restart", "unexpected reboot", "kernel power"), cost="C1"),
            _tool("windows.event.bugcheck", keywords=("restart", "bsod", "bugcheck"), cost="C1"),
            _tool("windows.event.system", keywords=("restart", "system event"), cost="C1"),
            _tool("windows.crashdump.inventory", keywords=("restart", "crash", "dump"), cost="C2"),
            _tool("windows.crashdump.analyze", keywords=("restart", "crash", "dump", "bsod"), cost="C5", requires_admin=True, sensitive_outputs=True),
            _tool("windows.printer.queue", keywords=("printer", "print queue"), cost="C0"),
        )
        self.registry = MicroToolRegistry(
            self.tools,
            presets=(
                ToolPreset(
                    id="windows.restart.full",
                    tool_ids=(
                        "windows.event.kernel_power",
                        "windows.event.bugcheck",
                        "windows.event.system",
                        "windows.crashdump.inventory",
                        "windows.crashdump.analyze",
                    ),
                ),
            ),
        )

    def test_cheapest_relevant_tool_is_preferred_deterministically(self) -> None:
        result = self.registry.select(
            ToolSelectionRequest(
                query="Windows restart unexpectedly after a crash dump",
                platform="Windows",
                mode="targeted",
                max_tools=4,
            )
        )
        self.assertEqual(
            result.selected_ids(),
            (
                "windows.event.bugcheck",
                "windows.event.kernel_power",
                "windows.event.system",
                "windows.crashdump.inventory",
            ),
        )

    def test_irrelevant_tool_is_rejected(self) -> None:
        result = self.registry.select(
            ToolSelectionRequest(query="Windows restart unexpectedly", platform="Windows")
        )
        rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
        self.assertIn(("windows.printer.queue", "IRRELEVANT"), rejected)

    def test_c5_is_not_selected_during_initial_quick_diagnosis(self) -> None:
        result = self.registry.select(
            ToolSelectionRequest(
                query="restart crash dump bsod",
                platform="Windows",
                mode="quick",
                max_tools=6,
            )
        )
        self.assertNotIn("windows.crashdump.analyze", result.selected_ids())
        rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
        self.assertIn(("windows.crashdump.analyze", "COST_ABOVE_MODE"), rejected)

    def test_full_workflow_is_not_implicitly_selected(self) -> None:
        quick = self.registry.select(
            ToolSelectionRequest(query="restart", platform="Windows", mode="quick")
        )
        self.assertNotIn("windows.crashdump.analyze", quick.selected_ids())
        with self.assertRaisesRegex(RegistryPolicyError, "FULL_PRESET_REQUIRES_EXPLICIT_AUTHORIZATION"):
            self.registry.expand_preset("windows.restart.full", full_authorized=False)

    def test_explicit_full_request_permits_full_preset(self) -> None:
        expanded = self.registry.expand_preset("windows.restart.full", full_authorized=True)
        self.assertEqual(
            tuple(tool.id for tool in expanded),
            (
                "windows.event.kernel_power",
                "windows.event.bugcheck",
                "windows.event.system",
                "windows.crashdump.inventory",
                "windows.crashdump.analyze",
            ),
        )

    def test_full_mode_requires_explicit_or_evidence_driven_authorization(self) -> None:
        with self.assertRaisesRegex(
            RegistryPolicyError,
            "FULL_MODE_REQUIRES_EXPLICIT_OR_EVIDENCE_DRIVEN_AUTHORIZATION",
        ):
            self.registry.select(
                ToolSelectionRequest(query="restart", platform="Windows", mode="full")
            )

    def test_authority_restriction_blocks_unauthorized_tool(self) -> None:
        authority = SimpleNamespace(
            allowed_tools=("windows.event.kernel_power",),
            network_scope="deny",
        )
        result = self.registry.select(
            ToolSelectionRequest(
                query="restart bugcheck",
                platform="Windows",
                authority=authority,
                max_tools=5,
            )
        )
        self.assertEqual(result.selected_ids(), ("windows.event.kernel_power",))
        rejected = {(item.tool_id, item.reason_code) for item in result.rejected}
        self.assertIn(("windows.event.bugcheck", "AUTHORITY_TOOL_NOT_ALLOWED"), rejected)

    def test_registry_malformed_metadata_fails_closed(self) -> None:
        with self.assertRaises(RegistryValidationError):
            MicroToolRegistry.from_metadata(
                (
                    {
                        "id": "windows.event.system",
                        "platform": "windows",
                        "category": "event",
                        "keywords": ["restart"],
                        "risk": "read_only",
                        "requires_admin": False,
                        "network_access": "none",
                        "sensitive_outputs": False,
                        "effect": "read",
                    },
                )
            )

    def test_unknown_cost_and_risk_classes_fail_closed(self) -> None:
        with self.assertRaisesRegex(RegistryValidationError, "unknown cost class"):
            _tool("windows.event.badcost", keywords=("restart",), cost="C9").validate()
        with self.assertRaisesRegex(RegistryValidationError, "unknown risk class"):
            _tool("windows.event.badrisk", keywords=("restart",), risk="mystery").validate()

    def test_result_cannot_grant_remediation_authority(self) -> None:
        registry = MicroToolRegistry(
            (
                _tool(
                    "windows.service.restart",
                    keywords=("restart service",),
                    cost="C1",
                    risk="write",
                    effect="write",
                ),
            )
        )
        result = registry.select(
            ToolSelectionRequest(query="restart service", platform="Windows")
        )
        self.assertEqual(result.selected_ids(), ())
        self.assertEqual(result.rejected[0].reason_code, "NON_DIAGNOSTIC_EFFECT")

    def test_no_hidden_external_egress(self) -> None:
        registry = MicroToolRegistry(
            (
                _tool(
                    "network.vendor.lookup",
                    keywords=("vendor",),
                    platform="any",
                    network_access="allowlisted_egress",
                    effect="network_read",
                ),
            )
        )
        result = registry.select(ToolSelectionRequest(query="vendor", platform="Windows"))
        self.assertEqual(result.selected_ids(), ())
        self.assertEqual(result.rejected[0].reason_code, "EXTERNAL_EGRESS_DISABLED")

    def test_internal_network_scope_is_prefiltered_by_authority(self) -> None:
        registry = MicroToolRegistry(
            (
                _tool(
                    "network.ssh.probe",
                    keywords=("ssh",),
                    platform="any",
                    network_access="internal_only",
                    effect="network_read",
                ),
            )
        )
        denied = SimpleNamespace(
            allowed_tools=("network.ssh.probe",),
            network_scope="deny",
        )
        result = registry.select(
            ToolSelectionRequest(query="ssh", platform="Linux", authority=denied)
        )
        self.assertEqual(result.selected_ids(), ())
        self.assertEqual(result.rejected[0].reason_code, "AUTHORITY_NETWORK_SCOPE_NOT_ALLOWED")

    def test_deterministic_ordering_is_independent_of_input_order(self) -> None:
        forward = MicroToolRegistry(self.tools).select(
            ToolSelectionRequest(query="restart crash dump", platform="Windows", mode="targeted", max_tools=6)
        )
        reverse = MicroToolRegistry(reversed(self.tools)).select(
            ToolSelectionRequest(query="restart crash dump", platform="Windows", mode="targeted", max_tools=6)
        )
        self.assertEqual(forward.selected_ids(), reverse.selected_ids())
        self.assertEqual(forward.rejected, reverse.rejected)

    def test_stop_logic_is_explicit(self) -> None:
        sufficient = decide_escalation(
            EscalationContext(
                evidence_sufficient=True,
                uncertainty_reduction_expected=True,
                authority_available=True,
                next_cost="C1",
                max_justified_cost="C2",
            )
        )
        self.assertTrue(sufficient.stop)
        self.assertEqual(sufficient.reason_code, "EVIDENCE_SUFFICIENT")

        no_value = decide_escalation(
            EscalationContext(
                evidence_sufficient=False,
                uncertainty_reduction_expected=False,
                authority_available=True,
                next_cost="C1",
                max_justified_cost="C2",
            )
        )
        self.assertTrue(no_value.stop)
        self.assertEqual(no_value.reason_code, "NO_MATERIAL_UNCERTAINTY_REDUCTION")

        no_authority = decide_escalation(
            EscalationContext(
                evidence_sufficient=False,
                uncertainty_reduction_expected=True,
                authority_available=False,
                next_cost="C1",
                max_justified_cost="C2",
            )
        )
        self.assertTrue(no_authority.stop)
        self.assertEqual(no_authority.reason_code, "AUTHORITY_UNAVAILABLE")

        costly = decide_escalation(
            EscalationContext(
                evidence_sufficient=False,
                uncertainty_reduction_expected=True,
                authority_available=True,
                next_cost="C5",
                max_justified_cost="C2",
            )
        )
        self.assertTrue(costly.stop)
        self.assertEqual(costly.action, "human_decision")
        self.assertEqual(costly.reason_code, "COST_EXCEEDS_DIAGNOSTIC_VALUE")

    def test_office_it_v0_1_metadata_can_load_without_implementation_execution(self) -> None:
        from three_agent.office_it_tools import iter_specs

        registry = MicroToolRegistry.from_specs(iter_specs())
        metadata = registry.metadata_view()
        self.assertEqual(len(metadata), 9)
        self.assertTrue(all("keywords" in item for item in metadata))
        self.assertTrue(all("fixed_port" not in item for item in metadata))
        result = registry.select(
            ToolSelectionRequest(query="SSH server unreachable", platform="Windows")
        )
        self.assertEqual(result.selected_ids(), ("network.ssh.probe",))


if __name__ == "__main__":
    unittest.main()
