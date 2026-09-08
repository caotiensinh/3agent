from __future__ import annotations

import unittest

from three_agent.capability_authority import (
    CapabilityAuthorityDenied,
    TaskCapabilityAuthority,
)
from three_agent.task_contract import DIAGNOSTIC_LOCAL_READ_TOOLS, TOOLS, TaskContractCompiler


DOMAIN_COMPLETION_CASES = (
    ("storage.io.snapshot", "storage_io", "local:storage:io"),
    ("windows.print.driver.snapshot", "printer_drivers", "local:printer:drivers"),
    ("windows.boot.snapshot", "boot_state", "local:windows:boot"),
    ("windows.update.history", "windows_update_history", "local:windows:update-history"),
)


class DomainCompletionCapabilityIntegrationTests(unittest.TestCase):
    def test_new_tools_are_canonical_local_reads(self) -> None:
        expected = {tool_id for tool_id, _, _ in DOMAIN_COMPLETION_CASES}
        self.assertTrue(expected.issubset(DIAGNOSTIC_LOCAL_READ_TOOLS))
        self.assertTrue(expected.issubset(TOOLS))

    def test_default_analysis_does_not_auto_grant_new_tools(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DOMAIN-COMPLETION-DEFAULT",
            task_type="analysis",
            sensitivity="internal",
        )
        for tool_id, _, _ in DOMAIN_COMPLETION_CASES:
            with self.subTest(tool_id=tool_id):
                self.assertNotIn(tool_id, contract.allowed_tools)

    def test_explicit_grant_authorizes_only_read_effect(self) -> None:
        for tool_id, resource_kind, resource_ref in DOMAIN_COMPLETION_CASES:
            with self.subTest(tool_id=tool_id):
                contract = TaskContractCompiler().compile(
                    task_id=f"TASK-DOMAIN-COMPLETION-{tool_id}",
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
                self.assertEqual(decision.reason_code, "CAPABILITY_AUTHORIZED")

    def test_effect_widening_is_rejected(self) -> None:
        for tool_id, resource_kind, resource_ref in DOMAIN_COMPLETION_CASES:
            with self.subTest(tool_id=tool_id):
                contract = TaskContractCompiler().compile(
                    task_id=f"TASK-DOMAIN-COMPLETION-EFFECT-{tool_id}",
                    task_type="analysis",
                    sensitivity="internal",
                    allowed_tools=(tool_id,),
                )
                authority = TaskCapabilityAuthority.from_contract(contract)
                for widened_effect in ("network_read", "execute", "write"):
                    with self.subTest(effect=widened_effect):
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

    def test_child_authority_cannot_add_new_tool_not_in_parent(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="TASK-DOMAIN-COMPLETION-PARENT",
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
                task_id="TASK-DOMAIN-COMPLETION-CHILD",
                allowed_tools=("system.platform.identify", "storage.io.snapshot"),
            )


if __name__ == "__main__":
    unittest.main()
