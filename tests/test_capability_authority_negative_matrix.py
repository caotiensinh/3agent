from dataclasses import FrozenInstanceError
import unittest

from three_agent.capability_authority import (
    CapabilityAuthorityDenied,
    CapabilityDecision,
    TaskCapabilityAuthority,
)
from three_agent.diagnostics.common_tools import common_micro_tool_registry
from three_agent.inference_scope import inference_scope
from three_agent.task_contract import TaskContractCompiler


class CapabilityAuthorityNegativeMatrixTests(unittest.TestCase):
    @staticmethod
    def _authority(task_id: str = "TASK-A") -> TaskCapabilityAuthority:
        contract = TaskContractCompiler().compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("system.platform.identify",),
        )
        return TaskCapabilityAuthority.from_contract(contract)

    def test_unknown_tool_id_fails_closed(self):
        decision = self._authority().authorize(
            "diagnostic.ghost",
            resource_kind="system_inventory",
            resource_ref="local:platform",
            effect="read",
        )
        self.assertFalse(decision.allowed)
        self.assertEqual(decision.reason_code, "CAPABILITY_UNKNOWN")

    def test_known_tool_wrong_effect_fails_before_authorization(self):
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "CAPABILITY_EFFECT_NOT_ALLOWED",
        ):
            self._authority().require(
                "system.platform.identify",
                resource_kind="system_inventory",
                resource_ref="local:platform",
                effect="execute",
            )

    def test_known_tool_wrong_resource_kind_or_ref_fails_closed(self):
        authority = self._authority()
        bad_resources = (
            ("process_inventory", "local:platform"),
            ("system_inventory", "local:processes:top"),
        )
        for resource_kind, resource_ref in bad_resources:
            with self.subTest(resource_kind=resource_kind, resource_ref=resource_ref):
                with self.assertRaisesRegex(
                    CapabilityAuthorityDenied,
                    "RESOURCE_(KIND|REF)_NOT_AUTHORIZED",
                ):
                    authority.require(
                        "system.platform.identify",
                        resource_kind=resource_kind,
                        resource_ref=resource_ref,
                        effect="read",
                    )

    def test_wrong_task_lineage_cannot_bind_authority_to_scope(self):
        authority = self._authority("TASK-A")
        with self.assertRaisesRegex(
            ValueError,
            "capability authority task_id does not match inference scope",
        ):
            with inference_scope(
                "TASK-B",
                agent_id="diagnostic",
                stage="collect",
                capability_authority=authority,
            ):
                self.fail("wrong-lineage authority must fail before scope entry")

    def test_registry_membership_does_not_grant_task_authority(self):
        registry = common_micro_tool_registry()
        descriptor = registry.get("system.platform.identify")
        self.assertEqual(descriptor.id, "system.platform.identify")

        contract = TaskContractCompiler().compile(
            task_id="TASK-NO-DIAGNOSTIC",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=("read_file",),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "CAPABILITY_NOT_ALLOWED",
        ):
            authority.require(
                descriptor.id,
                resource_kind="system_inventory",
                resource_ref="local:platform",
                effect=descriptor.effect,
            )

    def test_forged_or_mutated_decision_record_never_grants_authority(self):
        authority = TaskCapabilityAuthority.from_contract(
            TaskContractCompiler().compile(
                task_id="TASK-DENY",
                task_type="analysis",
                sensitivity="internal",
                allowed_tools=("read_file",),
            )
        )
        forged = CapabilityDecision(
            task_id="TASK-DENY",
            capability="system.platform.identify",
            resource_kind="system_inventory",
            resource_ref="local:platform",
            effect="read",
            allowed=True,
            reason_code="CAPABILITY_AUTHORIZED",
            authority_fingerprint=authority.fingerprint,
        )
        self.assertTrue(forged.allowed)

        with self.assertRaises(FrozenInstanceError):
            forged.allowed = False  # type: ignore[misc]

        with self.assertRaisesRegex(
            CapabilityAuthorityDenied,
            "CAPABILITY_NOT_ALLOWED",
        ):
            authority.require(
                forged.capability,
                resource_kind=forged.resource_kind,
                resource_ref=forged.resource_ref,
                effect=forged.effect,
            )


if __name__ == "__main__":
    unittest.main()
