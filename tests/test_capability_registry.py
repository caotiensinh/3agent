import json
import unittest
from dataclasses import replace

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.capability_registry import (
    CapabilityDescriptor,
    CapabilityRegistry,
    CapabilityRegistryError,
)
from three_agent.task_contract import TOOLS, TaskContractCompiler


class CapabilityRegistryTests(unittest.TestCase):
    def test_default_registry_covers_canonical_tool_ids_exactly(self):
        registry = CapabilityRegistry.default()
        metadata = registry.planner_metadata(
            TaskCapabilityAuthority.from_contract(
                TaskContractCompiler().compile(
                    task_id="TASK-REGISTRY-COVERAGE",
                    task_type="analysis",
                    sensitivity="internal",
                    risk_level="low",
                )
            )
        )
        self.assertTrue(registry.fingerprint.startswith("sha256:"))
        self.assertEqual(set(TOOLS), {registry.descriptor(tool).capability_id for tool in TOOLS})
        self.assertEqual(metadata["schema_version"], "workspace-capability-registry/v1")

    def test_analysis_discovers_only_authorized_read_capabilities(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-REGISTRY-ANALYSIS",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        registry = CapabilityRegistry.default()
        discovered = registry.discover_for_contract(contract)
        self.assertEqual(
            tuple(item.capability_id for item in discovered),
            ("read_file", "search_docs"),
        )

    def test_write_capabilities_are_hidden_until_write_scope_exists(self):
        registry = CapabilityRegistry.default()
        no_write = TaskContractCompiler().compile(
            task_id="TASK-REGISTRY-NOWRITE",
            task_type="code_fix",
            sensitivity="internal",
            risk_level="medium",
        )
        with_write = TaskContractCompiler().compile(
            task_id="TASK-REGISTRY-WRITE",
            task_type="code_fix",
            sensitivity="internal",
            risk_level="medium",
            write_scope=("src",),
        )
        no_write_ids = {item.capability_id for item in registry.discover_for_contract(no_write)}
        with_write_ids = {item.capability_id for item in registry.discover_for_contract(with_write)}
        self.assertNotIn("apply_patch", no_write_ids)
        self.assertNotIn("write_staging", no_write_ids)
        self.assertIn("apply_patch", with_write_ids)
        self.assertIn("write_staging", with_write_ids)

    def test_web_gateway_discovery_tracks_authority_not_ui_intent(self):
        registry = CapabilityRegistry.default()
        internal_web = TaskContractCompiler().compile(
            task_id="TASK-REGISTRY-WEB",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
            public_web=True,
        )
        ids = {item.capability_id for item in registry.discover_for_contract(internal_web)}
        self.assertIn("web_gateway", ids)

        local_only = replace(
            internal_web,
            allowed_tools=tuple(tool for tool in internal_web.allowed_tools if tool != "web_gateway"),
            network_scope="internal_only",
        ).validate()
        local_ids = {item.capability_id for item in registry.discover_for_contract(local_only)}
        self.assertNotIn("web_gateway", local_ids)

    def test_child_registry_view_is_subset_of_parent_view(self):
        registry = CapabilityRegistry.default()
        contract = TaskContractCompiler().compile(
            task_id="TASK-REGISTRY-PARENT",
            task_type="code_fix",
            sensitivity="internal",
            risk_level="medium",
            write_scope=("src",),
        )
        parent = TaskCapabilityAuthority.from_contract(contract)
        child = parent.delegate(
            task_id="TASK-REGISTRY-PARENT",
            allowed_tools=("read_file", "run_tests"),
            write_scope="none",
            network_scope="deny",
        )
        parent_ids = {item.capability_id for item in registry.discover(parent)}
        child_ids = {item.capability_id for item in registry.discover(child)}
        self.assertTrue(child_ids.issubset(parent_ids))
        self.assertEqual(child_ids, {"read_file", "run_tests"})

    def test_select_fails_closed_for_non_discoverable_capability(self):
        registry = CapabilityRegistry.default()
        authority = TaskCapabilityAuthority.from_contract(
            TaskContractCompiler().compile(
                task_id="TASK-REGISTRY-SELECT",
                task_type="analysis",
                sensitivity="internal",
                risk_level="low",
            )
        )
        with self.assertRaisesRegex(CapabilityRegistryError, "not discoverable"):
            registry.select(authority, ("apply_patch",))

    def test_planner_metadata_contains_no_endpoints_commands_or_secrets(self):
        registry = CapabilityRegistry.default()
        authority = TaskCapabilityAuthority.from_contract(
            TaskContractCompiler().compile(
                task_id="TASK-REGISTRY-META",
                task_type="analysis",
                sensitivity="public",
                risk_level="low",
                public_web=True,
            )
        )
        encoded = json.dumps(registry.planner_metadata(authority), sort_keys=True).lower()
        self.assertNotIn("http://", encoded)
        self.assertNotIn("https://", encoded)
        self.assertNotIn("api_key", encoded)
        self.assertNotIn("credential", encoded)
        self.assertNotIn("shell", encoded)

    def test_registry_rejects_effect_drift(self):
        default = CapabilityRegistry.default()
        descriptors = [default.descriptor(tool) for tool in sorted(TOOLS)]
        index = next(i for i, item in enumerate(descriptors) if item.capability_id == "read_file")
        original = descriptors[index]
        descriptors[index] = CapabilityDescriptor(
            capability_id=original.capability_id,
            effect="write",
            resource_kind=original.resource_kind,
            side_effect_class=original.side_effect_class,
            trust_tier=original.trust_tier,
            concurrency_mode=original.concurrency_mode,
            cost_class=original.cost_class,
            evidence_default=original.evidence_default,
            description=original.description,
        )
        with self.assertRaisesRegex(CapabilityRegistryError, "effect drift"):
            CapabilityRegistry(descriptors)


if __name__ == "__main__":
    unittest.main()
