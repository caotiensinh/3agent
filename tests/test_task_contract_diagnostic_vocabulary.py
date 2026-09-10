from __future__ import annotations

import unittest

from three_agent.diagnostics.runtime_registry import runtime_tool_metadata
from three_agent.task_contract import (
    DIAGNOSTIC_INTERNAL_NETWORK_TOOLS,
    DIAGNOSTIC_LOCAL_READ_TOOLS,
    TOOLS,
    TaskContractCompiler,
    TaskContractError,
)


class TaskContractDiagnosticVocabularyTests(unittest.TestCase):
    def test_runtime_diagnostic_ids_are_representable_by_canonical_tools(self) -> None:
        runtime_ids = {item.id for item in runtime_tool_metadata()}

        self.assertTrue(runtime_ids)
        self.assertTrue(runtime_ids.issubset(TOOLS))
        self.assertTrue(DIAGNOSTIC_LOCAL_READ_TOOLS.issubset(TOOLS))
        self.assertTrue(DIAGNOSTIC_INTERNAL_NETWORK_TOOLS.issubset(TOOLS))
        self.assertTrue(
            DIAGNOSTIC_LOCAL_READ_TOOLS.isdisjoint(DIAGNOSTIC_INTERNAL_NETWORK_TOOLS)
        )

    def test_each_runtime_diagnostic_tool_compiles_through_canonical_contract(self) -> None:
        compiler = TaskContractCompiler()

        for metadata in runtime_tool_metadata():
            with self.subTest(tool_id=metadata.id):
                contract = compiler.compile(
                    task_id=f"L12-{metadata.id}",
                    task_type="analysis",
                    sensitivity="internal",
                    allowed_tools=(metadata.id,),
                )
                self.assertEqual(contract.allowed_tools, (metadata.id,))
                self.assertIn(metadata.id, TOOLS)

    def test_new_local_endpoint_collectors_are_canonical_local_reads(self) -> None:
        expected = {
            "process.top.snapshot",
            "hardware.usb.snapshot",
            "camera.devices.snapshot",
        }

        self.assertTrue(expected.issubset(DIAGNOSTIC_LOCAL_READ_TOOLS))
        self.assertTrue(expected.issubset(TOOLS))

    def test_duplicate_tool_ids_are_normalized_without_expanding_vocabulary(self) -> None:
        contract = TaskContractCompiler().compile(
            task_id="L12-DUPLICATE",
            task_type="analysis",
            sensitivity="internal",
            allowed_tools=(
                "system.platform.identify",
                "system.platform.identify",
                "camera.devices.snapshot",
                "camera.devices.snapshot",
            ),
        )

        self.assertEqual(
            contract.allowed_tools,
            ("system.platform.identify", "camera.devices.snapshot"),
        )

    def test_unknown_tool_id_fails_closed(self) -> None:
        with self.assertRaisesRegex(TaskContractError, "unknown tools"):
            TaskContractCompiler().compile(
                task_id="L12-UNKNOWN",
                task_type="analysis",
                sensitivity="internal",
                allowed_tools=("diagnostic.unreviewed.fixture",),
            )

    def test_internal_network_tool_cannot_be_smuggled_into_public_deny_scope(self) -> None:
        with self.assertRaisesRegex(
            TaskContractError,
            "Internal diagnostic network tools require network_scope=internal_only",
        ):
            TaskContractCompiler().compile(
                task_id="L12-NETWORK-SCOPE",
                task_type="analysis",
                sensitivity="public",
                allowed_tools=("network.quality.internal",),
            )


if __name__ == "__main__":
    unittest.main()
