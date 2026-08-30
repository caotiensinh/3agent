from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.runtime_validation import RuntimeValidationError, RuntimeValidatorBridge
from three_agent.store import TaskStore
from three_agent.task_contract import ExecutionBudget, TaskContractCompiler


class RuntimeValidationPrecompiledContractTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = TaskStore(root / "workspace.db")
        self.store.initialize()
        self.artifacts = ArtifactManager(root / "artifacts")
        self.bridge = RuntimeValidatorBridge(
            self.store,
            self.artifacts,
            confidentiality_mode="internal",
            public_web=False,
        )
        self.compiler = TaskContractCompiler()

    def tearDown(self):
        self.tmp.cleanup()

    def _task(self):
        return self.store.create_task("V3", "checkpoint test")

    def test_same_authority_contract_may_extend_only_bounded_wall_time(self):
        task = self._task()
        base = self.compiler.compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
            output_schema={"type": "object"},
        )
        contract = replace(
            base,
            execution_budget=ExecutionBudget(
                max_steps=base.execution_budget.max_steps,
                max_tool_calls=base.execution_budget.max_tool_calls,
                max_retries=base.execution_budget.max_retries,
                max_escalations=base.execution_budget.max_escalations,
                max_wall_time_ms=86_400_000,
            ),
        ).validate()
        attempt = self.bridge.begin(task.task_id, contract=contract)
        self.assertEqual(attempt.execution_budget.max_wall_time_ms, 86_400_000)
        self.assertEqual(
            self.store.task_contract_record(task.task_id)["contract_sha256"],
            attempt.contract_sha256,
        )

    def test_precompiled_contract_cannot_change_task_or_sensitivity_or_risk(self):
        task = self._task()
        other = self.store.create_task("Other", "other")
        wrong_task = self.compiler.compile(
            task_id=other.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
        )
        with self.assertRaisesRegex(RuntimeValidationError, "TASK_MISMATCH"):
            self.bridge.begin(task.task_id, contract=wrong_task)

        public = self.compiler.compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="public",
            risk_level="low",
        )
        with self.assertRaisesRegex(RuntimeValidationError, "SENSITIVITY"):
            self.bridge.begin(task.task_id, contract=public)

        medium = self.compiler.compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="medium",
        )
        with self.assertRaisesRegex(RuntimeValidationError, "AUTHORITY_EXPANSION"):
            self.bridge.begin(task.task_id, contract=medium)


if __name__ == "__main__":
    unittest.main()
