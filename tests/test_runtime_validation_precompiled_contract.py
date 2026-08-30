from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.presentation_schemas import PRESENTATION_PLAN_SCHEMA_V1
from three_agent.runtime_validation import (
    MAX_PRECOMPILED_ANALYSIS_WALL_TIME_MS,
    RuntimeValidationError,
    RuntimeValidatorBridge,
)
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

    def _canonical(self, task_id):
        return self.compiler.compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
            public_web=False,
            output_schema=PRESENTATION_PLAN_SCHEMA_V1,
        )

    def test_only_bounded_wall_time_extension_is_accepted(self):
        task = self._task()
        base = self._canonical(task.task_id)
        contract = replace(
            base,
            execution_budget=ExecutionBudget(
                max_steps=base.execution_budget.max_steps,
                max_tool_calls=base.execution_budget.max_tool_calls,
                max_retries=base.execution_budget.max_retries,
                max_escalations=base.execution_budget.max_escalations,
                max_wall_time_ms=MAX_PRECOMPILED_ANALYSIS_WALL_TIME_MS,
            ),
            policy_reason_codes=base.policy_reason_codes + ("WORKFLOW_V3_CHECKPOINT_24H_BOUND",),
        ).validate()
        attempt = self.bridge.begin(task.task_id, contract=contract)
        self.assertEqual(
            attempt.execution_budget.max_wall_time_ms,
            MAX_PRECOMPILED_ANALYSIS_WALL_TIME_MS,
        )
        self.assertEqual(
            self.store.task_contract_record(task.task_id)["contract_sha256"],
            attempt.contract_sha256,
        )

    def test_task_sensitivity_risk_and_schema_mismatches_are_denied(self):
        task = self._task()
        other = self.store.create_task("Other", "other")
        with self.assertRaisesRegex(RuntimeValidationError, "TASK_MISMATCH"):
            self.bridge.begin(other.task_id, contract=self._canonical(task.task_id))

        public = self.compiler.compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="public",
            risk_level="low",
            output_schema=PRESENTATION_PLAN_SCHEMA_V1,
        )
        with self.assertRaisesRegex(RuntimeValidationError, "AUTHORITY_EXPANSION"):
            self.bridge.begin(task.task_id, contract=public)

        medium = self.compiler.compile(
            task_id=task.task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="medium",
            output_schema=PRESENTATION_PLAN_SCHEMA_V1,
        )
        with self.assertRaisesRegex(RuntimeValidationError, "AUTHORITY_EXPANSION"):
            self.bridge.begin(task.task_id, contract=medium)

        wrong_schema = replace(self._canonical(task.task_id), output_schema={"type": "object"}).validate()
        with self.assertRaisesRegex(RuntimeValidationError, "AUTHORITY_EXPANSION"):
            self.bridge.begin(task.task_id, contract=wrong_schema)

    def test_tools_model_and_non_wall_budget_expansion_are_denied(self):
        task = self._task()
        base = self._canonical(task.task_id)

        extra_tool = replace(
            base,
            allowed_tools=tuple(base.allowed_tools) + ("calculator",),
        ).validate()
        with self.assertRaisesRegex(RuntimeValidationError, "AUTHORITY_EXPANSION"):
            self.bridge.begin(task.task_id, contract=extra_tool)

        stronger_model = replace(
            base,
            model_policy=replace(base.model_policy, initial_tier="strong", max_tier="strong"),
        ).validate()
        with self.assertRaisesRegex(RuntimeValidationError, "AUTHORITY_EXPANSION"):
            self.bridge.begin(task.task_id, contract=stronger_model)

        more_steps = replace(
            base,
            execution_budget=replace(
                base.execution_budget,
                max_steps=base.execution_budget.max_steps + 1,
            ),
        ).validate()
        with self.assertRaisesRegex(RuntimeValidationError, "EXECUTION_AUTHORITY"):
            self.bridge.begin(task.task_id, contract=more_steps)

    def test_wall_time_cannot_shrink_or_exceed_24h_cap(self):
        task = self._task()
        base = self._canonical(task.task_id)
        shorter = replace(
            base,
            execution_budget=replace(
                base.execution_budget,
                max_wall_time_ms=base.execution_budget.max_wall_time_ms - 1,
            ),
        ).validate()
        with self.assertRaisesRegex(RuntimeValidationError, "WALL_TIME"):
            self.bridge.begin(task.task_id, contract=shorter)

        too_long = replace(
            base,
            execution_budget=replace(
                base.execution_budget,
                max_wall_time_ms=MAX_PRECOMPILED_ANALYSIS_WALL_TIME_MS + 1,
            ),
        ).validate()
        with self.assertRaisesRegex(RuntimeValidationError, "WALL_TIME"):
            self.bridge.begin(task.task_id, contract=too_long)


if __name__ == "__main__":
    unittest.main()
