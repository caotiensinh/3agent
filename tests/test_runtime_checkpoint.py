import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.execution_observation import ExecutionObservationBuilder
from three_agent.execution_plan import ExecutionPlanBuilder
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.runtime_checkpoint import (
    RuntimeCheckpointBuilder,
    RuntimeCheckpointCodec,
    RuntimeCheckpointError,
    RuntimeRecovery,
)
from three_agent.task_context import TaskContextBuilder
from three_agent.task_contract import TaskContractCompiler


def sample_workflow():
    return {
        "title": "Runtime recovery",
        "objective": "Recover canonical nodes without replaying ambiguous work.",
        "trigger": "manual",
        "risk_level": "medium",
        "data_class": "internal",
        "nodes": [
            {
                "id": "start",
                "label": "Start",
                "kind": "input",
                "action": "input",
                "depends_on": [],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "collect",
                "label": "Collect evidence",
                "kind": "agent",
                "action": "research",
                "depends_on": ["start"],
                "condition": "",
                "approval_required": False,
            },
            {
                "id": "approve",
                "label": "Human approval",
                "kind": "approval",
                "action": "human_approval",
                "depends_on": ["collect"],
                "condition": "evidence accepted",
                "approval_required": True,
            },
            {
                "id": "done",
                "label": "Return result",
                "kind": "output",
                "action": "output",
                "depends_on": ["approve"],
                "condition": "",
                "approval_required": False,
            },
        ],
        "outputs": ["Bounded result"],
        "warnings": [],
    }


class RuntimeCheckpointTests(unittest.TestCase):
    @staticmethod
    def _runtime():
        task_id = "TASK-RECOVERY-1"
        contract = TaskContractCompiler().compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level="medium",
            allowed_sources=("repo", "evidence"),
            allowed_tools=("search_docs", "read_file"),
            write_scope="none",
        )
        acceptance = AcceptanceContract(
            task_id=task_id,
            criteria=(
                AcceptanceCriterion(
                    criterion_id="result",
                    statement="Produce deterministic checkpoint recovery",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Recover canonical runtime state.",
            task_contract=contract,
            acceptance_contract=acceptance,
        )
        context = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-RECOVERY-1",
            trace_id="TRACE-RECOVERY-1",
            actor_id="ACTOR-RECOVERY-1",
            purpose="runtime checkpoint recovery",
            project_id="PROJECT-1",
            created_at=datetime(2026, 9, 8, 1, 0, tzinfo=timezone.utc),
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        plan = ExecutionPlanBuilder.build(
            task_context=context,
            parent_authority=authority,
            workflow_contract=sample_workflow(),
        )
        return context, authority, plan

    @staticmethod
    def _observation(plan, authority, node_id, status, second, *, error_class=None):
        return ExecutionObservationBuilder.build(
            plan=plan,
            node_id=node_id,
            parent_authority=authority,
            status=status,
            started_at=f"2026-09-08T01:00:{second:02d}Z",
            finished_at=f"2026-09-08T01:00:{second:02d}Z",
            error_class=error_class,
        )

    def _checkpoint(self, observations=(), approved_node_ids=()):
        context, authority, plan = self._runtime()
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=observations,
            approved_node_ids=approved_node_ids,
            captured_at=datetime(2026, 9, 8, 1, 5, tzinfo=timezone.utc),
        )
        return context, authority, plan, checkpoint

    def test_checkpoint_is_deterministic_and_codec_round_trips(self):
        context, authority, plan = self._runtime()
        start = self._observation(plan, authority, "start", "SUCCEEDED", 0)
        first = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start,),
            captured_at=datetime(2026, 9, 8, 1, 5, tzinfo=timezone.utc),
        )
        second = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start,),
            captured_at=datetime(2026, 9, 8, 1, 5, tzinfo=timezone.utc),
        )
        self.assertEqual(first, second)
        payload = RuntimeCheckpointCodec.dumps(first)
        restored = RuntimeCheckpointCodec.loads(payload)
        self.assertEqual(restored, first)
        self.assertEqual(restored.fingerprint, first.fingerprint)

    def test_codec_rejects_tampering(self):
        context, authority, plan = self._runtime()
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            captured_at=datetime(2026, 9, 8, 1, 5, tzinfo=timezone.utc),
        )
        envelope = json.loads(RuntimeCheckpointCodec.dumps(checkpoint))
        envelope["checkpoint"]["plan_fingerprint"] = "sha256:" + "0" * 64
        tampered = json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        with self.assertRaises(RuntimeCheckpointError):
            RuntimeCheckpointCodec.loads(tampered)

    def test_recovery_revalidates_exact_runtime_and_never_executes(self):
        context, authority, plan = self._runtime()
        start = self._observation(plan, authority, "start", "SUCCEEDED", 0)
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start,),
            captured_at=datetime(2026, 9, 8, 1, 5, tzinfo=timezone.utc),
        )
        recovery = RuntimeRecovery.evaluate(
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start,),
        )
        self.assertEqual(recovery.status, "RECOVERABLE")
        self.assertEqual(recovery.scheduling_decision.ready_node_ids, ("collect",))
        self.assertEqual(
            recovery.reason_code,
            "CHECKPOINT_REVALIDATED_NO_EXECUTION_PERFORMED",
        )

    def test_partial_observation_requires_manual_reconciliation(self):
        context, authority, plan = self._runtime()
        partial = self._observation(plan, authority, "start", "PARTIAL", 0)
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(partial,),
            captured_at=datetime(2026, 9, 8, 1, 5, tzinfo=timezone.utc),
        )
        recovery = RuntimeRecovery.evaluate(
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(partial,),
        )
        self.assertEqual(recovery.status, "MANUAL_RECONCILIATION")
        self.assertEqual(recovery.manual_node_ids, ("start",))
        self.assertEqual(recovery.scheduling_decision.ready_node_ids, ())

    def test_changed_context_plan_authority_or_observations_fail_closed(self):
        context, authority, plan = self._runtime()
        start = self._observation(plan, authority, "start", "SUCCEEDED", 0)
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start,),
            captured_at=datetime(2026, 9, 8, 1, 5, tzinfo=timezone.utc),
        )
        changed_context = context.derive(evidence_refs=("evidence:new",))
        with self.assertRaisesRegex(
            RuntimeCheckpointError,
            "RECOVERY_TASK_CONTEXT_FINGERPRINT_MISMATCH",
        ):
            RuntimeRecovery.evaluate(
                checkpoint=checkpoint,
                task_context=changed_context,
                plan=plan,
                parent_authority=authority,
                observations=(start,),
            )

        with self.assertRaisesRegex(
            RuntimeCheckpointError,
            "RECOVERY_OBSERVATION_SET_MISMATCH",
        ):
            RuntimeRecovery.evaluate(
                checkpoint=checkpoint,
                task_context=context,
                plan=plan,
                parent_authority=authority,
                observations=(),
            )

        wrong_checkpoint = replace(
            checkpoint,
            parent_authority_fingerprint="sha256:" + "0" * 64,
        )
        with self.assertRaises(RuntimeCheckpointError):
            RuntimeRecovery.evaluate(
                checkpoint=wrong_checkpoint,
                task_context=context,
                plan=plan,
                parent_authority=authority,
                observations=(start,),
            )

    def test_approval_state_is_checkpoint_bound(self):
        context, authority, plan = self._runtime()
        start = self._observation(plan, authority, "start", "SUCCEEDED", 0)
        collect = self._observation(plan, authority, "collect", "SUCCEEDED", 1)
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start, collect),
            approved_node_ids=("approve",),
            captured_at=datetime(2026, 9, 8, 1, 5, tzinfo=timezone.utc),
        )
        recovery = RuntimeRecovery.evaluate(
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(collect, start),
        )
        self.assertEqual(recovery.status, "RECOVERABLE")
        self.assertEqual(recovery.scheduling_decision.ready_node_ids, ("approve",))
        self.assertEqual(checkpoint.approved_node_ids, ("approve",))

    def test_complete_checkpoint_stays_complete(self):
        context, authority, plan = self._runtime()
        observations = tuple(
            self._observation(plan, authority, node_id, "SUCCEEDED", index)
            for index, node_id in enumerate(("start", "collect", "approve", "done"))
        )
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=observations,
            approved_node_ids=("approve",),
            captured_at=datetime(2026, 9, 8, 1, 5, tzinfo=timezone.utc),
        )
        recovery = RuntimeRecovery.evaluate(
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=observations,
        )
        self.assertEqual(recovery.status, "COMPLETE")
        self.assertEqual(recovery.scheduling_decision.status, "COMPLETE")


if __name__ == "__main__":
    unittest.main()
