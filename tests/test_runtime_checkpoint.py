import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.execution_observation import ExecutionObservationBuilder
from three_agent.execution_plan import ExecutionPlanBuilder
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.runtime_checkpoint import (
    CheckpointObservationRef,
    RuntimeCheckpointBuilder,
    RuntimeCheckpointError,
    RuntimeCheckpointRecovery,
    RuntimeCheckpointStore,
)
from three_agent.task_context import TaskContextBuilder
from three_agent.task_contract import TaskContractCompiler


def sample_workflow():
    return {
        "title": "Runtime checkpoint",
        "objective": "Recover canonical runtime state without replaying work.",
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
                "id": "research",
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
                "depends_on": ["research"],
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
        task_id = "TASK-CHECKPOINT-1"
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
                    statement="Recover a deterministic scheduling decision",
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
            session_id="SESSION-CHECKPOINT-1",
            trace_id="TRACE-CHECKPOINT-1",
            actor_id="ACTOR-CHECKPOINT-1",
            purpose="runtime checkpoint recovery",
            project_id="PROJECT-1",
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        plan = ExecutionPlanBuilder.build(
            task_context=context,
            parent_authority=authority,
            workflow_contract=sample_workflow(),
        )
        return context, authority, plan

    @staticmethod
    def _observation(
        plan,
        authority,
        node_id,
        status,
        second,
        *,
        normalized_output=None,
        error_class=None,
    ):
        return ExecutionObservationBuilder.build(
            plan=plan,
            node_id=node_id,
            parent_authority=authority,
            status=status,
            started_at=f"2026-09-08T02:30:{second:02d}Z",
            finished_at=f"2026-09-08T02:30:{second:02d}Z",
            normalized_output=normalized_output,
            error_class=error_class,
        )

    def test_checkpoint_is_metadata_only_and_recovers_next_ready_node(self):
        context, authority, plan = self._runtime()
        secret_marker = "raw-secret-output-must-not-enter-checkpoint"
        start = self._observation(
            plan,
            authority,
            "start",
            "SUCCEEDED",
            0,
            normalized_output={"private": secret_marker},
        )
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start,),
            created_at="2026-09-08T02:31:00Z",
        )
        serialized = json.dumps(checkpoint.canonical_dict(), sort_keys=True)
        self.assertNotIn(secret_marker, serialized)
        self.assertNotIn("normalized_output", serialized)
        self.assertEqual(checkpoint.observation_refs[0].observation_id, start.observation_id)
        self.assertEqual(
            checkpoint.observation_refs[0].observation_fingerprint,
            start.fingerprint,
        )

        decision = RuntimeCheckpointRecovery.recover(
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start,),
        )
        self.assertEqual(decision.status, "READY")
        self.assertEqual(decision.ready_node_ids, ("research",))

    def test_partial_observation_recovers_waiting_and_never_auto_replays(self):
        context, authority, plan = self._runtime()
        partial = self._observation(plan, authority, "start", "PARTIAL", 0)
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(partial,),
            created_at="2026-09-08T02:31:00Z",
        )
        decision = RuntimeCheckpointRecovery.recover(
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(partial,),
        )
        self.assertEqual(decision.status, "WAITING")
        self.assertNotIn("start", decision.ready_node_ids)
        record = next(item for item in decision.records if item.node_id == "start")
        self.assertEqual(
            record.reason_code,
            "PARTIAL_OBSERVATION_REQUIRES_RECONCILIATION",
        )

    def test_recovery_rejects_missing_or_tampered_observation(self):
        context, authority, plan = self._runtime()
        start = self._observation(plan, authority, "start", "SUCCEEDED", 0)
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start,),
            created_at="2026-09-08T02:31:00Z",
        )
        with self.assertRaisesRegex(
            RuntimeCheckpointError,
            "RECOVERY_OBSERVATION_MISSING",
        ):
            RuntimeCheckpointRecovery.recover(
                checkpoint=checkpoint,
                task_context=context,
                plan=plan,
                parent_authority=authority,
                observations=(),
            )

        bad_ref = replace(
            checkpoint.observation_refs[0],
            observation_fingerprint="sha256:" + "0" * 64,
        )
        identity = checkpoint._identity_dict()
        identity["observation_refs"] = [bad_ref.canonical_dict()]
        tampered = replace(
            checkpoint,
            observation_refs=(bad_ref,),
            checkpoint_id="checkpoint:" + "0" * 24,
        )
        with self.assertRaisesRegex(
            RuntimeCheckpointError,
            "CHECKPOINT_IDENTITY_MISMATCH",
        ):
            tampered.validate()

    def test_checkpoint_rejects_context_drift(self):
        context, authority, plan = self._runtime()
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            created_at="2026-09-08T02:31:00Z",
        )
        changed_context = context.derive(evidence_refs=("evidence:new",))
        with self.assertRaisesRegex(
            RuntimeCheckpointError,
            "CHECKPOINT_TASK_CONTEXT_CHANGED",
        ):
            checkpoint.validate_bindings(
                task_context=changed_context,
                plan=plan,
                parent_authority=authority,
            )

    def test_approval_is_not_persisted_and_must_be_supplied_again_on_recovery(self):
        context, authority, plan = self._runtime()
        observations = (
            self._observation(plan, authority, "start", "SUCCEEDED", 0),
            self._observation(plan, authority, "research", "SUCCEEDED", 1),
            self._observation(plan, authority, "approve", "SUCCEEDED", 2),
        )
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=observations,
            approved_node_ids=("approve",),
            created_at="2026-09-08T02:31:00Z",
        )
        serialized = json.dumps(checkpoint.canonical_dict(), sort_keys=True)
        self.assertNotIn("approved_node_ids", serialized)

        with self.assertRaisesRegex(
            RuntimeCheckpointError,
            "RECOVERY_SCHEDULER_REVALIDATION_FAILED",
        ):
            RuntimeCheckpointRecovery.recover(
                checkpoint=checkpoint,
                task_context=context,
                plan=plan,
                parent_authority=authority,
                observations=observations,
            )

        recovered = RuntimeCheckpointRecovery.recover(
            checkpoint=checkpoint,
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=observations,
            approved_node_ids=("approve",),
        )
        self.assertEqual(recovered.ready_node_ids, ("done",))

    def test_previous_checkpoint_chain_is_bound_by_fingerprint(self):
        context, authority, plan = self._runtime()
        first = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            created_at="2026-09-08T02:31:00Z",
        )
        start = self._observation(plan, authority, "start", "SUCCEEDED", 0)
        second = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            observations=(start,),
            created_at="2026-09-08T02:32:00Z",
            previous_checkpoint=first,
        )
        self.assertEqual(second.previous_checkpoint_fingerprint, first.fingerprint)
        self.assertNotEqual(second.fingerprint, first.fingerprint)

    def test_store_round_trip_and_corruption_detection(self):
        context, authority, plan = self._runtime()
        checkpoint = RuntimeCheckpointBuilder.build(
            task_context=context,
            plan=plan,
            parent_authority=authority,
            created_at="2026-09-08T02:31:00Z",
        )
        with tempfile.TemporaryDirectory() as temporary:
            store = RuntimeCheckpointStore(Path(temporary))
            path = store.save(checkpoint)
            loaded = store.load(
                task_id=context.task_id,
                checkpoint_id=checkpoint.checkpoint_id,
            )
            self.assertEqual(loaded, checkpoint)
            self.assertEqual(loaded.fingerprint, checkpoint.fingerprint)

            envelope = json.loads(path.read_text(encoding="utf-8"))
            envelope["checkpoint"]["plan_fingerprint"] = "sha256:" + "0" * 64
            path.write_text(json.dumps(envelope), encoding="utf-8")
            with self.assertRaises(RuntimeCheckpointError):
                store.load(
                    task_id=context.task_id,
                    checkpoint_id=checkpoint.checkpoint_id,
                )

    def test_store_rejects_invalid_checkpoint_identifier(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = RuntimeCheckpointStore(Path(temporary))
            with self.assertRaisesRegex(
                RuntimeCheckpointError,
                "INVALID_CHECKPOINT_ID",
            ):
                store.load(
                    task_id="TASK-1",
                    checkpoint_id="../../escape",
                )


if __name__ == "__main__":
    unittest.main()
