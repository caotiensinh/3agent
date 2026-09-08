import unittest
from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta, timezone

from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_context_manifest import ContextManifestBuilder, ContextSectionInput
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.task_context import TaskContextBuilder, TaskContextError
from three_agent.task_contract import TaskContractCompiler


class TaskContextConvergenceTests(unittest.TestCase):
    @staticmethod
    def _bindings(*, task_id: str = "TASK-CTX-1", risk_level: str = "medium"):
        contract = TaskContractCompiler().compile(
            task_id=task_id,
            task_type="analysis",
            sensitivity="internal",
            risk_level=risk_level,
            allowed_sources=("repo", "evidence"),
            write_scope="none",
        )
        acceptance = AcceptanceContract(
            task_id=task_id,
            criteria=(
                AcceptanceCriterion(
                    criterion_id="result",
                    statement="Produce a source-grounded runtime result",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Normalize the WorkSpace runtime task context.",
            task_contract=contract,
            acceptance_contract=acceptance,
        )
        return contract, canonical

    def test_builder_projects_existing_contract_without_becoming_authority(self):
        contract, canonical = self._bindings()
        created = datetime(2026, 9, 8, 1, 0, tzinfo=timezone.utc)
        context = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-1",
            trace_id="TRACE-1",
            actor_id="ACTOR-1",
            purpose="runtime convergence",
            project_id="PROJECT-1",
            inventory_scope=("repo:caotiensinh/3agent",),
            created_at=created,
            deadline=created + timedelta(minutes=15),
        )

        self.assertEqual(context.task_id, contract.task_id)
        self.assertEqual(context.risk_class, "R2")
        self.assertEqual(context.authority_fingerprint, canonical.authority_fingerprint)
        self.assertEqual(context.resource_budget.wall_time_s, 600)
        self.assertEqual(context.resource_budget.model_tokens, 18000)
        self.assertEqual(context.resource_budget.tool_calls, contract.execution_budget.max_tool_calls)
        self.assertEqual(context.context_version, 1)
        self.assertIsNone(context.parent_context_fingerprint)

        metadata = context.canonical_dict()
        self.assertNotIn("intent", metadata)
        self.assertEqual(metadata["intent_sha256"], context.intent_sha256)
        self.assertEqual(metadata["task_contract_fingerprint"], context.task_contract_fingerprint)
        self.assertEqual(metadata["canonical_task_fingerprint"], canonical.fingerprint)

        with self.assertRaises(FrozenInstanceError):
            context.actor_id = "OTHER-ACTOR"

    def test_builder_rejects_canonical_task_bound_to_different_contract(self):
        contract, _ = self._bindings(task_id="TASK-CTX-PARENT")
        _, other_canonical = self._bindings(task_id="TASK-CTX-OTHER")

        with self.assertRaises(TaskContextError):
            TaskContextBuilder.build(
                task_contract=contract,
                canonical_task=other_canonical,
                session_id="SESSION-1",
                trace_id="TRACE-1",
                actor_id="ACTOR-1",
                purpose="must fail closed",
                project_id="PROJECT-1",
            )

    def test_versioned_derivation_adds_references_without_identity_change(self):
        contract, canonical = self._bindings()
        root = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-1",
            trace_id="TRACE-1",
            actor_id="ACTOR-1",
            purpose="runtime convergence",
            project_id="PROJECT-1",
        )
        derived = root.derive(
            context_refs=("memory:summary:1",),
            evidence_refs=("evidence:unit:1",),
        )

        self.assertEqual(derived.context_version, 2)
        self.assertEqual(derived.parent_context_fingerprint, root.fingerprint)
        self.assertEqual(derived.identity_fingerprint, root.identity_fingerprint)
        self.assertNotEqual(derived.fingerprint, root.fingerprint)
        self.assertEqual(derived.context_refs, ("memory:summary:1",))
        self.assertEqual(derived.evidence_refs, ("evidence:unit:1",))

        with self.assertRaisesRegex(TaskContextError, "TASK_CONTEXT_DERIVATION_HAS_NO_NEW_REFERENCES"):
            derived.derive(context_refs=("memory:summary:1",))

    def test_context_manifest_binding_requires_same_scope_and_authority(self):
        contract, canonical = self._bindings()
        root = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-1",
            trace_id="TRACE-1",
            actor_id="ACTOR-1",
            purpose="runtime convergence",
            project_id="PROJECT-1",
        )
        manifest = ContextManifestBuilder.build(
            context_manifest_id="CTX-MANIFEST-1",
            project_id="PROJECT-1",
            conversation_id="SESSION-1",
            task_id=contract.task_id,
            model_id="local:test",
            max_input=1000,
            reserved_output=100,
            section_inputs=(
                ContextSectionInput(
                    section_type="memory",
                    item_count=1,
                    token_count=100,
                    source_hash="sha256:" + ("a" * 64),
                    source_refs=("memory:1",),
                    critical=True,
                ),
            ),
            authority_fingerprint=root.authority_fingerprint,
        )

        bound = root.bind_context_manifest(manifest)

        self.assertEqual(bound.context_version, 2)
        self.assertEqual(bound.identity_fingerprint, root.identity_fingerprint)
        self.assertEqual(len(bound.context_refs), 1)
        self.assertIn("CTX-MANIFEST-1", bound.context_refs[0])
        self.assertIn(manifest.fingerprint, bound.context_refs[0])

    def test_context_manifest_authority_mismatch_fails_closed(self):
        contract, canonical = self._bindings()
        root = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-1",
            trace_id="TRACE-1",
            actor_id="ACTOR-1",
            purpose="runtime convergence",
            project_id="PROJECT-1",
        )
        manifest = ContextManifestBuilder.build(
            context_manifest_id="CTX-MANIFEST-2",
            project_id="PROJECT-1",
            conversation_id="SESSION-1",
            task_id=contract.task_id,
            model_id="local:test",
            max_input=1000,
            reserved_output=100,
            section_inputs=(
                ContextSectionInput(
                    section_type="evidence",
                    item_count=1,
                    token_count=50,
                    source_hash="sha256:" + ("b" * 64),
                    source_refs=("evidence:1",),
                ),
            ),
            authority_fingerprint="sha256:" + ("0" * 64),
        )

        with self.assertRaisesRegex(TaskContextError, "TASK_CONTEXT_MANIFEST_AUTHORITY_MISMATCH"):
            root.bind_context_manifest(manifest)

    def test_deadline_and_reference_validation_are_fail_closed(self):
        contract, canonical = self._bindings(risk_level="critical")
        created = datetime(2026, 9, 8, 1, 0, tzinfo=timezone.utc)

        with self.assertRaisesRegex(TaskContextError, "TASK_CONTEXT_DEADLINE_NOT_AFTER_CREATED_AT"):
            TaskContextBuilder.build(
                task_contract=contract,
                canonical_task=canonical,
                session_id="SESSION-1",
                trace_id="TRACE-1",
                actor_id="ACTOR-1",
                purpose="runtime convergence",
                project_id="PROJECT-1",
                created_at=created,
                deadline=created,
            )

        with self.assertRaisesRegex(TaskContextError, "INVALID_INVENTORY_SCOPE"):
            TaskContextBuilder.build(
                task_contract=contract,
                canonical_task=canonical,
                session_id="SESSION-1",
                trace_id="TRACE-1",
                actor_id="ACTOR-1",
                purpose="runtime convergence",
                project_id="PROJECT-1",
                inventory_scope=("bad\nscope",),
            )


if __name__ == "__main__":
    unittest.main()
