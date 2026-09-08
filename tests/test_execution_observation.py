import unittest
from dataclasses import FrozenInstanceError, replace

from three_agent.capability_authority import TaskCapabilityAuthority
from three_agent.execution_observation import (
    ExecutionEvidenceBinding,
    ExecutionObservationBuilder,
    ExecutionObservationError,
    ObservationCost,
)
from three_agent.execution_plan import ExecutionNodeBinding, ExecutionPlanBuilder
from three_agent.harness_acceptance import AcceptanceContract, AcceptanceCriterion
from three_agent.harness_task_compiler import HarnessTaskCompiler
from three_agent.security_monitoring.execution_evidence_adapter import (
    ExecutionEvidenceAdapterError,
    bind_normalized_evidence,
)
from three_agent.security_monitoring.normalized_evidence import (
    EvidenceIntegrity,
    EvidenceObservationWindow,
    EvidenceProvenance,
    EvidenceQuality,
    NormalizedEvidence,
)
from three_agent.task_context import TaskContextBuilder, TaskResourceBudget
from three_agent.task_contract import TaskContractCompiler


def sample_workflow():
    return {
        "title": "Runtime observation binding",
        "objective": "Collect evidence, validate it, and return a bounded result.",
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
                "id": "done",
                "label": "Return result",
                "kind": "output",
                "action": "output",
                "depends_on": ["research"],
                "condition": "",
                "approval_required": False,
            },
        ],
        "outputs": ["Validated result"],
        "warnings": [],
    }


class ExecutionObservationConvergenceTests(unittest.TestCase):
    @staticmethod
    def _runtime():
        task_id = "TASK-OBS-1"
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
                    statement="Produce evidence-bound runtime observations",
                    verifier="unit_test",
                ),
            ),
        )
        canonical = HarnessTaskCompiler().compile(
            user_prompt="Bind execution observations to evidence.",
            task_contract=contract,
            acceptance_contract=acceptance,
        )
        context = TaskContextBuilder.build(
            task_contract=contract,
            canonical_task=canonical,
            session_id="SESSION-OBS-1",
            trace_id="TRACE-OBS-1",
            actor_id="ACTOR-OBS-1",
            purpose="runtime observation binding",
            project_id="PROJECT-1",
        )
        authority = TaskCapabilityAuthority.from_contract(contract)
        plan = ExecutionPlanBuilder.build(
            task_context=context,
            parent_authority=authority,
            workflow_contract=sample_workflow(),
            node_bindings={
                "research": ExecutionNodeBinding(
                    allowed_sources=("repo", "evidence"),
                    allowed_tools=("search_docs", "read_file"),
                    resource_budget=TaskResourceBudget(
                        wall_time_s=30,
                        model_tokens=500,
                        tool_calls=2,
                    ),
                    evidence_requirements=("source_integrity",),
                ),
            },
        )
        node = next(row for row in plan.nodes if row.node_id == "research")
        return context, authority, plan, node

    @staticmethod
    def _binding(requirement="source_integrity"):
        return ExecutionEvidenceBinding(
            requirement=requirement,
            evidence_ref="evidence:1234567890abcdef12345678",
            evidence_fingerprint="sha256:" + "a" * 64,
        )

    def test_observation_is_deterministic_and_bound_to_exact_plan_node_authority(self):
        context, authority, plan, node = self._runtime()
        first = ExecutionObservationBuilder.build(
            plan=plan,
            node_id="research",
            parent_authority=authority,
            status="SUCCEEDED",
            started_at="2026-09-08T10:00:00+09:00",
            finished_at="2026-09-08T10:00:02+09:00",
            normalized_output={"z": 2, "a": {"ok": True}},
            evidence_bindings=(self._binding(),),
            cost=ObservationCost(wall_time_s=2, model_tokens=100, tool_calls=1),
        )
        second = ExecutionObservationBuilder.build(
            plan=plan,
            node_id="research",
            parent_authority=authority,
            status="SUCCEEDED",
            started_at="2026-09-08T01:00:00Z",
            finished_at="2026-09-08T01:00:02Z",
            normalized_output={"a": {"ok": True}, "z": 2},
            evidence_bindings=(self._binding(),),
            cost=ObservationCost(wall_time_s=2.0, model_tokens=100, tool_calls=1),
        )

        self.assertEqual(first.observation_id, second.observation_id)
        self.assertEqual(first.fingerprint, second.fingerprint)
        self.assertEqual(first.task_context_fingerprint, context.fingerprint)
        self.assertEqual(first.plan_fingerprint, plan.fingerprint)
        self.assertEqual(first.node_fingerprint, node.fingerprint)
        self.assertEqual(first.authority_fingerprint, node.authority_fingerprint)
        self.assertEqual(first.evidence_refs, (self._binding().evidence_ref,))
        self.assertEqual(first.normalized_output, {"a": {"ok": True}, "z": 2})
        with self.assertRaises(FrozenInstanceError):
            first.status = "FAILED"
        with self.assertRaises(ExecutionObservationError):
            replace(first, observation_id="observation:" + "0" * 24).validate()

    def test_success_requires_all_declared_evidence(self):
        _, authority, plan, _ = self._runtime()
        with self.assertRaisesRegex(
            ExecutionObservationError,
            "OBSERVATION_REQUIRED_EVIDENCE_MISSING:source_integrity",
        ):
            ExecutionObservationBuilder.build(
                plan=plan,
                node_id="research",
                parent_authority=authority,
                status="SUCCEEDED",
                started_at="2026-09-08T01:00:00Z",
                finished_at="2026-09-08T01:00:01Z",
                normalized_output={"ok": True},
            )

    def test_partial_may_preserve_incomplete_evidence_without_claiming_success(self):
        _, authority, plan, _ = self._runtime()
        observation = ExecutionObservationBuilder.build(
            plan=plan,
            node_id="research",
            parent_authority=authority,
            status="PARTIAL",
            started_at="2026-09-08T01:00:00Z",
            finished_at="2026-09-08T01:00:01Z",
            normalized_output={"partial": True},
        )
        self.assertEqual(observation.status, "PARTIAL")
        self.assertEqual(observation.evidence_refs, ())

    def test_observation_cannot_claim_undeclared_evidence_requirement(self):
        _, authority, plan, _ = self._runtime()
        with self.assertRaisesRegex(
            ExecutionObservationError,
            "OBSERVATION_UNDECLARED_EVIDENCE_REQUIREMENT:other_requirement",
        ):
            ExecutionObservationBuilder.build(
                plan=plan,
                node_id="research",
                parent_authority=authority,
                status="PARTIAL",
                started_at="2026-09-08T01:00:00Z",
                finished_at="2026-09-08T01:00:01Z",
                evidence_bindings=(self._binding("other_requirement"),),
            )

    def test_status_error_semantics_fail_closed(self):
        _, authority, plan, _ = self._runtime()
        with self.assertRaisesRegex(
            ExecutionObservationError,
            "FAILED_OBSERVATION_REQUIRES_ERROR_CLASS",
        ):
            ExecutionObservationBuilder.build(
                plan=plan,
                node_id="research",
                parent_authority=authority,
                status="FAILED",
                started_at="2026-09-08T01:00:00Z",
                finished_at="2026-09-08T01:00:01Z",
            )
        with self.assertRaisesRegex(
            ExecutionObservationError,
            "SUCCEEDED_OBSERVATION_CANNOT_HAVE_ERROR",
        ):
            ExecutionObservationBuilder.build(
                plan=plan,
                node_id="research",
                parent_authority=authority,
                status="SUCCEEDED",
                started_at="2026-09-08T01:00:00Z",
                finished_at="2026-09-08T01:00:01Z",
                error_class="TOOL_ERROR",
                evidence_bindings=(self._binding(),),
            )

    def test_timestamps_and_cost_are_bounded(self):
        _, authority, plan, _ = self._runtime()
        with self.assertRaisesRegex(
            ExecutionObservationError,
            "OBSERVATION_FINISHED_BEFORE_STARTED",
        ):
            ExecutionObservationBuilder.build(
                plan=plan,
                node_id="research",
                parent_authority=authority,
                status="PARTIAL",
                started_at="2026-09-08T01:00:02Z",
                finished_at="2026-09-08T01:00:01Z",
            )
        with self.assertRaisesRegex(
            ExecutionObservationError,
            "OBSERVATION_TOOL_CALLS_EXCEED_NODE_BUDGET",
        ):
            ExecutionObservationBuilder.build(
                plan=plan,
                node_id="research",
                parent_authority=authority,
                status="PARTIAL",
                started_at="2026-09-08T01:00:00Z",
                finished_at="2026-09-08T01:00:01Z",
                cost=ObservationCost(tool_calls=3),
            )

    def test_security_normalized_evidence_adapter_preserves_existing_evidence(self):
        context, authority, plan, node = self._runtime()
        evidence = NormalizedEvidence.create(
            evidence_type="snmp_observation",
            source_type="snmpv3_read",
            asset_ref="asset-001",
            task_ref_sha256=plan.task_context_identity_fingerprint,
            authorization_ref_sha256=node.authority_fingerprint,
            collected_at="2026-09-08T01:00:02Z",
            observation_window=EvidenceObservationWindow(
                start_at="2026-09-08T01:00:00Z",
                end_at="2026-09-08T01:00:01Z",
            ),
            integrity=EvidenceIntegrity(
                content_sha256="sha256:" + "b" * 64,
                source_record_sha256="sha256:" + "c" * 64,
            ),
            sensitivity="internal",
            quality=EvidenceQuality(confidence=1.0, completeness=1.0),
            raw_ref="raw:snmp:asset-001:1",
            provenance=EvidenceProvenance(
                producer="security_monitoring",
                parser_version="test-v1",
                lineage_refs=("sha256:" + "d" * 64,),
            ),
        )
        binding = bind_normalized_evidence(
            plan=plan,
            node_id="research",
            evidence=evidence,
            requirement="source_integrity",
        )
        observation = ExecutionObservationBuilder.build(
            plan=plan,
            node_id="research",
            parent_authority=authority,
            status="SUCCEEDED",
            started_at="2026-09-08T01:00:00Z",
            finished_at="2026-09-08T01:00:02Z",
            normalized_output={"asset": "asset-001", "reachable": True},
            evidence_bindings=(binding,),
        )
        self.assertEqual(binding.evidence_ref, evidence.evidence_id)
        self.assertEqual(binding.evidence_fingerprint, evidence.identity_sha256)
        self.assertEqual(observation.evidence_refs, (evidence.evidence_id,))
        self.assertEqual(observation.task_context_fingerprint, context.fingerprint)

    def test_security_evidence_adapter_rejects_task_or_authority_mismatch(self):
        _, _, plan, node = self._runtime()
        evidence = NormalizedEvidence.create(
            evidence_type="snmp_observation",
            source_type="snmpv3_read",
            asset_ref="asset-001",
            task_ref_sha256="sha256:" + "1" * 64,
            authorization_ref_sha256=node.authority_fingerprint,
            collected_at="2026-09-08T01:00:02Z",
            observation_window=EvidenceObservationWindow(
                start_at="2026-09-08T01:00:00Z",
                end_at="2026-09-08T01:00:01Z",
            ),
            integrity=EvidenceIntegrity(
                content_sha256="sha256:" + "2" * 64,
                source_record_sha256="sha256:" + "3" * 64,
            ),
            sensitivity="internal",
            quality=EvidenceQuality(confidence=1.0, completeness=1.0),
            raw_ref="raw:snmp:asset-001:2",
            provenance=EvidenceProvenance(
                producer="security_monitoring",
                parser_version="test-v1",
                lineage_refs=("sha256:" + "4" * 64,),
            ),
        )
        with self.assertRaisesRegex(
            ExecutionEvidenceAdapterError,
            "EVIDENCE_TASK_CONTEXT_MISMATCH",
        ):
            bind_normalized_evidence(
                plan=plan,
                node_id="research",
                evidence=evidence,
                requirement="source_integrity",
            )


if __name__ == "__main__":
    unittest.main()
