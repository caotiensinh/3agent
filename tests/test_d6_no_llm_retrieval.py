import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.artifacts import ArtifactManager
from three_agent.deterministic_retrieval import DeterministicRetrievalExecutor
from three_agent.knowledge_plane import InboundKnowledgeImporter, PublicEvidenceExporter
from three_agent.models import TaskStatus
from three_agent.route_planner import DeterministicRoutePlanner
from three_agent.runtime_validation import RuntimeValidatorBridge
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler, TaskContractError
from three_agent.validator_ledger import ValidatorLedger


def research_payload(text: str = "GPU inference efficiency deterministic evidence") -> dict:
    return {
        "task_id": "TASK-FIXTURE",
        "generated_at": "2026-08-29T10:00:00+09:00",
        "sources": [
            {
                "source_id": "S1",
                "title": "Public deterministic note",
                "url": "https://example.com/deterministic-note",
                "fetch_status": "ok",
                "extracted_text": text,
            }
        ],
        "source_assessments": [
            {
                "source_id": "S1",
                "relevance": "high",
                "scope_match": True,
                "time_match": True,
                "authority": "primary",
            }
        ],
        "rejected_sources": [],
    }


class D6NoLLMRoutingTests(unittest.TestCase):
    def test_deterministic_retrieval_contract_has_no_model_or_escalation(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-1",
            task_type="retrieval",
            sensitivity="confidential",
            deterministic_only=True,
        )
        self.assertEqual(contract.model_policy.initial_tier, "none")
        self.assertEqual(contract.model_policy.max_tier, "none")
        self.assertFalse(contract.model_policy.escalation_allowed)
        self.assertEqual(contract.execution_budget.max_escalations, 0)
        self.assertEqual(contract.execution_budget.max_retries, 0)
        self.assertIn("NO_LLM_DETERMINISTIC_LOCAL_RETRIEVAL", contract.policy_reason_codes)
        self.assertEqual(contract.network_scope, "deny")
        self.assertEqual(contract.validators, ("policy", "evidence"))

        decision = DeterministicRoutePlanner.plan(contract)
        self.assertEqual(decision.route, "NO_LLM")
        self.assertEqual(decision.reason_code, "CONTRACT_NO_LLM")
        self.assertFalse(decision.escalation_allowed)

    def test_no_llm_request_cannot_expand_scope(self):
        compiler = TaskContractCompiler()
        with self.assertRaises(TaskContractError):
            compiler.compile(
                task_id="TASK-1",
                task_type="analysis",
                deterministic_only=True,
            )
        with self.assertRaises(TaskContractError):
            compiler.compile(
                task_id="TASK-2",
                task_type="retrieval",
                sensitivity="public",
                public_web=True,
                deterministic_only=True,
            )
        with self.assertRaises(TaskContractError):
            compiler.compile(
                task_id="TASK-3",
                task_type="retrieval",
                allowed_tools=("search_docs", "web_gateway"),
                deterministic_only=True,
            )

    def test_normal_model_contract_stays_model_routed(self):
        contract = TaskContractCompiler().compile(
            task_id="TASK-1",
            task_type="analysis",
            sensitivity="confidential",
        )
        decision = DeterministicRoutePlanner.plan(contract)
        self.assertEqual(decision.route, "MODEL")
        self.assertEqual(decision.initial_model_tier, "specialist")
        self.assertEqual(decision.max_model_tier, "strong")

    def test_production_runtime_bridge_records_reason_coded_model_route_without_raw_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            task = store.create_task("SECRET TITLE", "SECRET REQUEST BODY")
            bridge = RuntimeValidatorBridge(
                store,
                ArtifactManager(root / "artifacts"),
                confidentiality_mode="confidential",
                public_web=False,
            )
            bridge.begin(task.task_id)
            with store.connect() as conn:
                rows = conn.execute(
                    "SELECT agent_id, action, details FROM activities WHERE task_id = ? ORDER BY id",
                    (task.task_id,),
                ).fetchall()
            route_rows = [row for row in rows if row["action"] == "route_selected"]
            self.assertEqual(len(route_rows), 1)
            details = str(route_rows[0]["details"])
            self.assertIn("route=MODEL", details)
            self.assertIn("reason=CONTRACT_SPECIALIST_FIRST", details)
            self.assertNotIn("SECRET TITLE", details)
            self.assertNotIn("SECRET REQUEST BODY", details)


class DeterministicRetrievalExecutorTests(unittest.TestCase):
    def _runtime(self, root: Path, *, evidence=True):
        store = TaskStore(root / "tasks.db")
        store.initialize()
        artifacts = ArtifactManager(root / "artifacts")
        knowledge = root / "knowledge"
        if evidence:
            exported = PublicEvidenceExporter(root / "out").export_research_payload(
                research_payload("CONFIDENTIAL-MARKER GPU inference efficiency evidence")
            )
            InboundKnowledgeImporter(knowledge).import_bundle(exported)
        return store, artifacts, knowledge

    def test_verified_retrieval_completes_with_zero_inference_telemetry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, artifacts, knowledge = self._runtime(root)
            telemetry = root / "inference.jsonl"
            with patch.dict(
                os.environ,
                {"WORKSPACE_INFERENCE_TELEMETRY": str(telemetry)},
                clear=False,
            ):
                result = DeterministicRetrievalExecutor(
                    store, artifacts, knowledge
                ).run(
                    "Local evidence lookup",
                    "GPU inference efficiency",
                )

            self.assertEqual(result.status, "completed")
            self.assertEqual(result.task_status, TaskStatus.DONE.value)
            self.assertEqual(result.route["route"], "NO_LLM")
            self.assertTrue(result.verification["verified"])
            self.assertTrue(result.verification["first_pass_verified"])
            self.assertEqual(
                result.verification["required_validators"], ["policy", "evidence"]
            )
            self.assertFalse(telemetry.exists())

            contract = store.task_contract_for_task(result.task_id)
            self.assertEqual(contract["model_policy"]["initial_tier"], "none")
            self.assertEqual(contract["execution_budget"]["max_escalations"], 0)

            artifact = json.loads(Path(result.artifact_path).read_text(encoding="utf-8"))
            self.assertIn("CONFIDENTIAL-MARKER", artifact["context"]["text"])
            ledger = ValidatorLedger(store).export_results(result.task_id)
            serialized = json.dumps(ledger)
            self.assertNotIn("CONFIDENTIAL-MARKER", serialized)
            self.assertNotIn("GPU inference efficiency", serialized)
            for row in ledger:
                for ref in row["evidence_refs"]:
                    self.assertTrue(ref.startswith("sha256:"))

    def test_missing_evidence_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, artifacts, knowledge = self._runtime(root, evidence=False)
            result = DeterministicRetrievalExecutor(store, artifacts, knowledge).run(
                "Missing evidence lookup",
                "GPU inference efficiency",
            )
            self.assertEqual(result.status, "failed")
            self.assertEqual(result.task_status, TaskStatus.FAILED.value)
            self.assertFalse(result.verification["verified"])
            self.assertIn("evidence", result.verification["failed_validators"])

    def test_high_risk_retrieval_waits_for_human_instead_of_self_approving(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store, artifacts, knowledge = self._runtime(root)
            result = DeterministicRetrievalExecutor(store, artifacts, knowledge).run(
                "High-risk local lookup",
                "GPU inference efficiency",
                risk_level="high",
            )
            self.assertEqual(result.status, "blocked")
            self.assertEqual(result.task_status, TaskStatus.WAITING_HUMAN.value)
            self.assertFalse(result.verification["verified"])
            self.assertEqual(result.verification["missing_validators"], ["human"])
            self.assertNotIn("human", result.verification["passed_validators"])


if __name__ == "__main__":
    unittest.main()
