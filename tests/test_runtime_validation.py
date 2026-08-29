import tempfile
import unittest
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.handoff_security import build_handoff_security_metadata
from three_agent.models import TaskStatus
from three_agent.runtime_validation import (
    RuntimeValidatorBridge,
    WorkflowDailyValidationProxy,
    WorkflowResearchValidationProxy,
)
from three_agent.store import TaskStore
from three_agent.workflow import WorkflowRunner


class FakeResearchAgent:
    def __init__(self, mode: str = "ready"):
        self.mode = mode

    @staticmethod
    def _handoff(task_id: str) -> dict:
        payload = {
            "schema_version": "1.0",
            "task_id": task_id,
            "agent_id": "research",
            "presentation_ready": True,
            "blockers": [],
            "objective": "Test objective",
            "key_facts": [
                {
                    "fact_id": "F001",
                    "claim": "Verified fact",
                    "source_ids": ["S1"],
                    "confidence": "medium",
                }
            ],
            "inferences": [],
            "conflicts": [],
            "unresolved_items": [],
            "constraint_gaps": [],
            "conclusion": "Verified conclusion",
            "recommended_next_actions": [],
            "sources": [
                {
                    "source_id": "S1",
                    "title": "Source",
                    "url": "https://example.com",
                    "fetch_status": "ok",
                }
            ],
            "source_assessments": [],
            "quality_metrics": {
                "usable_source_count": 1,
                "verified_fact_count": 1,
                "evidence_coverage": 1.0,
            },
            "generated_at": "2026-08-29T00:00:00+09:00",
        }
        security = build_handoff_security_metadata(
            payload,
            [],
            source_agent="research",
            source_type="research_handoff",
            target_agent="presentation",
            task_id=task_id,
            trust_domain="workspace-local-derived-from-untrusted",
            sanitizer_version="workspace-handoff-sanitizer/v1",
            provenance_refs=["S1"],
        )
        payload["security"] = security.to_dict()
        return payload

    def run(self, task_id, store, artifacts, live=False):
        del live
        if self.mode == "error":
            raise RuntimeError("research provider failed")
        if self.mode == "blocked":
            store.set_status(task_id, TaskStatus.WAITING_HUMAN)
            return ()

        handoff = self._handoff(task_id)
        if self.mode == "tampered":
            handoff["key_facts"][0]["claim"] = "Tampered after signing"
        handoff_path = artifacts.write_research_handoff(task_id, handoff)
        store.set_status(task_id, TaskStatus.RESEARCH_COMPLETED)
        return (handoff_path,)


class FakePresentationAgent:
    def __init__(self, fail: bool = False):
        self.fail = fail

    def run(self, task_id, store, artifacts, **kwargs):
        del kwargs
        if self.fail:
            store.set_status(task_id, TaskStatus.FAILED)
            raise RuntimeError("presentation failed")
        payload = {
            "schema_version": "presentation-artifact/v1",
            "task_id": task_id,
            "status": "validated",
        }
        json_path, md_path = artifacts.write_task_artifact(
            "presentations",
            task_id,
            payload,
            "# Presentation",
        )
        store.set_status(task_id, TaskStatus.PRESENTATION_COMPLETED)
        return json_path, md_path


class FakeDailyAgent:
    def __init__(self, fail: bool = False):
        self.fail = fail

    def run(self, date, store, artifacts, live=False):
        del store, live
        if self.fail:
            raise RuntimeError("daily failed")
        return artifacts.write_daily_report(
            date,
            {"schema_version": "daily-report/v1"},
            "# Daily",
        )


class RuntimeValidatorBridgeTests(unittest.TestCase):
    def make_stack(
        self,
        root: Path,
        *,
        research_mode: str = "ready",
        presentation_fail: bool = False,
        daily_fail: bool = False,
    ):
        store = TaskStore(root / "tasks.db")
        store.initialize()
        artifacts = ArtifactManager(root / "data")
        bridge = RuntimeValidatorBridge(
            store,
            artifacts,
            confidentiality_mode="confidential",
            public_web=False,
        )
        runner = WorkflowRunner(
            store,
            artifacts,
            WorkflowResearchValidationProxy(
                FakeResearchAgent(research_mode),
                bridge,
            ),
            FakePresentationAgent(presentation_fail),
            WorkflowDailyValidationProxy(
                FakeDailyAgent(daily_fail),
                bridge,
            ),
        )
        return runner, store, bridge

    def test_successful_workflow_is_verified_on_first_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, store, bridge = self.make_stack(Path(tmp))
            result = runner.create_and_run(
                "Verified workflow",
                "Research, present and report",
                live=False,
                output_format="source",
            )

            self.assertEqual(result.status, "completed")
            state = bridge.ledger.evaluate(result.task_id)
            self.assertTrue(state.verified)
            self.assertTrue(state.first_pass_verified)
            self.assertEqual(
                set(state.required_validators),
                {"policy", "evidence", "integration_test"},
            )
            self.assertEqual(
                set(state.passed_validators),
                {"policy", "evidence", "integration_test"},
            )
            self.assertEqual(store.get_task(result.task_id).status, TaskStatus.DONE)

    def test_tampered_handoff_fails_evidence_and_never_reaches_presentation(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, _, bridge = self.make_stack(
                Path(tmp),
                research_mode="tampered",
            )
            result = runner.create_and_run(
                "Tampered",
                "Reject modified evidence",
                live=False,
                output_format="source",
            )

            self.assertEqual(result.status, "failed")
            state = bridge.ledger.evaluate(result.task_id)
            self.assertFalse(state.verified)
            self.assertIn("evidence", state.failed_validators)
            rows = bridge.ledger.export_results(result.task_id)
            reasons = [row["reason_code"] for row in rows]
            self.assertIn("EVIDENCE_HANDOFF_INTEGRITY_FAIL", reasons)
            self.assertIn("WORKFLOW_TASK_NOT_DONE", reasons)
            self.assertIsNone(
                bridge.artifacts.find_latest_task_artifact(
                    "presentations",
                    result.task_id,
                    suffix=".json",
                )
            )

    def test_blocked_research_is_not_verified_but_remains_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, store, bridge = self.make_stack(
                Path(tmp),
                research_mode="blocked",
            )
            result = runner.create_and_run(
                "Blocked",
                "No usable evidence",
                live=False,
                output_format="source",
            )

            self.assertEqual(result.status, "blocked")
            self.assertEqual(
                store.get_task(result.task_id).status,
                TaskStatus.WAITING_HUMAN,
            )
            state = bridge.ledger.evaluate(result.task_id)
            self.assertFalse(state.verified)
            self.assertIn("evidence", state.failed_validators)
            self.assertIn("integration_test", state.failed_validators)

    def test_daily_failure_prevents_integration_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, store, bridge = self.make_stack(
                Path(tmp),
                daily_fail=True,
            )
            result = runner.create_and_run(
                "Daily failure",
                "Core stages succeed but report fails",
                live=False,
                output_format="source",
            )

            self.assertEqual(result.status, "failed")
            self.assertEqual(store.get_task(result.task_id).status, TaskStatus.FAILED)
            state = bridge.ledger.evaluate(result.task_id)
            self.assertFalse(state.verified)
            self.assertIn("integration_test", state.failed_validators)
            rows = bridge.ledger.export_results(result.task_id)
            self.assertIn(
                "WORKFLOW_DAILY_FAILED",
                [row["reason_code"] for row in rows],
            )

    def test_retry_can_verify_but_cannot_rewrite_first_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner, _, bridge = self.make_stack(
                root,
                research_mode="tampered",
            )
            task = runner.store.create_task("Retry", "First run fails")
            first = runner.run_task(
                task.task_id,
                live=False,
                output_format="source",
            )
            self.assertEqual(first.status, "failed")

            runner.research_agent._agent.mode = "ready"
            second = runner.run_task(
                task.task_id,
                live=False,
                output_format="source",
            )
            self.assertEqual(second.status, "completed")

            state = bridge.ledger.evaluate(task.task_id)
            self.assertTrue(state.verified)
            self.assertFalse(state.first_pass_verified)
            rows = bridge.ledger.export_results(task.task_id)
            evidence_attempts = [
                row["attempt"]
                for row in rows
                if row["validator"] == "evidence"
            ]
            self.assertEqual(evidence_attempts, [1, 2])

    def test_public_research_contract_is_explicitly_public_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            artifacts = ArtifactManager(root / "data")
            task = store.create_task("Public", "Public web research")
            bridge = RuntimeValidatorBridge(
                store,
                artifacts,
                confidentiality_mode="public-research",
                public_web=True,
            )
            bridge.begin(task.task_id)
            contract = store.task_contract_for_task(task.task_id)
            self.assertEqual(contract["sensitivity"], "public")
            self.assertEqual(contract["network_scope"], "allowlisted_egress")
            self.assertIn("web_gateway", contract["allowed_tools"])

    def test_confidential_mode_rejects_public_web_contract(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            artifacts = ArtifactManager(root / "data")
            with self.assertRaisesRegex(
                ValueError,
                "public_web runtime validation",
            ):
                RuntimeValidatorBridge(
                    store,
                    artifacts,
                    confidentiality_mode="confidential",
                    public_web=True,
                )


if __name__ == "__main__":
    unittest.main()
