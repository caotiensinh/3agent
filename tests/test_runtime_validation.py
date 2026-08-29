import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.handoff_security import build_handoff_security_metadata
from three_agent.models import TaskStatus
from three_agent.runtime_validation import RuntimeValidationError, RuntimeValidatorBridge
from three_agent.store import TaskStore
from three_agent.task_contract import TaskContractCompiler
from three_agent.workflow import WorkflowRunner


class FakeResearchAgent:
    def __init__(self, mode: str = "ready"):
        self.mode = mode

    @staticmethod
    def _handoff(task_id: str, *, ready: bool = True) -> dict:
        payload = {
            "schema_version": "1.0",
            "task_id": task_id,
            "agent_id": "research",
            "presentation_ready": ready,
            "blockers": [] if ready else ["NO_VERIFIED_FACT"],
            "objective": "Test objective",
            "key_facts": (
                [
                    {
                        "fact_id": "F001",
                        "claim": "Verified fact",
                        "source_ids": ["S1"],
                        "confidence": "medium",
                    }
                ]
                if ready
                else []
            ),
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
                "usable_source_count": 1 if ready else 0,
                "verified_fact_count": 1 if ready else 0,
                "evidence_coverage": 1.0 if ready else 0.0,
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
            raise RuntimeError("research provider failed token=RESEARCH_SECRET")
        if self.mode == "blocked":
            handoff = self._handoff(task_id, ready=False)
            handoff_path = artifacts.write_research_handoff(task_id, handoff)
            store.set_status(task_id, TaskStatus.WAITING_HUMAN)
            return (handoff_path,)
        if self.mode == "status_only":
            folder = artifacts.root / "fake"
            folder.mkdir(parents=True, exist_ok=True)
            handoff_path = folder / f"{task_id}_handoff.json"
            handoff_path.write_text("{}\n", encoding="utf-8")
            store.set_status(task_id, TaskStatus.RESEARCH_COMPLETED)
            return (handoff_path,)

        handoff = self._handoff(task_id)
        if self.mode == "tampered":
            handoff["key_facts"][0]["claim"] = "Tampered after signing"
        handoff_path = artifacts.write_research_handoff(task_id, handoff)
        store.set_status(task_id, TaskStatus.RESEARCH_COMPLETED)
        return (handoff_path,)


class FakePresentationAgent:
    def __init__(self, mode: str = "valid"):
        self.mode = mode

    def run(self, task_id, store, artifacts, **kwargs):
        del kwargs
        if self.mode == "error":
            store.set_status(task_id, TaskStatus.FAILED)
            raise RuntimeError("presentation failed password=DECK_SECRET")

        handoff_path = artifacts.find_latest_task_artifact(
            "research", task_id, suffix="_handoff.json"
        )
        handoff_hash = hashlib.sha256(handoff_path.read_bytes()).hexdigest()
        valid = self.mode != "invalid"
        payload = {
            "schema_version": "presentation-artifact/v1",
            "task_id": task_id,
            "agent_id": "presentation",
            "status": "model_planned_evidence_validated",
            "source_research_handoff_sha256": f"sha256:{handoff_hash}",
            "plan": {
                "schema_version": "presentation-plan/v1",
                "title": "Fixture deck",
                "subtitle": "",
                "audience": "R&D internal",
                "purpose": "inform",
                "language": "ja",
                "slides": [],
            },
            "qa": {
                "schema_version": "presentation-qa/v1",
                "status": "pass" if valid else "failed",
                "errors": [] if valid else ["fixture failure"],
                "visible_facts_source_bounded": valid,
            },
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
            raise RuntimeError("daily failed api_key=DAILY_SECRET")
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
        presentation_mode: str = "valid",
        daily_fail: bool = False,
        confidentiality_mode: str = "confidential",
        public_web: bool = False,
    ):
        store = TaskStore(root / "tasks.db")
        store.initialize()
        artifacts = ArtifactManager(root / "data")
        bridge = RuntimeValidatorBridge(
            store,
            artifacts,
            confidentiality_mode=confidentiality_mode,
            public_web=public_web,
        )
        runner = WorkflowRunner(
            store,
            artifacts,
            FakeResearchAgent(research_mode),
            FakePresentationAgent(presentation_mode),
            FakeDailyAgent(daily_fail),
            validator_bridge=bridge,
        )
        return runner, store, bridge

    def test_successful_workflow_is_verified_before_done_on_first_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, store, bridge = self.make_stack(Path(tmp))
            result = runner.create_and_run(
                "Verified workflow",
                "Research, present and report",
                live=False,
                output_format="source",
            )

            self.assertEqual(result.status, "completed")
            self.assertEqual(store.get_task(result.task_id).status, TaskStatus.DONE)
            state = bridge.evaluate(result.task_id)
            self.assertTrue(state.verified)
            self.assertTrue(state.first_pass_verified)
            self.assertEqual(
                set(state.required_validators),
                {"policy", "evidence", "schema"},
            )
            self.assertEqual(
                set(state.passed_validators),
                {"policy", "evidence", "schema"},
            )
            manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
            self.assertTrue(manifest["verification"]["verified"])

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
            state = bridge.evaluate(result.task_id)
            self.assertFalse(state.verified)
            self.assertIn("evidence", state.failed_validators)
            self.assertIn("schema", state.missing_validators)
            rows = bridge.ledger.export_results(result.task_id)
            evidence_rows = [row for row in rows if row["validator"] == "evidence"]
            self.assertEqual(
                evidence_rows[-1]["reason_code"],
                "EVIDENCE_HANDOFF_INTEGRITY_FAIL",
            )
            self.assertTrue(
                all(
                    ref.startswith("sha256:")
                    for ref in evidence_rows[-1]["evidence_refs"]
                )
            )
            self.assertIsNone(
                bridge.artifacts.find_latest_task_artifact(
                    "presentations",
                    result.task_id,
                    suffix=".json",
                )
            )

    def test_blocked_research_is_not_verified_and_remains_blocked(self):
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
            state = bridge.evaluate(result.task_id)
            self.assertFalse(state.verified)
            self.assertIn("evidence", state.failed_validators)
            self.assertIn("schema", state.missing_validators)

    def test_status_alone_cannot_manufacture_evidence_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, store, bridge = self.make_stack(
                Path(tmp),
                research_mode="status_only",
            )
            result = runner.create_and_run(
                "Status only",
                "Do not trust stage status",
                live=False,
                output_format="source",
            )

            self.assertEqual(result.status, "failed")
            self.assertEqual(store.get_task(result.task_id).status, TaskStatus.FAILED)
            state = bridge.evaluate(result.task_id)
            self.assertFalse(state.verified)
            self.assertIn("evidence", state.failed_validators)

    def test_presentation_completed_status_cannot_override_invalid_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, store, bridge = self.make_stack(
                Path(tmp),
                presentation_mode="invalid",
            )
            result = runner.create_and_run(
                "Invalid presentation",
                "Reject invalid deterministic QA",
                live=False,
                output_format="source",
            )

            self.assertEqual(result.status, "failed")
            self.assertEqual(store.get_task(result.task_id).status, TaskStatus.FAILED)
            state = bridge.evaluate(result.task_id)
            self.assertFalse(state.verified)
            self.assertIn("schema", state.failed_validators)

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

            runner.research_agent.mode = "ready"
            second = runner.run_task(
                task.task_id,
                live=False,
                output_format="source",
            )
            self.assertEqual(second.status, "completed")

            state = bridge.evaluate(task.task_id)
            self.assertTrue(state.verified)
            self.assertFalse(state.first_pass_verified)
            rows = bridge.ledger.export_results(task.task_id)
            evidence_attempts = [
                row["attempt"]
                for row in rows
                if row["validator"] == "evidence"
            ]
            self.assertEqual(evidence_attempts, [1, 2])

    def test_daily_failure_does_not_mint_or_revoke_task_validator_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, store, bridge = self.make_stack(
                Path(tmp),
                daily_fail=True,
            )
            result = runner.create_and_run(
                "Daily failure",
                "Core task verifies but date-wide report fails",
                live=False,
                output_format="source",
            )

            self.assertEqual(result.status, "failed")
            self.assertEqual(store.get_task(result.task_id).status, TaskStatus.FAILED)
            self.assertIn("api_key=<redacted>", result.error or "")
            self.assertNotIn("DAILY_SECRET", result.error or "")
            state = bridge.evaluate(result.task_id)
            self.assertTrue(state.verified)
            self.assertEqual(
                set(state.passed_validators),
                {"policy", "evidence", "schema"},
            )

    def test_public_research_contract_is_explicitly_public_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            runner, store, bridge = self.make_stack(
                root,
                confidentiality_mode="public-research",
                public_web=True,
            )
            del runner
            task = store.create_task("Public", "Public web research")
            bridge.begin(task.task_id)
            contract = store.task_contract_for_task(task.task_id)
            self.assertEqual(contract["sensitivity"], "public")
            self.assertEqual(contract["network_scope"], "allowlisted_egress")
            self.assertIn("web_gateway", contract["allowed_tools"])
            self.assertEqual(
                set(contract["validators"]),
                {"policy", "evidence", "schema"},
            )

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

    def test_conflicting_prebound_contract_fails_closed_and_stays_immutable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            artifacts = ArtifactManager(root / "data")
            task = store.create_task("Immutable", "Reject contract mutation")
            old_contract = TaskContractCompiler().compile(
                task_id=task.task_id,
                task_type="general",
                sensitivity="internal",
            )
            old_digest = RuntimeValidatorBridge(
                store,
                artifacts,
                confidentiality_mode="internal",
                public_web=False,
            ).ledger.bind_contract(old_contract)

            bridge = RuntimeValidatorBridge(
                store,
                artifacts,
                confidentiality_mode="confidential",
                public_web=False,
            )
            with self.assertRaisesRegex(
                RuntimeValidationError,
                "TASK_CONTRACT_BIND_FAILED",
            ):
                bridge.begin(task.task_id)

            record = store.task_contract_record(task.task_id)
            self.assertEqual(record["contract_sha256"], old_digest)
            rows = bridge.ledger.export_results(task.task_id)
            policy = [row for row in rows if row["validator"] == "policy"]
            self.assertEqual(policy[-1]["status"], "failed")
            self.assertEqual(
                policy[-1]["reason_code"],
                "POLICY_CONTRACT_BIND_MISMATCH",
            )
            self.assertEqual(policy[-1]["evidence_refs"], [])


if __name__ == "__main__":
    unittest.main()
