import json
import tempfile
import unittest
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.inference_scope import current_inference_scope, inference_scope
from three_agent.models import TaskStatus
from three_agent.runtime_efficiency import InferenceTelemetryRecorder, build_prompt_envelope
from three_agent.store import TaskStore
from three_agent.workflow import WorkflowRunner


class ScopedResearchAgent:
    def __init__(self, observed):
        self.observed = observed

    def run(self, task_id, store, artifacts, live=False):
        del live
        scope = current_inference_scope()
        self.observed.append(("research", scope.metadata() if scope else None))
        artifacts.root.mkdir(parents=True, exist_ok=True)
        path = artifacts.root / f"{task_id}-research.json"
        path.write_text("{}\n", encoding="utf-8")
        store.set_status(task_id, TaskStatus.RESEARCH_COMPLETED)
        return (path,)


class ScopedPresentationAgent:
    def __init__(self, observed):
        self.observed = observed

    def run(self, task_id, store, artifacts, **kwargs):
        del kwargs
        scope = current_inference_scope()
        self.observed.append(("presentation", scope.metadata() if scope else None))
        artifacts.root.mkdir(parents=True, exist_ok=True)
        path = artifacts.root / f"{task_id}-presentation.json"
        path.write_text("{}\n", encoding="utf-8")
        store.set_status(task_id, TaskStatus.PRESENTATION_COMPLETED)
        return (path,)


class UnscopedDailyAgent:
    def __init__(self, observed):
        self.observed = observed

    def run(self, date, store, artifacts, live=False):
        del store, live
        scope = current_inference_scope()
        self.observed.append(("daily", scope.metadata() if scope else None))
        artifacts.root.mkdir(parents=True, exist_ok=True)
        json_path = artifacts.root / f"{date}-daily.json"
        md_path = artifacts.root / f"{date}-daily.md"
        json_path.write_text("{}\n", encoding="utf-8")
        md_path.write_text("# daily\n", encoding="utf-8")
        return json_path, md_path


class InferenceScopeTests(unittest.TestCase):
    def test_nested_scope_restores_previous_authoritative_context(self):
        self.assertIsNone(current_inference_scope())
        with inference_scope("TASK-A", agent_id="research", stage="research"):
            self.assertEqual(current_inference_scope().task_id, "TASK-A")
            with inference_scope("TASK-B", agent_id="presentation", stage="presentation"):
                self.assertEqual(current_inference_scope().task_id, "TASK-B")
            self.assertEqual(current_inference_scope().task_id, "TASK-A")
        self.assertIsNone(current_inference_scope())

    def test_telemetry_records_scope_metadata_without_prompt_or_response(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "inference.jsonl"
            recorder = InferenceTelemetryRecorder(path)
            envelope = build_prompt_envelope("SECRET SYSTEM", "SECRET USER")
            with inference_scope("TASK-123", agent_id="research", stage="research"):
                recorder.record(
                    model="qwen-test",
                    envelope=envelope,
                    structured=True,
                    schema_id="schema-v1",
                    payload={
                        "prompt_eval_count": 12,
                        "eval_count": 3,
                        "response": "SECRET RESPONSE",
                    },
                    success=True,
                    wall_duration_ms=1.0,
                )
            raw = path.read_text(encoding="utf-8")
            row = json.loads(raw)
            self.assertEqual(row["schema_version"], "workspace-inference-telemetry/v2")
            self.assertEqual(
                row["task_scope"],
                {"task_id": "TASK-123", "agent_id": "research", "stage": "research"},
            )
            self.assertNotIn("SECRET SYSTEM", raw)
            self.assertNotIn("SECRET USER", raw)
            self.assertNotIn("SECRET RESPONSE", raw)

    def test_workflow_scopes_task_agents_but_not_date_wide_daily_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            store = TaskStore(root / "tasks.db")
            store.initialize()
            artifacts = ArtifactManager(root / "data")
            observed = []
            runner = WorkflowRunner(
                store,
                artifacts,
                ScopedResearchAgent(observed),
                ScopedPresentationAgent(observed),
                UnscopedDailyAgent(observed),
            )
            result = runner.create_and_run(
                "Scoped workflow",
                "Verify trusted inference attribution",
                live=False,
                output_format="source",
            )
            self.assertEqual(result.status, "completed")
            self.assertEqual(observed[0][0], "research")
            self.assertEqual(observed[0][1]["task_id"], result.task_id)
            self.assertEqual(observed[0][1]["agent_id"], "research")
            self.assertEqual(observed[1][0], "presentation")
            self.assertEqual(observed[1][1]["task_id"], result.task_id)
            self.assertEqual(observed[1][1]["agent_id"], "presentation")
            self.assertEqual(observed[2], ("daily", None))

    def test_invalid_scope_identifiers_fail_closed(self):
        with self.assertRaises(ValueError):
            with inference_scope("TASK WITH SPACES", agent_id="research", stage="research"):
                pass
        with self.assertRaises(ValueError):
            with inference_scope("TASK-1", agent_id="", stage="research"):
                pass


if __name__ == "__main__":
    unittest.main()
