import json
import tempfile
import unittest
from pathlib import Path

from three_agent.artifacts import ArtifactManager
from three_agent.models import TaskStatus
from three_agent.store import TaskStore
from three_agent.workflow import WorkflowRunner


class FakeResearchAgent:
    def __init__(self, calls: list[str], mode: str = "success"):
        self.calls = calls
        self.mode = mode

    def run(self, task_id, store, artifacts, live=False):
        self.calls.append("research")
        if self.mode == "error":
            raise RuntimeError("provider failed token=RESEARCH_SECRET")
        folder = artifacts.root / "fake"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{task_id}-research.json"
        path.write_text("{}\n", encoding="utf-8")
        status = (
            TaskStatus.WAITING_HUMAN
            if self.mode == "blocked"
            else TaskStatus.RESEARCH_COMPLETED
        )
        store.set_status(task_id, status)
        return (path,)


class FakePresentationAgent:
    def __init__(self, calls: list[str], mode: str = "success"):
        self.calls = calls
        self.mode = mode

    def run(self, task_id, store, artifacts, **kwargs):
        del kwargs
        self.calls.append("presentation")
        if self.mode == "error":
            store.set_status(task_id, TaskStatus.FAILED)
            raise RuntimeError("render failed password=DECK_SECRET")
        folder = artifacts.root / "fake"
        folder.mkdir(parents=True, exist_ok=True)
        path = folder / f"{task_id}-presentation.json"
        path.write_text("{}\n", encoding="utf-8")
        store.set_status(task_id, TaskStatus.PRESENTATION_COMPLETED)
        return (path,)


class FakeDailyAgent:
    def __init__(self, calls: list[str], fail: bool = False):
        self.calls = calls
        self.fail = fail
        self.observed_status = None

    def run(self, date, store, artifacts, live=False):
        del live
        self.calls.append("daily")
        tasks = store.list_tasks()
        self.observed_status = tasks[0].status if tasks else None
        if self.fail:
            raise RuntimeError("daily failed api_key=DAILY_SECRET")
        folder = artifacts.root / "daily_reports"
        folder.mkdir(parents=True, exist_ok=True)
        json_path = folder / f"{date}.json"
        md_path = folder / f"{date}.md"
        json_path.write_text("{}\n", encoding="utf-8")
        md_path.write_text("# Daily\n", encoding="utf-8")
        return json_path, md_path


class WorkflowRunnerTests(unittest.TestCase):
    def make_runner(self, root: Path, research_mode="success", presentation_mode="success", daily_fail=False):
        store = TaskStore(root / "tasks.db")
        store.initialize()
        artifacts = ArtifactManager(root / "data")
        calls: list[str] = []
        daily = FakeDailyAgent(calls, fail=daily_fail)
        runner = WorkflowRunner(
            store,
            artifacts,
            FakeResearchAgent(calls, mode=research_mode),
            FakePresentationAgent(calls, mode=presentation_mode),
            daily,
        )
        return runner, store, calls, daily

    def test_success_runs_all_agents_and_finishes_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, store, calls, daily = self.make_runner(Path(tmp))
            result = runner.create_and_run(
                "E2E task",
                "Research and present this topic",
                live=True,
                output_format="source",
            )

            self.assertEqual(calls, ["research", "presentation", "daily"])
            self.assertEqual(result.status, "completed")
            self.assertEqual(result.task_status, TaskStatus.DONE.value)
            self.assertEqual(store.get_task(result.task_id).status, TaskStatus.DONE)
            self.assertEqual(daily.observed_status, TaskStatus.DONE)
            self.assertTrue(result.research_artifacts)
            self.assertTrue(result.presentation_artifacts)
            self.assertTrue(result.daily_report_artifacts)

            manifest = json.loads(Path(result.manifest_path).read_text(encoding="utf-8"))
            self.assertEqual(manifest["schema_version"], "workflow-run/v1")
            self.assertEqual(manifest["business_stage"], "task_completed")
            self.assertIsNone(manifest["error"])

    def test_live_success_unloads_each_agent_model_in_stage_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, _, calls, _ = self.make_runner(Path(tmp))
            lifecycle: list[str] = []

            class LifecycleLLM:
                def __init__(self, role: str):
                    self.role = role

                def unload(self):
                    lifecycle.append(self.role)

            runner.research_agent.llm = LifecycleLLM("research")
            runner.presentation_agent.llm = LifecycleLLM("presentation")
            runner.daily_agent.llm = LifecycleLLM("daily")

            result = runner.create_and_run("Lifecycle", "Sequential model lifecycle", live=True)
            self.assertEqual(result.status, "completed")
            self.assertEqual(calls, ["research", "presentation", "daily"])
            self.assertEqual(lifecycle, ["research", "presentation", "daily"])

    def test_research_gate_blocks_presentation_but_daily_still_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, store, calls, daily = self.make_runner(Path(tmp), research_mode="blocked")
            result = runner.create_and_run("Blocked task", "Insufficient evidence", live=True)

            self.assertEqual(calls, ["research", "daily"])
            self.assertEqual(result.status, "blocked")
            self.assertEqual(result.task_status, TaskStatus.WAITING_HUMAN.value)
            self.assertEqual(store.get_task(result.task_id).status, TaskStatus.WAITING_HUMAN)
            self.assertEqual(daily.observed_status, TaskStatus.WAITING_HUMAN)
            self.assertEqual(result.presentation_artifacts, [])
            self.assertTrue(result.daily_report_artifacts)

    def test_presentation_failure_is_reported_and_daily_still_runs(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, store, calls, daily = self.make_runner(Path(tmp), presentation_mode="error")
            result = runner.create_and_run("Failure task", "Trigger renderer failure", live=True)

            self.assertEqual(calls, ["research", "presentation", "daily"])
            self.assertEqual(result.status, "failed")
            self.assertEqual(store.get_task(result.task_id).status, TaskStatus.FAILED)
            self.assertEqual(daily.observed_status, TaskStatus.FAILED)
            self.assertIn("password=<redacted>", result.error or "")
            self.assertNotIn("DECK_SECRET", result.error or "")

    def test_daily_failure_changes_workflow_to_failed_and_redacts_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            runner, store, calls, _ = self.make_runner(Path(tmp), daily_fail=True)
            result = runner.create_and_run("Daily fail", "Complete first two agents", live=True)

            self.assertEqual(calls, ["research", "presentation", "daily"])
            self.assertEqual(result.status, "failed")
            self.assertEqual(store.get_task(result.task_id).status, TaskStatus.FAILED)
            self.assertIn("api_key=<redacted>", result.error or "")
            self.assertNotIn("DAILY_SECRET", result.error or "")
            self.assertTrue(Path(result.manifest_path).exists())


if __name__ == "__main__":
    unittest.main()
