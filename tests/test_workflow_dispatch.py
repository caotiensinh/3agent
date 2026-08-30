import tempfile
import time
import unittest
from pathlib import Path

from three_agent.workflow_dispatch import (
    MAX_PARALLEL_DISPATCH,
    WorkflowCompiler,
    WorkflowDispatchError,
    WorkflowDispatchService,
    WorkflowDraftStore,
)


def standard_spec():
    return {
        "title": "Quarterly market brief",
        "summary": "Research evidence, prepare slides, verify, then attach daily report.",
        "nodes": [
            {
                "id": "research",
                "label": "Research evidence",
                "kind": "research",
                "objective": "Collect and synthesize approved evidence.",
                "depends_on": [],
                "requires_approval": False,
            },
            {
                "id": "presentation",
                "label": "Build presentation",
                "kind": "presentation",
                "objective": "Create a source-grounded presentation.",
                "depends_on": ["research"],
                "requires_approval": False,
            },
            {
                "id": "verify",
                "label": "Verify deliverable",
                "kind": "verify",
                "objective": "Run mandatory validators.",
                "depends_on": ["presentation"],
                "requires_approval": False,
            },
            {
                "id": "daily",
                "label": "Record daily report",
                "kind": "daily_report",
                "objective": "Attach evidence-backed daily reporting.",
                "depends_on": ["verify"],
                "requires_approval": False,
            },
        ],
    }


class FakeLLM:
    def __init__(self, payload):
        self.payload = payload
        self.calls = 0

    def generate_json(self, system_prompt, user_prompt, **kwargs):
        self.calls += 1
        self.system_prompt = system_prompt
        self.user_prompt = user_prompt
        self.kwargs = kwargs
        return self.payload


class FakeRunResult:
    def __init__(self):
        self.task_id = "task-1"
        self.status = "completed"
        self.task_status = "done"


class FakeOrchestrator:
    def __init__(self, payload):
        self.research_llm = FakeLLM(payload)
        self.calls = []

    def run_workflow(self, title, request, **kwargs):
        self.calls.append((title, request, kwargs))
        return FakeRunResult()


class WorkflowDispatchTests(unittest.TestCase):
    def test_standard_pipeline_compiles_with_one_model_call_and_is_executable(self):
        llm = FakeLLM(standard_spec())
        plan = WorkflowCompiler(llm).compile(
            "Research the market, create a presentation, verify it, and report."
        )
        self.assertEqual(llm.calls, 1)
        self.assertTrue(plan.execution_ready)
        self.assertEqual(
            plan.execution_template,
            "workspace-standard-deliverable-v1",
        )
        self.assertTrue(plan.approval_required)
        self.assertEqual(
            [list(wave) for wave in plan.waves],
            [["research"], ["presentation"], ["verify"], ["daily"]],
        )
        self.assertIn("flowchart TD", plan.mermaid)
        self.assertIn("<svg", plan.diagram_svg)
        self.assertTrue(plan.spec_sha256.startswith("sha256:"))

    def test_custom_parallel_dag_is_preview_only_and_batches_never_exceed_two(self):
        payload = {
            "title": "Parallel analysis",
            "summary": "Run three independent analyses then verify.",
            "nodes": [
                {
                    "id": "a",
                    "label": "A",
                    "kind": "analysis",
                    "objective": "Analyze A.",
                    "depends_on": [],
                    "requires_approval": False,
                },
                {
                    "id": "b",
                    "label": "B",
                    "kind": "analysis",
                    "objective": "Analyze B.",
                    "depends_on": [],
                    "requires_approval": False,
                },
                {
                    "id": "c",
                    "label": "C",
                    "kind": "analysis",
                    "objective": "Analyze C.",
                    "depends_on": [],
                    "requires_approval": False,
                },
                {
                    "id": "verify",
                    "label": "Verify",
                    "kind": "verify",
                    "objective": "Verify merged findings.",
                    "depends_on": ["a", "b", "c"],
                    "requires_approval": False,
                },
            ],
        }
        plan = WorkflowCompiler(FakeLLM(payload)).compile("Analyze three options.")
        self.assertFalse(plan.execution_ready)
        self.assertEqual(list(plan.waves[0]), ["a", "b", "c"])
        self.assertTrue(
            all(len(batch) <= MAX_PARALLEL_DISPATCH for batch in plan.dispatch_batches)
        )
        self.assertEqual(
            [list(batch) for batch in plan.dispatch_batches[:2]],
            [["a", "b"], ["c"]],
        )

    def test_cycle_and_unsupported_authority_like_node_kind_fail_closed(self):
        cyclic = {
            "title": "Cycle",
            "summary": "Invalid.",
            "nodes": [
                {
                    "id": "a",
                    "label": "A",
                    "kind": "analysis",
                    "objective": "A",
                    "depends_on": ["b"],
                    "requires_approval": False,
                },
                {
                    "id": "b",
                    "label": "B",
                    "kind": "verify",
                    "objective": "B",
                    "depends_on": ["a"],
                    "requires_approval": False,
                },
            ],
        }
        with self.assertRaisesRegex(WorkflowDispatchError, "cycle"):
            WorkflowCompiler(FakeLLM(cyclic)).compile("cycle")

        authority = {
            "title": "Danger",
            "summary": "Invalid.",
            "nodes": [
                {
                    "id": "shell",
                    "label": "Run shell",
                    "kind": "shell",
                    "objective": "Execute arbitrary shell.",
                    "depends_on": [],
                    "requires_approval": False,
                },
                {
                    "id": "verify",
                    "label": "Verify",
                    "kind": "verify",
                    "objective": "Verify.",
                    "depends_on": ["shell"],
                    "requires_approval": False,
                },
            ],
        }
        with self.assertRaisesRegex(WorkflowDispatchError, "unsupported node kind"):
            WorkflowCompiler(FakeLLM(authority)).compile("run commands")

    def test_svg_and_mermaid_do_not_embed_user_script_markup(self):
        payload = standard_spec()
        payload["nodes"][0]["label"] = '</text><script>alert("x")</script>'
        plan = WorkflowCompiler(FakeLLM(payload)).compile("diagram")
        self.assertNotIn("<script", plan.diagram_svg.lower())
        self.assertNotIn("<script", plan.mermaid.lower())
        self.assertIn("&lt;/text&gt;", plan.diagram_svg)

    def test_owner_scoped_draft_store_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan = WorkflowCompiler(FakeLLM(standard_spec())).compile("workflow")
            store = WorkflowDraftStore(Path(tmp))
            created = store.create("owner-a", "private description", plan)
            loaded = store.get("owner-a", created["workflow_id"])
            self.assertEqual(loaded["description"], "private description")
            with self.assertRaises(KeyError):
                store.get("owner-b", created["workflow_id"])

    def test_dispatch_requires_explicit_approval_and_reuses_existing_runner(self):
        with tempfile.TemporaryDirectory() as tmp:
            orchestrator = FakeOrchestrator(standard_spec())
            service = WorkflowDispatchService(orchestrator, Path(tmp))
            draft = service.compile(
                "owner-a",
                "Research the market, create slides, verify, and report.",
            )
            with self.assertRaisesRegex(WorkflowDispatchError, "approval"):
                service.dispatch(
                    "owner-a",
                    draft["workflow_id"],
                    approved=False,
                )

            queued = service.dispatch(
                "owner-a",
                draft["workflow_id"],
                approved=True,
                language="ja",
                output_format="pptx",
            )
            self.assertIn(queued["status"], {"queued", "running", "completed"})
            deadline = time.monotonic() + 2.0
            final = queued
            while time.monotonic() < deadline:
                final = service.status("owner-a", draft["workflow_id"])
                if final["status"] in {"completed", "failed"}:
                    break
                time.sleep(0.01)
            self.assertEqual(final["status"], "completed")
            self.assertEqual(len(orchestrator.calls), 1)
            self.assertTrue(orchestrator.calls[0][2]["live"])
            self.assertEqual(
                orchestrator.calls[0][2]["language"],
                "ja",
            )


if __name__ == "__main__":
    unittest.main()
