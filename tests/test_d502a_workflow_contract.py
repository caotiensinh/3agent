import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "benchmark-d502a-exact-dedupe.yml"


class D502AWorkflowContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_workflow_supports_manual_fallback_and_bounded_main_auto_trigger(self):
        self.assertIn("workflow_dispatch:", self.text)
        self.assertIn("\n  push:\n", self.text)
        self.assertIn("    branches:\n      - main\n", self.text)
        self.assertNotIn("\n  pull_request:", self.text)
        self.assertIn("github.event_name == 'push' || inputs.confirm == 'BENCHMARK'", self.text)

        trigger = self.text.split("  push:\n", 1)[1].split("\npermissions:", 1)[0]
        for path in (
            "src/three_agent/evidence_packing.py",
            "src/three_agent/agents/research_ranked.py",
            "src/three_agent/agents/research_compiled.py",
            "src/three_agent/d502a_benchmark.py",
            "benchmarks/d502a_exact_body_dedupe_task_set_v1.json",
            ".github/workflows/benchmark-d502a-exact-dedupe.yml",
        ):
            self.assertIn(path, trigger)
        self.assertNotIn("src/**", trigger)
        self.assertNotIn("**/*", trigger)

    def test_workflow_is_read_only_and_runs_only_on_dedicated_rtx5090_benchmark_lane(self):
        self.assertIn("permissions:\n  contents: read", self.text)
        self.assertIn("runs-on: [self-hosted, Linux, X64, rtx5090, workspace-benchmark]", self.text)
        self.assertNotIn("contents: write", self.text)
        self.assertNotIn("pull-requests: write", self.text)

    def test_exact_source_lineage_is_automatic_on_push_and_explicit_on_manual_dispatch(self):
        self.assertIn(
            "EXPECTED_SHA: ${{ github.event_name == 'workflow_dispatch' && inputs.source_ref || github.sha }}",
            self.text,
        )
        self.assertIn(
            "MODEL: ${{ github.event_name == 'workflow_dispatch' && inputs.model || 'qwen3:30b' }}",
            self.text,
        )
        self.assertIn("ref: ${{ env.EXPECTED_SHA }}", self.text)
        self.assertIn("persist-credentials: false", self.text)
        self.assertIn("test \"$(git rev-parse HEAD)\" = \"$EXPECTED_SHA\"", self.text)
        self.assertIn("python3 -m pip install --no-deps -e .", self.text)

    def test_one_click_lane_runs_both_variants_and_independent_verification(self):
        self.assertIn("three_agent.d502a_benchmark run", self.text)
        self.assertIn("three_agent.d502a_benchmark verify", self.text)
        self.assertIn("d502a_exact_body_dedupe_task_set_v1.json", self.text)
        self.assertIn("d502a-decision.json", self.text)
        self.assertIn("d502a-verification.json", self.text)
        self.assertIn("baseline-legacy-48k/benchmark.json", self.text)
        self.assertIn("exact-dedupe-legacy-48k/benchmark.json", self.text)

    def test_publishable_artifact_paths_do_not_include_raw_runtime_state(self):
        publish = self.text.split("Publish metadata-only D5-02a benchmark evidence", 1)[1]
        self.assertNotIn("/data/", publish)
        self.assertNotIn("/state/", publish)
        self.assertNotIn("inference.jsonl", publish)
        self.assertNotIn("resource_events.jsonl", publish)
        self.assertNotIn("internet.jsonl", publish)
        self.assertNotIn("execution.jsonl", publish)


if __name__ == "__main__":
    unittest.main()
