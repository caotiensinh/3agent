from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/live-chat-multiturn-acceptance.yml"


class LiveMultiturnWorkflowContractTests(unittest.TestCase):
    def test_self_hosted_live_workflow_is_main_only_and_not_pr_triggered(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("workflow_dispatch:", text)
        self.assertIn("branches: [main]", text)
        self.assertNotIn("pull_request:", text)
        self.assertIn("self-hosted", text)
        self.assertIn("linux", text)
        self.assertIn("x64", text)
        self.assertIn("rtx5090", text)

    def test_live_workflow_is_read_only_to_host_runtime(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        for forbidden in (
            "systemctl restart",
            "systemctl stop",
            "systemctl start",
            "systemctl enable",
            "systemctl disable",
            "apt install",
            "apt-get install",
            "pip install",
            "git reset --hard",
            "git clean -",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_gpu_inventory_is_verified_inside_the_trusted_job(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("nvidia-smi", text)
        self.assertIn("RTX 5090", text)
        self.assertIn("gpu_count", text)
        self.assertIn("EXPECTED_GPU_COUNT", text)

    def test_acceptance_config_defaults_to_exact_checkout_not_runner_home(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("WORKSPACE_CONFIG", text)
        self.assertIn("config/local.json", text)
        self.assertNotIn("$HOME/3agent/config/local.json", text)

    def test_live_workflow_isolates_resource_runtime_per_execution(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("THREE_AGENT_RUNTIME_DIR", text)
        self.assertIn("runner.temp", text)

    def test_failure_report_path_is_exported_before_live_command(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        export_index = text.index("WORKSPACE_CHAT_ACCEPTANCE_REPORT")
        command_index = text.index("workspace-chat-multiturn-acceptance")
        self.assertLess(export_index, command_index)

    def test_report_is_sanitized_and_artifact_is_bounded(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("if-no-files-found: error", text)
        self.assertIn("retention-days: 14", text)

    def test_portable_gate_tracks_live_acceptance_contract_changes(self):
        text = (ROOT / ".github/workflows/portable-deploy-ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertGreaterEqual(
            text.count("'.github/workflows/live-chat-multiturn-acceptance.yml'"),
            2,
        )
        self.assertGreaterEqual(
            text.count("'tests/test_live_multiturn_workflow_contract.py'"),
            2,
        )
        self.assertIn("workflow_dispatch:", text)

    def test_package_routes_live_acceptance_to_current_contract_service(self):
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('version = "1!0.0.2"', text)
        self.assertIn(
            'workspace-chat-multiturn-acceptance = "three_agent.chat_multiturn_acceptance_v2:main"',
            text,
        )
        self.assertIn('workspace-chat = "three_agent.chat_gateway_v18:main"', text)
        self.assertIn('three-agent-chat = "three_agent.chat_gateway_v18:main"', text)
        self.assertTrue((ROOT / "src/three_agent/chat_multiturn_acceptance_v2.py").is_file())
        v18 = (ROOT / "src/three_agent/chat_gateway_v18.py").read_text(encoding="utf-8")
        self.assertIn("CurrentRequestProjectChatService", v18)
        self.assertIn("chat_context_v2", v18)
        self.assertTrue((ROOT / "src/three_agent/chat_gateway_v17.py").is_file())


if __name__ == "__main__":
    unittest.main()
