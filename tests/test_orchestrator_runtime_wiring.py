from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import three_agent.orchestrator as orchestrator_module
from three_agent.config import AppConfig, GatewayConfig, LLMConfig


class OrchestratorRuntimeWiringTests(unittest.TestCase):
    @staticmethod
    def _config(root: Path) -> AppConfig:
        repo_root = Path(__file__).resolve().parents[1]
        return AppConfig(
            environment="test",
            test_mode_full_access=True,
            database_path=root / "tasks" / "tasks.db",
            artifact_root=root / "artifacts",
            profile_root=repo_root / "profiles",
            llm=LLMConfig("ollama", "http://127.0.0.1:11434", "", 5),
            internet_gateway=GatewayConfig(True, True, root / "internet.jsonl"),
            execution_gateway=GatewayConfig(True, True, root / "execution.jsonl"),
            raw={"adaptive_learning": {"runtime_retrieval": {"enabled": False}}},
            confidentiality_mode="confidential",
        )

    def test_runtime_gateways_are_initialized_once(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = self._config(root)
            recorder_cls = orchestrator_module.ResourceEventRecorder
            knowledge_gateway_cls = orchestrator_module.KnowledgeGatewayV3
            telemetry_env = {
                "WORKSPACE_INFERENCE_TELEMETRY": str(
                    root / "artifacts" / "activity" / "inference.jsonl"
                ),
                "WORKSPACE_RESOURCE_TELEMETRY": str(
                    root / "artifacts" / "activity" / "resource_events.jsonl"
                ),
            }

            with (
                patch.dict(os.environ, telemetry_env, clear=False),
                patch.object(
                    orchestrator_module,
                    "ResourceEventRecorder",
                    wraps=recorder_cls,
                ) as recorder_ctor,
                patch.object(
                    orchestrator_module,
                    "KnowledgeGatewayV3",
                    wraps=knowledge_gateway_cls,
                ) as knowledge_gateway_ctor,
            ):
                orchestrator = orchestrator_module.Orchestrator(config)

            self.assertEqual(recorder_ctor.call_count, 1)
            self.assertEqual(knowledge_gateway_ctor.call_count, 1)
            self.assertIsNotNone(orchestrator.resource_events)
            self.assertIsNotNone(orchestrator.knowledge_gateway)


if __name__ == "__main__":
    unittest.main()
