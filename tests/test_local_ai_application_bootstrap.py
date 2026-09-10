from __future__ import annotations

from types import SimpleNamespace
import unittest
from unittest.mock import patch

from three_agent import cli as cli_module
from three_agent.application_bootstrap import build_application_runtime, build_orchestrator
from three_agent.local_ai_composition import LocalAICompositionError
from three_agent.local_ai_gateway import LocalModelGatewayPolicyError


class FakeGenerationBackend:
    def __init__(self, runtime_model: str):
        self.config = SimpleNamespace(model=runtime_model)
        self.generate_calls = []
        self.json_calls = []

    def generate(self, system_prompt, user_prompt, **kwargs):
        self.generate_calls.append((system_prompt, user_prompt, dict(kwargs)))
        return "unused"

    def generate_json(self, system_prompt, user_prompt, **kwargs):
        self.json_calls.append((system_prompt, user_prompt, dict(kwargs)))
        return {"unused": True}


class FakeOrchestrator:
    created = []

    def __init__(self, config):
        self.config = config
        type(self).created.append(config)


class LocalAIApplicationBootstrapTests(unittest.TestCase):
    def setUp(self):
        FakeOrchestrator.created = []

    @staticmethod
    def config(local_ai_marker=None):
        raw = {}
        if local_ai_marker is not None:
            raw["local_ai"] = local_ai_marker
        return SimpleNamespace(raw=raw)

    @staticmethod
    def valid_local_ai():
        return {
            "enabled": True,
            "bindings": [
                {
                    "model_id": "trusted-small",
                    "runtime_id": "ollama-local",
                    "runtime_model": "runtime-small:latest",
                    "tier": "small",
                    "capabilities": ["generation.text", "generation.json"],
                }
            ],
        }

    @patch("three_agent.application_bootstrap.Orchestrator", FakeOrchestrator)
    def test_disabled_local_ai_is_exact_application_noop(self):
        backend = FakeGenerationBackend("runtime-small:latest")
        runtime = build_application_runtime(
            self.config({"enabled": False, "bindings": "ignored"}),
            generation_backends={"untrusted-extra": backend},
        )
        self.assertIsNone(runtime.local_model_gateway)
        self.assertIsInstance(runtime.orchestrator, FakeOrchestrator)
        self.assertEqual(len(FakeOrchestrator.created), 1)
        self.assertEqual(backend.generate_calls, [])
        self.assertEqual(backend.json_calls, [])

    @patch("three_agent.application_bootstrap.Orchestrator", FakeOrchestrator)
    def test_enabled_bootstrap_injects_only_trusted_precreated_backend(self):
        backend = FakeGenerationBackend("runtime-small:latest")
        extra = FakeGenerationBackend("extra:latest")
        runtime = build_application_runtime(
            self.config(self.valid_local_ai()),
            generation_backends={"trusted-small": backend, "untrusted-extra": extra},
        )
        self.assertIsNotNone(runtime.local_model_gateway)
        assert runtime.local_model_gateway is not None
        self.assertEqual(
            [binding.model_id for binding in runtime.local_model_gateway.registry.bindings()],
            ["trusted-small"],
        )
        with self.assertRaisesRegex(LocalModelGatewayPolicyError, "MODEL_NOT_TRUSTED"):
            runtime.local_model_gateway.registry.require(
                "untrusted-extra", "generation.text"
            )
        self.assertEqual(backend.generate_calls, [])
        self.assertEqual(backend.json_calls, [])
        self.assertEqual(extra.generate_calls, [])
        self.assertEqual(extra.json_calls, [])

    @patch("three_agent.application_bootstrap.Orchestrator", FakeOrchestrator)
    def test_invalid_enabled_config_fails_before_orchestrator_construction(self):
        with self.assertRaisesRegex(LocalAICompositionError, "LOCAL_AI_BINDINGS_REQUIRED"):
            build_application_runtime(self.config({"enabled": True, "bindings": []}))
        self.assertEqual(FakeOrchestrator.created, [])

    @patch("three_agent.application_bootstrap.Orchestrator", FakeOrchestrator)
    def test_missing_backend_fails_before_orchestrator_construction(self):
        with self.assertRaisesRegex(
            LocalAICompositionError, "LOCAL_AI_GENERATION_BACKEND_MISSING"
        ):
            build_application_runtime(self.config(self.valid_local_ai()))
        self.assertEqual(FakeOrchestrator.created, [])

    @patch("three_agent.cli.load_config")
    @patch("three_agent.application_bootstrap.Orchestrator", FakeOrchestrator)
    def test_cli_smoke_cannot_bypass_enabled_local_ai_fail_closed(self, load_config_mock):
        load_config_mock.return_value = self.config(self.valid_local_ai())
        with self.assertRaisesRegex(
            LocalAICompositionError, "LOCAL_AI_GENERATION_BACKEND_MISSING"
        ):
            cli_module.main(["smoke"])
        self.assertEqual(FakeOrchestrator.created, [])

    @patch("three_agent.application_bootstrap.Orchestrator", FakeOrchestrator)
    def test_binding_snapshot_is_not_changed_by_later_request_like_mutation(self):
        local_ai = self.valid_local_ai()
        config = self.config(local_ai)
        backend = FakeGenerationBackend("runtime-small:latest")
        runtime = build_application_runtime(
            config,
            generation_backends={"trusted-small": backend},
        )
        assert runtime.local_model_gateway is not None
        local_ai["bindings"][0]["runtime_model"] = "attacker-selected:latest"
        binding = runtime.local_model_gateway.registry.require(
            "trusted-small", "generation.text"
        )
        self.assertEqual(binding.runtime_model, "runtime-small:latest")

    @patch("three_agent.application_bootstrap.Orchestrator", FakeOrchestrator)
    def test_backward_compatible_facade_returns_orchestrator(self):
        orchestrator = build_orchestrator(self.config())
        self.assertIsInstance(orchestrator, FakeOrchestrator)
        self.assertEqual(len(FakeOrchestrator.created), 1)


if __name__ == "__main__":
    unittest.main()
