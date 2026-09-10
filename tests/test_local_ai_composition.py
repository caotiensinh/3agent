from __future__ import annotations

from types import SimpleNamespace
import unittest

from three_agent.local_ai_composition import (
    LocalAICompositionError,
    build_local_model_gateway,
    local_ai_composition_spec,
)
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


class FakeEmbeddingBackend:
    def __init__(self, model_id: str):
        self.model_id = model_id
        self.query_calls = []
        self.document_calls = []

    def encode_queries(self, inputs):
        self.query_calls.append(list(inputs))
        return []

    def encode_documents(self, inputs):
        self.document_calls.append(list(inputs))
        return []


class LocalAICompositionTests(unittest.TestCase):
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
                },
                {
                    "model_id": "trusted-embedding",
                    "runtime_id": "huggingface-local",
                    "runtime_model": "runtime-embedding",
                    "tier": "small",
                    "capabilities": [
                        "retrieval.embedding.query",
                        "retrieval.embedding.document",
                    ],
                },
            ],
        }

    def backends(self):
        generation = FakeGenerationBackend("runtime-small:latest")
        embedding = FakeEmbeddingBackend("runtime-embedding")
        return generation, embedding

    def test_absent_local_ai_is_disabled(self):
        self.assertIsNone(build_local_model_gateway(self.config()))

    def test_disabled_local_ai_short_circuits_without_parsing_bindings(self):
        config = self.config({"enabled": False, "bindings": "not-a-list"})
        self.assertIsNone(build_local_model_gateway(config))

    def test_enabled_must_be_boolean(self):
        with self.assertRaisesRegex(LocalAICompositionError, "LOCAL_AI_CONFIG_INVALID"):
            build_local_model_gateway(self.config({"enabled": "true", "bindings": []}))

    def test_enabled_requires_non_empty_binding_array(self):
        with self.assertRaisesRegex(
            LocalAICompositionError, "LOCAL_AI_BINDINGS_REQUIRED"
        ):
            build_local_model_gateway(self.config({"enabled": True, "bindings": []}))

    def test_binding_schema_rejects_unknown_keys(self):
        raw = self.valid_local_ai()
        raw["bindings"][0]["download"] = True
        with self.assertRaisesRegex(
            LocalAICompositionError, "LOCAL_AI_BINDING_INVALID"
        ):
            local_ai_composition_spec(self.config(raw))

    def test_duplicate_normalized_model_ids_fail_closed(self):
        raw = self.valid_local_ai()
        duplicate = dict(raw["bindings"][0])
        duplicate["model_id"] = "TRUSTED-SMALL"
        raw["bindings"].append(duplicate)
        with self.assertRaisesRegex(
            LocalAICompositionError, "LOCAL_AI_BINDING_DUPLICATE"
        ):
            local_ai_composition_spec(self.config(raw))

    def test_unsupported_tier_and_capability_are_rejected_by_gateway_policy(self):
        raw = self.valid_local_ai()
        raw["bindings"][0]["tier"] = "unbounded"
        with self.assertRaisesRegex(
            LocalAICompositionError, "LOCAL_AI_BINDING_INVALID"
        ):
            local_ai_composition_spec(self.config(raw))

        raw = self.valid_local_ai()
        raw["bindings"][0]["capabilities"] = ["runtime.download"]
        with self.assertRaisesRegex(
            LocalAICompositionError, "LOCAL_AI_BINDING_INVALID"
        ):
            local_ai_composition_spec(self.config(raw))

    def test_duplicate_capabilities_are_rejected(self):
        raw = self.valid_local_ai()
        raw["bindings"][0]["capabilities"] = [
            "generation.text",
            "generation.text",
        ]
        with self.assertRaisesRegex(
            LocalAICompositionError, "LOCAL_AI_BINDING_INVALID"
        ):
            local_ai_composition_spec(self.config(raw))

    def test_required_generation_backend_must_be_injected(self):
        _, embedding = self.backends()
        with self.assertRaisesRegex(
            LocalAICompositionError, "LOCAL_AI_GENERATION_BACKEND_MISSING"
        ):
            build_local_model_gateway(
                self.config(self.valid_local_ai()),
                embedding_backends={"trusted-embedding": embedding},
            )

    def test_required_embedding_backend_must_be_injected(self):
        generation, _ = self.backends()
        with self.assertRaisesRegex(
            LocalAICompositionError, "LOCAL_AI_EMBEDDING_BACKEND_MISSING"
        ):
            build_local_model_gateway(
                self.config(self.valid_local_ai()),
                generation_backends={"trusted-small": generation},
            )

    def test_valid_composition_is_immutable_and_does_not_call_backends(self):
        generation, embedding = self.backends()
        config = self.config(self.valid_local_ai())
        spec = local_ai_composition_spec(config)
        self.assertIsNotNone(spec)
        assert spec is not None
        self.assertEqual(len(spec.bindings), 2)
        self.assertTrue(spec.fingerprint.startswith("sha256:"))
        self.assertFalse(spec.snapshot()["runtime_download"])

        gateway = build_local_model_gateway(
            config,
            generation_backends={
                "trusted-small": generation,
                "untrusted-extra": FakeGenerationBackend("extra"),
            },
            embedding_backends={"trusted-embedding": embedding},
        )
        self.assertIsNotNone(gateway)
        assert gateway is not None
        self.assertEqual(generation.generate_calls, [])
        self.assertEqual(generation.json_calls, [])
        self.assertEqual(embedding.query_calls, [])
        self.assertEqual(embedding.document_calls, [])
        self.assertEqual(
            [item.model_id for item in gateway.registry.bindings()],
            ["trusted-embedding", "trusted-small"],
        )
        with self.assertRaisesRegex(
            LocalModelGatewayPolicyError, "MODEL_NOT_TRUSTED"
        ):
            gateway.registry.require("untrusted-extra", "generation.text")


if __name__ == "__main__":
    unittest.main()
