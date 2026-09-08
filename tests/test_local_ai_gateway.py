from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
import unittest

from three_agent.local_ai_gateway import (
    LocalAIModelBinding,
    LocalAIModelBindingRegistry,
    LocalModelGateway,
    LocalModelGatewayError,
    LocalModelGatewayPolicyError,
    canonical_binding_fingerprint,
)
from three_agent.task_contract import ModelPolicy, TaskContractCompiler


class FakeGenerationBackend:
    def __init__(self, runtime_model: str):
        self.config = SimpleNamespace(model=runtime_model)
        self.generate_calls = []
        self.json_calls = []

    def generate(self, system_prompt, user_prompt, **kwargs):
        self.generate_calls.append((system_prompt, user_prompt, dict(kwargs)))
        return "local answer"

    def generate_json(self, system_prompt, user_prompt, **kwargs):
        self.json_calls.append((system_prompt, user_prompt, dict(kwargs)))
        return {"status": "ok"}


class FakeEmbeddingBackend:
    def __init__(self, model_id: str):
        self.model_id = model_id
        self.query_calls = []
        self.document_calls = []

    def encode_queries(self, inputs):
        self.query_calls.append(list(inputs))
        return [[1.0, 0.0] for _ in inputs]

    def encode_documents(self, inputs):
        self.document_calls.append(list(inputs))
        return [[0.0, 1.0] for _ in inputs]


class LocalModelGatewayTests(unittest.TestCase):
    def setUp(self):
        self.compiler = TaskContractCompiler()
        self.generation_binding = LocalAIModelBinding(
            model_id="security-analyst",
            runtime_id="ollama-local",
            runtime_model="foundation-sec:8b",
            tier="specialist",
            capabilities=("generation.text", "generation.json"),
        )
        self.embedding_binding = LocalAIModelBinding(
            model_id="security-retrieval",
            runtime_id="huggingface-local",
            runtime_model="securebert-biencoder",
            tier="small",
            capabilities=(
                "retrieval.embedding.query",
                "retrieval.embedding.document",
            ),
        )

    def analysis_contract(self, *, output_schema=None):
        return self.compiler.compile(
            task_id="task-analysis",
            task_type="analysis",
            sensitivity="internal",
            risk_level="low",
            output_schema=output_schema,
        )

    def retrieval_contract(self):
        return self.compiler.compile(
            task_id="task-retrieval",
            task_type="retrieval",
            sensitivity="internal",
            risk_level="low",
        )

    def gateway(self):
        generation = FakeGenerationBackend("foundation-sec:8b")
        embedding = FakeEmbeddingBackend("securebert-biencoder")
        gateway = LocalModelGateway(
            LocalAIModelBindingRegistry(
                [self.generation_binding, self.embedding_binding]
            ),
            generation_backends={"security-analyst": generation},
            embedding_backends={"security-retrieval": embedding},
        )
        return gateway, generation, embedding

    def test_untrusted_model_fails_before_backend_invocation(self):
        gateway, generation, _ = self.gateway()
        with self.assertRaisesRegex(LocalModelGatewayPolicyError, "MODEL_NOT_TRUSTED"):
            gateway.generate(
                self.analysis_contract(),
                "user-supplied-model",
                "system",
                "incident",
            )
        self.assertEqual(generation.generate_calls, [])

    def test_capability_mismatch_fails_before_backend_invocation(self):
        gateway, generation, _ = self.gateway()
        with self.assertRaisesRegex(
            LocalModelGatewayPolicyError, "MODEL_CAPABILITY_NOT_TRUSTED"
        ):
            gateway.generate(
                self.analysis_contract(),
                "security-retrieval",
                "system",
                "incident",
            )
        self.assertEqual(generation.generate_calls, [])

    def test_model_tier_cannot_exceed_task_contract_authority(self):
        contract = self.compiler.compile(
            task_id="task-small",
            task_type="classification",
            sensitivity="internal",
            risk_level="low",
        )
        contract = replace(
            contract,
            model_policy=ModelPolicy(
                initial_tier="small",
                max_tier="small",
                escalation_allowed=False,
                confidence_floor=contract.model_policy.confidence_floor,
                trusted_local_only=True,
            ),
        ).validate()
        gateway, generation, _ = self.gateway()
        with self.assertRaisesRegex(
            LocalModelGatewayPolicyError, "MODEL_TIER_EXCEEDS_CONTRACT_MAX"
        ):
            gateway.generate(contract, "security-analyst", "system", "incident")
        self.assertEqual(generation.generate_calls, [])

    def test_no_llm_contract_cannot_invoke_local_model(self):
        contract = self.compiler.compile(
            task_id="task-no-llm",
            task_type="retrieval",
            sensitivity="internal",
            risk_level="low",
            deterministic_only=True,
        )
        gateway, _, embedding = self.gateway()
        with self.assertRaisesRegex(
            LocalModelGatewayPolicyError, "MODEL_TIER_EXCEEDS_CONTRACT_MAX"
        ):
            gateway.embed_queries(
                contract,
                "security-retrieval",
                ["camera offline"],
            )
        self.assertEqual(embedding.query_calls, [])

    def test_generate_binds_output_budget_and_trust_domain(self):
        gateway, generation, _ = self.gateway()
        contract = self.analysis_contract()
        result = gateway.generate(
            contract,
            "security-analyst",
            "system",
            "incident evidence",
            num_predict=512,
            think=True,
            temperature=0.1,
        )
        self.assertEqual(result.value, "local answer")
        self.assertEqual(result.task_id, contract.task_id)
        self.assertEqual(result.model_id, "security-analyst")
        self.assertEqual(result.capability, "generation.text")
        self.assertTrue(result.authority_fingerprint.startswith("sha256:"))
        _, _, kwargs = generation.generate_calls[0]
        self.assertEqual(kwargs["num_predict"], 512)
        self.assertTrue(kwargs["think"])
        self.assertEqual(kwargs["temperature"], 0.1)
        self.assertEqual(kwargs["trust_domain"], contract.cache_policy.trust_domain)

    def test_generation_cannot_exceed_contract_output_budget(self):
        gateway, generation, _ = self.gateway()
        contract = self.analysis_contract()
        with self.assertRaisesRegex(
            LocalModelGatewayPolicyError, "GENERATION_OUTPUT_BUDGET_EXCEEDED"
        ):
            gateway.generate(
                contract,
                "security-analyst",
                "system",
                "incident",
                num_predict=contract.generation_budget.max_output_tokens + 1,
            )
        self.assertEqual(generation.generate_calls, [])

    def test_structured_generation_requires_task_contract_schema(self):
        gateway, generation, _ = self.gateway()
        with self.assertRaisesRegex(
            LocalModelGatewayPolicyError, "TASK_CONTRACT_OUTPUT_SCHEMA_REQUIRED"
        ):
            gateway.generate_json(
                self.analysis_contract(),
                "security-analyst",
                "system",
                "incident",
            )
        self.assertEqual(generation.json_calls, [])

    def test_structured_generation_uses_authoritative_contract_schema(self):
        schema = {
            "type": "object",
            "properties": {"status": {"type": "string"}},
            "required": ["status"],
            "additionalProperties": False,
        }
        gateway, generation, _ = self.gateway()
        contract = self.analysis_contract(output_schema=schema)
        result = gateway.generate_json(
            contract,
            "security-analyst",
            "system",
            "incident",
            num_predict=256,
            schema_id="security-analysis-v1",
        )
        self.assertEqual(result.value, {"status": "ok"})
        _, _, kwargs = generation.json_calls[0]
        self.assertEqual(kwargs["schema"], schema)
        self.assertEqual(kwargs["schema_id"], "security-analysis-v1")
        self.assertEqual(kwargs["num_predict"], 256)

    def test_generation_backend_model_identity_must_match_binding(self):
        bad = FakeGenerationBackend("different-model:8b")
        gateway = LocalModelGateway(
            LocalAIModelBindingRegistry([self.generation_binding]),
            generation_backends={"security-analyst": bad},
        )
        with self.assertRaisesRegex(
            LocalModelGatewayError, "GENERATION_BACKEND_MODEL_MISMATCH"
        ):
            gateway.generate(
                self.analysis_contract(),
                "security-analyst",
                "system",
                "incident",
            )
        self.assertEqual(bad.generate_calls, [])

    def test_embedding_backend_model_identity_must_match_binding(self):
        bad = FakeEmbeddingBackend("different-embedding")
        gateway = LocalModelGateway(
            LocalAIModelBindingRegistry([self.embedding_binding]),
            embedding_backends={"security-retrieval": bad},
        )
        with self.assertRaisesRegex(
            LocalModelGatewayError, "EMBEDDING_BACKEND_MODEL_MISMATCH"
        ):
            gateway.embed_queries(
                self.retrieval_contract(),
                "security-retrieval",
                ["switch loop"],
            )
        self.assertEqual(bad.query_calls, [])

    def test_query_and_document_embedding_use_distinct_backend_methods(self):
        gateway, _, embedding = self.gateway()
        contract = self.retrieval_contract()
        query = gateway.embed_queries(
            contract,
            "security-retrieval",
            ["PoE failure"],
        )
        documents = gateway.embed_documents(
            contract,
            "security-retrieval",
            ["Switch port reports no power"],
        )
        self.assertEqual(query.value, [[1.0, 0.0]])
        self.assertEqual(documents.value, [[0.0, 1.0]])
        self.assertEqual(embedding.query_calls, [["PoE failure"]])
        self.assertEqual(embedding.document_calls, [["Switch port reports no power"]])

    def test_gateway_metadata_contains_no_prompt_content(self):
        gateway, _, _ = self.gateway()
        secret_marker = "PRIVATE-INCIDENT-MARKER"
        result = gateway.generate(
            self.analysis_contract(),
            "security-analyst",
            "system",
            secret_marker,
        )
        metadata = result.metadata()
        self.assertNotIn(secret_marker, repr(metadata))
        self.assertFalse(metadata["runtime_download"])
        self.assertFalse(metadata["raw_prompt_persisted_by_gateway"])
        self.assertEqual(metadata["authority_source"], "TaskContract")

    def test_binding_fingerprint_is_stable_independent_of_registration_order(self):
        left = canonical_binding_fingerprint(
            [self.generation_binding, self.embedding_binding]
        )
        right = canonical_binding_fingerprint(
            [self.embedding_binding, self.generation_binding]
        )
        self.assertEqual(left, right)
        self.assertTrue(left.startswith("sha256:"))

    def test_gateway_source_contains_no_runtime_discovery_or_model_acquisition(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "three_agent"
            / "local_ai_gateway.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "huggingface_hub",
            "snapshot_download",
            "hf_hub_download",
            "urlopen(",
            "/api/pull",
            "/api/create",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("TaskModelAuthority.from_contract", source)
        self.assertIn("authority.require_tier", source)


if __name__ == "__main__":
    unittest.main()
