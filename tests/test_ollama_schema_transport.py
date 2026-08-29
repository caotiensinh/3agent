import json
import unittest
from unittest.mock import patch

from three_agent.config import LLMConfig
from three_agent.llm import OllamaClient, _ollama_transport_schema
from three_agent.research_schemas import RESEARCH_SYNTHESIS_SCHEMA_V1
from three_agent.runtime_efficiency import (
    StructuredOutputValidationError,
    validate_json_schema_subset,
)


class _FakeResponse:
    def __init__(self, payload):
        self._payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self):
        return json.dumps(self._payload).encode("utf-8")


class OllamaStructuredSchemaTransportTests(unittest.TestCase):
    @staticmethod
    def _contains_limit_keyword(value):
        if isinstance(value, dict):
            if any(key in value for key in ("minLength", "maxLength", "minItems", "maxItems")):
                return True
            return any(
                OllamaStructuredSchemaTransportTests._contains_limit_keyword(item)
                for item in value.values()
            )
        if isinstance(value, list):
            return any(
                OllamaStructuredSchemaTransportTests._contains_limit_keyword(item)
                for item in value
            )
        return False

    def test_transport_schema_removes_only_ollama_grammar_incompatible_limits(self):
        authoritative = RESEARCH_SYNTHESIS_SCHEMA_V1
        transport = _ollama_transport_schema(authoritative)

        self.assertTrue(self._contains_limit_keyword(authoritative))
        self.assertFalse(self._contains_limit_keyword(transport))
        self.assertEqual(transport["type"], authoritative["type"])
        self.assertEqual(transport["required"], authoritative["required"])
        self.assertEqual(
            transport["properties"]["verified_facts"]["items"]["required"],
            authoritative["properties"]["verified_facts"]["items"]["required"],
        )
        self.assertEqual(
            transport["properties"]["verified_facts"]["items"]["properties"]["evidence_quotes"]["items"]["required"],
            authoritative["properties"]["verified_facts"]["items"]["properties"]["evidence_quotes"]["items"]["required"],
        )
        self.assertIsNot(transport, authoritative)

    def test_authoritative_post_validation_still_enforces_removed_limits(self):
        schema = {
            "type": "object",
            "additionalProperties": False,
            "required": ["items", "label"],
            "properties": {
                "items": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 2,
                    "items": {"type": "string", "maxLength": 3},
                },
                "label": {"type": "string", "minLength": 2, "maxLength": 4},
            },
        }
        transport = _ollama_transport_schema(schema)
        self.assertFalse(self._contains_limit_keyword(transport))

        validate_json_schema_subset({"items": ["abc"], "label": "ok"}, schema)
        with self.assertRaises(StructuredOutputValidationError):
            validate_json_schema_subset({"items": [], "label": "ok"}, schema)
        with self.assertRaises(StructuredOutputValidationError):
            validate_json_schema_subset({"items": ["abcd"], "label": "ok"}, schema)
        with self.assertRaises(StructuredOutputValidationError):
            validate_json_schema_subset({"items": ["abc"], "label": "x"}, schema)

    def test_ollama_request_uses_transport_schema_but_validates_authoritative_schema(self):
        captured = {}
        valid = {
            "verified_facts": [],
            "inferences": [],
            "conflicts": [],
            "unresolved": [],
            "conclusion": "ok",
            "recommended_next_actions": [],
        }

        def fake_urlopen(request, timeout):
            captured["body"] = json.loads(request.data.decode("utf-8"))
            return _FakeResponse({"response": json.dumps(valid)})

        config = LLMConfig(
            provider="ollama",
            base_url="http://127.0.0.1:11434",
            model="qwen-test",
            timeout_seconds=30,
            keep_alive="2m",
        )
        client = OllamaClient(config, telemetry=None)
        with patch("three_agent.llm.urlopen", side_effect=fake_urlopen):
            result = client.generate_json(
                "system",
                "user",
                schema=RESEARCH_SYNTHESIS_SCHEMA_V1,
                schema_id="workspace.research.synthesis/v1",
                think=False,
                num_predict=64,
            )

        self.assertEqual(result, valid)
        sent_schema = captured["body"]["format"]
        self.assertFalse(self._contains_limit_keyword(sent_schema))
        self.assertEqual(sent_schema["required"], RESEARCH_SYNTHESIS_SCHEMA_V1["required"])


if __name__ == "__main__":
    unittest.main()
