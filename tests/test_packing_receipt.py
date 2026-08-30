import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from three_agent.agents import ResearchAgent
from three_agent.benchmark_snapshot import effective_config_fingerprint
from three_agent.config import AppConfig, GatewayConfig, LLMConfig, ModelPolicyConfig
from three_agent.evidence_packing import (
    DEFAULT_SYNTHESIS_CONTEXT_BUDGET_CHARS,
    EvidencePackingPolicy,
    PACKING_RECEIPT_SCHEMA,
    pack_evidence_sources,
    resolve_evidence_packing_policy,
)
from three_agent.handoff_security import verify_handoff_security_metadata
from three_agent.research_quality import build_handoff, synthesis_context_proxy_accounting


class Source:
    def __init__(self, source_id: str, text: str, title: str = "T"):
        self.source_id = source_id
        self.title = title
        self.url = f"https://example.test/{source_id}"
        self.extracted_text = text
        self.fetch_status = "ok"


class FakeLLM:
    def generate_json(self, *args, **kwargs):
        return {
            "verified_facts": [{"claim": "Fact", "source_ids": ["S1"], "evidence_quotes": []}],
            "inferences": [],
            "conflicts": [],
            "unresolved": [],
            "conclusion": "Fact",
            "recommended_next_actions": [],
        }


def source_dict(source_id: str, text: str) -> dict:
    return {
        "source_id": source_id,
        "title": "T",
        "url": f"https://example.test/{source_id}",
        "fetch_status": "ok",
        "extracted_text": text,
    }


def assessment(source_id: str, vetted: int, supplied: int, budget: int) -> dict:
    return {
        "source_id": source_id,
        "relevance": "high",
        "scope_match": True,
        "time_match": True,
        "authority": "primary",
        "reason": "test",
        "synthesis_packing_receipt_version": PACKING_RECEIPT_SCHEMA,
        "synthesis_packing_mode": "quality_ranked_v1",
        "synthesis_context_budget_chars": budget,
        "synthesis_vetted_text_chars": vetted,
        "synthesis_supplied_text_chars": supplied,
        "synthesis_supplied": supplied > 0,
        "synthesis_packed_rank": 1,
    }


def app_config(root: Path) -> AppConfig:
    llm = LLMConfig(
        provider="ollama",
        base_url="http://127.0.0.1:11434",
        model="qwen-test",
        timeout_seconds=120,
        keep_alive="2m",
    )
    policy = ModelPolicyConfig(
        enabled=True,
        fast_model="qwen-test",
        research_model="qwen-test",
        presentation_model="qwen-test",
        report_model="qwen-test",
        deep_model="qwen-deep",
        deep_escalation=True,
        deep_prompt_chars=14000,
    )
    return AppConfig(
        environment="test",
        test_mode_full_access=False,
        database_path=root / "tasks.db",
        artifact_root=root / "data",
        profile_root=root / "profiles",
        llm=llm,
        internet_gateway=GatewayConfig(
            enabled=False,
            allow_all=False,
            audit_log=root / "internet.jsonl",
            mode="strict",
            direct_egress=False,
        ),
        execution_gateway=GatewayConfig(
            enabled=False,
            allow_all=False,
            audit_log=root / "execution.jsonl",
        ),
        raw={},
        model_policy=policy,
    )


class PackingReceiptTests(unittest.TestCase):
    def test_default_budget_remains_legacy_48k(self):
        with patch.dict(os.environ, {}, clear=True):
            policy = resolve_evidence_packing_policy()
        self.assertEqual(policy.budget_chars, DEFAULT_SYNTHESIS_CONTEXT_BUDGET_CHARS)
        self.assertEqual(policy.mode, "legacy_v1")
        self.assertFalse(policy.exact_body_dedupe)

    def test_invalid_budget_fails_closed(self):
        for value in ("abc", "0", "1024", "70000"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                resolve_evidence_packing_policy(
                    {"WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS": value}
                )

    def test_default_packer_is_byte_compatible_with_legacy_rendering(self):
        sources = [Source("S1", "alpha"), Source("S2", "beta")]
        expected = "\n---\n".join(
            f"[{s.source_id}]\nTITLE: {s.title}\nURL: {s.url}\nTEXT:\n{s.extracted_text}\n"
            for s in sources
        )
        rendered, receipt = pack_evidence_sources(
            sources,
            policy=EvidencePackingPolicy(mode="legacy_v1", budget_chars=48000),
        )
        self.assertEqual(rendered, expected)
        self.assertEqual(receipt["schema_version"], PACKING_RECEIPT_SCHEMA)
        self.assertFalse(receipt["exact_body_dedupe_enabled"])
        self.assertFalse(receipt["body_hashes_logged"])
        self.assertFalse(receipt["raw_content_logged"])

    def test_smaller_budget_records_full_vetted_and_actual_supplied_text(self):
        source = Source("S1", "abcdefghij", title="A")
        header = f"[S1]\nTITLE: A\nURL: {source.url}\nTEXT:\n"
        rendered, receipt = pack_evidence_sources(
            [source],
            policy=EvidencePackingPolicy(
                mode="quality_ranked_v1",
                budget_chars=len(header) + 4,
            ),
        )
        self.assertTrue(rendered.endswith("abcd"))
        self.assertEqual(receipt["vetted_source_text_chars"], 10)
        self.assertEqual(receipt["supplied_source_text_chars"], 4)
        item = receipt["sources"][0]
        self.assertEqual(item["vetted_text_chars"], 10)
        self.assertEqual(item["supplied_text_chars"], 4)
        self.assertFalse(item["body_fully_supplied"])
        self.assertNotIn("text", item)
        self.assertNotIn("url", item)
        self.assertNotIn("title", item)

    def test_runtime_synthesis_writes_receipt_to_authoritative_assessment(self):
        agent = ResearchAgent.__new__(ResearchAgent)
        agent.llm = FakeLLM()
        agent.profile = lambda: "profile"
        source = Source("S1", "evidence text")
        assessments = [
            {
                "source_id": "S1",
                "relevance": "high",
                "scope_match": True,
                "time_match": True,
                "authority": "primary",
                "reason": "test",
            }
        ]
        with patch.dict(
            os.environ,
            {
                "WORKSPACE_EVIDENCE_PACKING_MODE": "quality_ranked_v1",
                "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS": "32000",
                "WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE": "false",
            },
            clear=False,
        ):
            result = agent._synthesize(
                "title",
                "request",
                "objective",
                [],
                [source],
                assessments,
            )
        self.assertEqual(result["verified_facts"][0]["claim"], "Fact")
        item = assessments[0]
        self.assertEqual(item["synthesis_packing_receipt_version"], PACKING_RECEIPT_SCHEMA)
        self.assertEqual(item["synthesis_context_budget_chars"], 32000)
        self.assertFalse(item["synthesis_exact_body_dedupe_enabled"])
        self.assertEqual(item["synthesis_vetted_text_chars"], len(source.extracted_text))
        self.assertEqual(item["synthesis_supplied_text_chars"], len(source.extracted_text))
        self.assertTrue(item["synthesis_supplied"])
        self.assertTrue(item["synthesis_body_fully_supplied"])
        self.assertFalse(item["synthesis_exact_body_duplicate_suppressed"])
        self.assertIsNone(item["synthesis_duplicate_of_source_id"])
        self.assertNotIn("extracted_text", item)
        self.assertNotIn("url", item)

    def test_runtime_synthesis_records_duplicate_relationship_without_body_hash(self):
        agent = ResearchAgent.__new__(ResearchAgent)
        agent.llm = FakeLLM()
        agent.profile = lambda: "profile"
        body = "identical vetted evidence"
        sources = [Source("S1", body), Source("S2", body)]
        assessments = [
            {
                "source_id": source.source_id,
                "relevance": "high",
                "scope_match": True,
                "time_match": True,
                "authority": "primary",
                "reason": "test",
            }
            for source in sources
        ]
        with patch.dict(
            os.environ,
            {
                "WORKSPACE_EVIDENCE_PACKING_MODE": "legacy_v1",
                "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS": "32000",
                "WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE": "true",
            },
            clear=False,
        ):
            result = agent._synthesize(
                "title",
                "request",
                "objective",
                [],
                sources,
                assessments,
            )

        self.assertEqual(result["verified_facts"][0]["claim"], "Fact")
        by_id = {item["source_id"]: item for item in assessments}
        self.assertTrue(by_id["S1"]["synthesis_exact_body_dedupe_enabled"])
        self.assertTrue(by_id["S1"]["synthesis_supplied"])
        self.assertTrue(by_id["S1"]["synthesis_body_fully_supplied"])
        self.assertFalse(by_id["S1"]["synthesis_exact_body_duplicate_suppressed"])
        self.assertFalse(by_id["S2"]["synthesis_supplied"])
        self.assertTrue(by_id["S2"]["synthesis_exact_body_duplicate_suppressed"])
        self.assertEqual(by_id["S2"]["synthesis_duplicate_of_source_id"], "S1")
        serialized = repr(assessments)
        self.assertNotIn("sha256", serialized.lower())
        self.assertNotIn(body, serialized)

    def test_context_accounting_prefers_authoritative_receipt(self):
        research = {
            "sources": [source_dict("S1", "a" * 100), source_dict("S2", "b" * 100)],
            "source_assessments": [
                assessment("S1", 100, 100, 150),
                assessment("S2", 100, 25, 150) | {"synthesis_packed_rank": 2},
            ],
            "verified_facts": [{"claim": "fact", "source_ids": ["S1"]}],
            "inferences": [],
            "conflicts": [],
            "source_assessment_error": None,
        }
        metric = synthesis_context_proxy_accounting(research)
        self.assertEqual(metric["synthesis_context_budget_chars"], 150)
        self.assertEqual(metric["synthesis_vetted_source_text_chars"], 200)
        self.assertEqual(metric["synthesis_supplied_source_text_chars"], 125)
        self.assertEqual(metric["synthesis_cited_source_text_chars"], 100)
        self.assertEqual(metric["context_precision_proxy"], 0.8)
        self.assertEqual(metric["context_recall_proxy"], 0.625)
        self.assertEqual(metric["synthesis_packing_receipt_version"], PACKING_RECEIPT_SCHEMA)

    def test_duplicate_suppression_does_not_redefine_context_recall_metric(self):
        body = "x" * 100
        duplicate = assessment("S2", 100, 0, 48000) | {
            "synthesis_packed_rank": 2,
            "synthesis_exact_body_dedupe_enabled": True,
            "synthesis_exact_body_duplicate_suppressed": True,
            "synthesis_duplicate_of_source_id": "S1",
        }
        research = {
            "sources": [source_dict("S1", body), source_dict("S2", body)],
            "source_assessments": [
                assessment("S1", 100, 100, 48000),
                duplicate,
            ],
            "verified_facts": [{"claim": "fact", "source_ids": ["S1"]}],
            "inferences": [],
            "conflicts": [],
            "source_assessment_error": None,
        }
        metric = synthesis_context_proxy_accounting(research)
        self.assertEqual(metric["synthesis_vetted_source_text_chars"], 200)
        self.assertEqual(metric["synthesis_supplied_source_text_chars"], 100)
        self.assertEqual(metric["context_recall_proxy"], 0.5)

    def test_partial_or_tampered_receipt_fails_closed(self):
        base = {
            "sources": [source_dict("S1", "a" * 10), source_dict("S2", "b" * 10)],
            "source_assessments": [
                assessment("S1", 10, 10, 100),
                {
                    "source_id": "S2",
                    "relevance": "high",
                    "scope_match": True,
                    "time_match": True,
                    "authority": "primary",
                },
            ],
            "verified_facts": [],
            "inferences": [],
            "conflicts": [],
            "source_assessment_error": None,
        }
        with self.assertRaisesRegex(ValueError, "PACKING_RECEIPT_INCOMPLETE"):
            synthesis_context_proxy_accounting(base)

        tampered = dict(base)
        tampered["source_assessments"] = [assessment("S1", 999, 10, 100)]
        tampered["sources"] = [source_dict("S1", "a" * 10)]
        with self.assertRaisesRegex(ValueError, "PACKING_RECEIPT_SOURCE_LENGTH_MISMATCH"):
            synthesis_context_proxy_accounting(tampered)

    def test_receipt_aware_handoff_security_hash_verifies(self):
        research = {
            "task_id": "TASK-1",
            "objective": "test",
            "sources": [source_dict("S1", "evidence")],
            "source_assessments": [assessment("S1", 8, 8, 32000)],
            "verified_facts": [
                {"claim": "Fact", "source_ids": ["S1"], "confidence": "medium"}
            ],
            "inferences": [],
            "conflicts": [],
            "unresolved_items": [],
            "constraint_gaps": [],
            "rejected_numeric_claims": [],
            "rejected_sources": [],
            "source_assessment_error": None,
            "synthesis_error": None,
        }
        handoff = build_handoff(research)
        self.assertEqual(handoff["quality_metrics"]["synthesis_context_budget_chars"], 32000)
        verified = verify_handoff_security_metadata(
            handoff,
            expected_source_agent="research",
            expected_target_agent="presentation",
            expected_task_id="TASK-1",
        )
        self.assertEqual(verified["content_hash"], handoff["security"]["content_hash"])

    def test_legacy_payload_without_receipt_still_uses_reconstruction(self):
        research = {
            "sources": [source_dict("S1", "abcdefghij")],
            "source_assessments": [
                {
                    "source_id": "S1",
                    "relevance": "high",
                    "scope_match": True,
                    "time_match": True,
                    "authority": "primary",
                }
            ],
            "verified_facts": [{"claim": "Fact", "source_ids": ["S1"]}],
            "inferences": [],
            "conflicts": [],
            "source_assessment_error": None,
        }
        metric = synthesis_context_proxy_accounting(research)
        self.assertEqual(metric["synthesis_supplied_source_text_chars"], 10)
        self.assertNotIn("synthesis_packing_receipt_version", metric)

    def test_benchmark_fingerprint_changes_with_context_budget(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = app_config(Path(tmp))
            with patch.dict(
                os.environ,
                {
                    "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS": "48000",
                    "WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE": "false",
                },
                clear=False,
            ):
                baseline = effective_config_fingerprint(config)
            with patch.dict(
                os.environ,
                {
                    "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS": "32000",
                    "WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE": "false",
                },
                clear=False,
            ):
                candidate = effective_config_fingerprint(config)
        self.assertNotEqual(baseline, candidate)

    def test_benchmark_fingerprint_changes_with_exact_body_dedupe_flag(self):
        with tempfile.TemporaryDirectory() as tmp:
            config = app_config(Path(tmp))
            with patch.dict(
                os.environ,
                {
                    "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS": "48000",
                    "WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE": "false",
                },
                clear=False,
            ):
                baseline = effective_config_fingerprint(config)
            with patch.dict(
                os.environ,
                {
                    "WORKSPACE_SYNTHESIS_CONTEXT_BUDGET_CHARS": "48000",
                    "WORKSPACE_EVIDENCE_EXACT_BODY_DEDUPE": "true",
                },
                clear=False,
            ):
                candidate = effective_config_fingerprint(config)
        self.assertNotEqual(baseline, candidate)


if __name__ == "__main__":
    unittest.main()
