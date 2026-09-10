from __future__ import annotations

import unittest

from three_agent.harness_context_compiler import (
    CompiledContext,
    ContextCandidate,
    ContextCompilePolicy,
    ContextCompiler,
    ContextCompilerError,
)
from three_agent.harness_context_manifest import ContextManifestBuilder


class HarnessH3ContextCompilerTests(unittest.TestCase):
    @staticmethod
    def candidate(
        item_id: str,
        *,
        section_type: str = "memory",
        content: str | None = None,
        token_count: int = 100,
        priority: int = 50,
        critical: bool = False,
        derived: bool = False,
        obsolete: bool = False,
        exact_required: bool = False,
        structural_key: str | None = None,
        extractive_content: str | None = None,
        extractive_token_count: int | None = None,
    ) -> ContextCandidate:
        return ContextCandidate(
            item_id=item_id,
            section_type=section_type,
            content=content or f"content for {item_id}",
            token_count=token_count,
            source_refs=(f"event:{item_id}",),
            priority=priority,
            critical=critical,
            derived=derived,
            obsolete=obsolete,
            exact_required=exact_required,
            structural_key=structural_key,
            extractive_content=extractive_content,
            extractive_token_count=extractive_token_count,
        )

    def test_below_soft_threshold_preserves_context_without_compaction(self) -> None:
        policy = ContextCompilePolicy(max_input=1000, reserved_output=100)
        candidates = (
            self.candidate("a", token_count=100),
            self.candidate("b", token_count=100),
        )
        result = ContextCompiler.compile(policy=policy, candidates=candidates)

        self.assertEqual(result.items, candidates)
        self.assertEqual(result.compaction_modes, ())
        self.assertFalse(result.checkpoint_required)
        self.assertFalse(result.rehydration_required)

    def test_soft_threshold_applies_structural_dedup_and_obsolete_derived_eviction(self) -> None:
        policy = ContextCompilePolicy(max_input=1000, reserved_output=100)
        candidates = (
            self.candidate("dup-low", token_count=250, priority=10, structural_key="router-ip"),
            self.candidate("dup-high", token_count=200, priority=90, structural_key="router-ip"),
            self.candidate("obsolete", token_count=150, derived=True, obsolete=True),
            self.candidate("keep", token_count=100),
        )
        result = ContextCompiler.compile(policy=policy, candidates=candidates)

        self.assertEqual([item.item_id for item in result.items], ["dup-high", "keep"])
        self.assertEqual(set(result.dropped_item_ids), {"dup-low", "obsolete"})
        self.assertEqual(result.compaction_modes, ("structural",))

    def test_hard_threshold_uses_extractive_projection_only_for_safe_noncritical_items(self) -> None:
        policy = ContextCompilePolicy(max_input=1000, reserved_output=100)
        candidates = (
            self.candidate(
                "security",
                section_type="security",
                token_count=300,
                critical=True,
                exact_required=True,
                extractive_content="short security",
                extractive_token_count=50,
            ),
            self.candidate(
                "narrative",
                token_count=450,
                extractive_content="short narrative",
                extractive_token_count=100,
            ),
        )
        result = ContextCompiler.compile(policy=policy, candidates=candidates)

        security, narrative = result.items
        self.assertEqual(security.token_count, 300)
        self.assertEqual(security.content, "content for security")
        self.assertEqual(narrative.token_count, 100)
        self.assertEqual(narrative.content, "short narrative")
        self.assertIn("extractive", result.compaction_modes)
        self.assertTrue(result.checkpoint_required)

    def test_critical_context_never_drops_and_overflow_fails_closed(self) -> None:
        policy = ContextCompilePolicy(max_input=500, reserved_output=100)
        critical = (
            self.candidate("c1", token_count=250, critical=True, exact_required=True),
            self.candidate("c2", token_count=200, critical=True, exact_required=True),
        )
        with self.assertRaisesRegex(ContextCompilerError, "CRITICAL_CONTEXT_EXCEEDS_BUDGET"):
            ContextCompiler.compile(policy=policy, candidates=critical)

    def test_capacity_pruning_prefers_priority_and_preserves_source_index_for_dropped_items(self) -> None:
        policy = ContextCompilePolicy(max_input=500, reserved_output=100)
        candidates = (
            self.candidate("critical", token_count=150, critical=True, priority=100),
            self.candidate("high", token_count=150, priority=90),
            self.candidate("low", token_count=150, priority=10),
            self.candidate("tiny", token_count=50, priority=80),
        )
        result = ContextCompiler.compile(policy=policy, candidates=candidates)

        self.assertIn("critical", [item.item_id for item in result.items])
        self.assertIn("high", [item.item_id for item in result.items])
        self.assertIn("tiny", [item.item_id for item in result.items])
        self.assertIn("low", result.dropped_item_ids)
        source_index = dict(result.source_index)
        self.assertEqual(source_index["low"], ("event:low",))

    def test_emergency_threshold_marks_checkpoint_and_rehydration_required(self) -> None:
        policy = ContextCompilePolicy(max_input=1000, reserved_output=100)
        candidates = (
            self.candidate("critical", token_count=300, critical=True, exact_required=True),
            self.candidate(
                "bulk",
                token_count=540,
                extractive_content="bulk extract",
                extractive_token_count=100,
            ),
        )
        result = ContextCompiler.compile(policy=policy, candidates=candidates)

        self.assertTrue(result.checkpoint_required)
        self.assertTrue(result.rehydration_required)

    def test_manifest_sections_preserve_source_pointers_without_prompt_body(self) -> None:
        policy = ContextCompilePolicy(max_input=1000, reserved_output=100)
        candidates = (
            self.candidate("task", section_type="task_spec", token_count=100, critical=True, exact_required=True),
            self.candidate("memory-1", section_type="memory", token_count=100),
            self.candidate("memory-2", section_type="memory", token_count=100),
        )
        result = ContextCompiler.compile(policy=policy, candidates=candidates)
        sections = result.manifest_sections()

        self.assertEqual([section.section_type for section in sections], ["task_spec", "memory"])
        self.assertEqual(sections[1].item_count, 2)
        self.assertEqual(sections[1].token_count, 200)
        self.assertEqual(sections[1].source_refs, ("event:memory-1", "event:memory-2"))

        manifest = ContextManifestBuilder.build(
            context_manifest_id="ctx-compiler",
            project_id="workspace",
            conversation_id="conv-001",
            task_id="TASK-20260903-0001",
            model_id="local/model",
            max_input=1000,
            reserved_output=100,
            section_inputs=sections,
            authority_fingerprint="sha256:" + "a" * 64,
            compaction=result.compaction_state,
            created_at="2026-09-03T03:00:00Z",
        )
        payload = str(manifest.canonical_dict())
        self.assertNotIn("content for task", payload)
        self.assertNotIn("content for memory", payload)

    def test_duplicate_item_ids_and_invalid_threshold_order_fail_closed(self) -> None:
        with self.assertRaisesRegex(ContextCompilerError, "INVALID_COMPACTION_THRESHOLD_ORDER"):
            ContextCompilePolicy(
                max_input=1000,
                reserved_output=100,
                soft_threshold=0.8,
                hard_threshold=0.7,
                emergency_threshold=0.9,
            ).validate()

        candidate = self.candidate("dup")
        with self.assertRaisesRegex(ContextCompilerError, "DUPLICATE_CONTEXT_ITEM_ID"):
            ContextCompiler.compile(
                policy=ContextCompilePolicy(max_input=1000, reserved_output=100),
                candidates=(candidate, candidate),
            )

    def test_invalid_extractive_projection_cannot_claim_token_reduction(self) -> None:
        invalid = self.candidate(
            "bad-extract",
            token_count=100,
            extractive_content="not smaller",
            extractive_token_count=100,
        )
        with self.assertRaisesRegex(ContextCompilerError, "EXTRACTIVE_TOKEN_COUNT_NOT_REDUCED"):
            invalid.validate()

    def test_critical_obsolete_context_is_rejected_instead_of_silently_dropped(self) -> None:
        invalid = self.candidate("critical-stale", token_count=100, critical=True, obsolete=True)
        with self.assertRaisesRegex(ContextCompilerError, "CRITICAL_CONTEXT_CANNOT_BE_OBSOLETE"):
            ContextCompiler.compile(
                policy=ContextCompilePolicy(max_input=1000, reserved_output=100),
                candidates=(invalid,),
            )

    def test_compiled_context_rejects_any_claim_that_critical_item_was_dropped(self) -> None:
        critical = self.candidate("critical", token_count=100, critical=True, exact_required=True)
        forged = CompiledContext(
            items=(),
            dropped_item_ids=("critical",),
            critical_item_ids=("critical",),
            raw_tokens=100,
            compiled_tokens=0,
            input_capacity=900,
            compaction_modes=("structural",),
            checkpoint_required=True,
            rehydration_required=False,
            source_index=(("critical", critical.source_refs),),
        )
        with self.assertRaisesRegex(ContextCompilerError, "CRITICAL_CONTEXT_DROPPED"):
            forged.validate()


if __name__ == "__main__":
    unittest.main()
