from __future__ import annotations

import hashlib
import unittest

from three_agent.harness_checkpoint import HarnessCheckpoint
from three_agent.harness_context_compiler import (
    ContextCandidate,
    ContextCompilePolicy,
)
from three_agent.harness_context_manifest import ContextManifestBuilder
from three_agent.harness_context_rehydration import (
    ContextRehydrationError,
    ContextRehydrator,
    ScopedContextCandidate,
)


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class HarnessH3ContextRehydrationTests(unittest.TestCase):
    @staticmethod
    def checkpoint() -> HarnessCheckpoint:
        return HarnessCheckpoint(
            checkpoint_id="chk-rehydrate-001",
            project_id="workspace",
            conversation_id="conv-001",
            task_id="TASK-20260903-0001",
            goal="Continue the Harness implementation from a verified anchor.",
            current_state="H2 is complete and H3 context work is active.",
            completed=("H2 memory", "H2 checkpoint"),
            open_tasks=("H3 context compiler",),
            decisions=("Keep raw history outside the physical model context.",),
            constraints=("Critical security context must never be dropped.",),
            known_failures=(),
            important_entities=("ContextCompiler", "HarnessCheckpoint"),
            latest_evidence=("exact-head CI evidence",),
            next_action="Rehydrate a fresh bounded context.",
            source_refs=("event:evt-001", "memory:rev-001"),
            created_at="2026-09-03T03:10:00Z",
        )

    @staticmethod
    def scoped(
        item_id: str,
        *,
        project_id: str = "workspace",
        conversation_id: str | None = "conv-001",
        task_id: str | None = "TASK-20260903-0001",
        token_count: int = 100,
        critical: bool = False,
        source_refs: tuple[str, ...] | None = None,
    ) -> ScopedContextCandidate:
        return ScopedContextCandidate(
            project_id=project_id,
            conversation_id=conversation_id,
            task_id=task_id,
            candidate=ContextCandidate(
                item_id=item_id,
                section_type="memory",
                content=f"retrieved content for {item_id}",
                token_count=token_count,
                source_refs=source_refs or (f"memory:{item_id}",),
                priority=80,
                critical=critical,
                exact_required=critical,
            ),
        )

    def rehydrate(self, *sources: ScopedContextCandidate, checkpoint_tokens: int = 150):
        return ContextRehydrator.rehydrate(
            checkpoint=self.checkpoint(),
            checkpoint_token_count=checkpoint_tokens,
            scoped_candidates=tuple(sources),
            resolved_source_refs=("event:evt-001", "memory:rev-001"),
            policy=ContextCompilePolicy(max_input=1000, reserved_output=100),
        )

    def test_rehydration_injects_exact_critical_checkpoint_anchor(self) -> None:
        result = self.rehydrate(self.scoped("source-1"))
        anchors = [item for item in result.compiled.items if item.section_type == "checkpoint"]

        self.assertEqual(len(anchors), 1)
        anchor = anchors[0]
        self.assertTrue(anchor.critical)
        self.assertTrue(anchor.exact_required)
        self.assertIn("checkpoint:chk-rehydrate-001", anchor.source_refs)
        self.assertIn("event:evt-001", anchor.source_refs)
        self.assertEqual(result.source_coverage, 1.0)

    def test_cross_project_source_is_rejected_before_compaction(self) -> None:
        with self.assertRaisesRegex(
            ContextRehydrationError,
            "REHYDRATION_PROJECT_SCOPE_MISMATCH",
        ):
            self.rehydrate(self.scoped("foreign", project_id="project-b"))

    def test_cross_conversation_source_is_rejected_before_compaction(self) -> None:
        with self.assertRaisesRegex(
            ContextRehydrationError,
            "REHYDRATION_CONVERSATION_SCOPE_MISMATCH",
        ):
            self.rehydrate(self.scoped("foreign", conversation_id="conv-other"))

    def test_cross_task_source_is_rejected_before_compaction(self) -> None:
        with self.assertRaisesRegex(
            ContextRehydrationError,
            "REHYDRATION_TASK_SCOPE_MISMATCH",
        ):
            self.rehydrate(self.scoped("foreign", task_id="TASK-20260903-9999"))

    def test_project_wide_source_is_allowed_without_narrower_scope_claim(self) -> None:
        project_wide = self.scoped(
            "project-knowledge",
            conversation_id=None,
            task_id=None,
        )
        result = self.rehydrate(project_wide)
        self.assertIn(
            "project-knowledge",
            [item.item_id for item in result.compiled.items],
        )

    def test_all_checkpoint_source_pointers_must_resolve(self) -> None:
        with self.assertRaisesRegex(
            ContextRehydrationError,
            "REHYDRATION_SOURCE_POINTER_UNRESOLVED",
        ):
            ContextRehydrator.rehydrate(
                checkpoint=self.checkpoint(),
                checkpoint_token_count=150,
                scoped_candidates=(self.scoped("source-1"),),
                resolved_source_refs=("event:evt-001",),
                policy=ContextCompilePolicy(max_input=1000, reserved_output=100),
            )

    def test_duplicate_resolved_source_pointer_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            ContextRehydrationError,
            "DUPLICATE_RESOLVED_SOURCE_REF",
        ):
            ContextRehydrator.rehydrate(
                checkpoint=self.checkpoint(),
                checkpoint_token_count=150,
                scoped_candidates=(),
                resolved_source_refs=(
                    "event:evt-001",
                    "memory:rev-001",
                    "memory:rev-001",
                ),
                policy=ContextCompilePolicy(max_input=1000, reserved_output=100),
            )

    def test_checkpoint_anchor_cannot_be_dropped_when_budget_is_too_small(self) -> None:
        with self.assertRaisesRegex(
            ContextRehydrationError,
            "CRITICAL_CONTEXT_EXCEEDS_BUDGET",
        ):
            ContextRehydrator.rehydrate(
                checkpoint=self.checkpoint(),
                checkpoint_token_count=450,
                scoped_candidates=(),
                resolved_source_refs=("event:evt-001", "memory:rev-001"),
                policy=ContextCompilePolicy(max_input=500, reserved_output=100),
            )

    def test_source_index_preserves_reconstruction_pointers_after_pruning(self) -> None:
        result = ContextRehydrator.rehydrate(
            checkpoint=self.checkpoint(),
            checkpoint_token_count=150,
            scoped_candidates=(
                self.scoped("high", token_count=250),
                self.scoped("low", token_count=250),
                self.scoped("tiny", token_count=100),
            ),
            resolved_source_refs=("event:evt-001", "memory:rev-001"),
            policy=ContextCompilePolicy(max_input=650, reserved_output=100),
        )
        source_index = dict(result.compiled.source_index)
        self.assertIn("memory:low", source_index["low"])
        self.assertIn("memory:high", source_index["high"])
        self.assertIn("event:evt-001", next(
            refs for item_id, refs in result.compiled.source_index
            if item_id.startswith("rehydration-anchor:")
        ))

    def test_rehydrated_manifest_metadata_contains_hashes_not_checkpoint_body(self) -> None:
        result = self.rehydrate(self.scoped("source-1"))
        manifest = ContextManifestBuilder.build(
            context_manifest_id="ctx-rehydrated-001",
            project_id="workspace",
            conversation_id="conv-001",
            task_id="TASK-20260903-0001",
            model_id="local/model",
            max_input=1000,
            reserved_output=100,
            section_inputs=result.manifest_sections(),
            authority_fingerprint=sha("authority"),
            compaction=result.compiled.compaction_state,
            created_at="2026-09-03T03:11:00Z",
        )
        payload = str(manifest.canonical_dict())
        self.assertNotIn("Continue the Harness implementation", payload)
        self.assertNotIn("Critical security context must never be dropped", payload)
        self.assertIn("source_hash", payload)


if __name__ == "__main__":
    unittest.main()
