from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from three_agent.harness_context_manifest import (
    CompactionState,
    ContextManifest,
    ContextManifestBuilder,
    ContextManifestError,
    ContextManifestSection,
    ContextManifestStore,
    ContextSectionInput,
    TokenBudget,
)
from three_agent.store import TaskStore


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


class HarnessH3ContextManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "workspace.db"
        self.task_store = TaskStore(self.db_path)
        self.task_store.initialize()
        self.task = self.task_store.create_task(
            "Harness context manifest test",
            "Verify audit-safe token budgeting metadata.",
        )
        self.store = ContextManifestStore(self.task_store)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def build(
        self,
        manifest_id: str = "ctx-001",
        *,
        project_id: str = "workspace",
        created_at: str = "2026-09-03T02:55:00Z",
        max_input: int = 120000,
        reserved_output: int = 12000,
        source_ref: str = "event:evt-001",
        compaction: CompactionState | None = None,
    ) -> ContextManifest:
        return ContextManifestBuilder.build(
            context_manifest_id=manifest_id,
            project_id=project_id,
            conversation_id="conv-001",
            task_id=self.task.task_id,
            model_id="local/qwen3.6:35b",
            max_input=max_input,
            reserved_output=reserved_output,
            section_inputs=(
                ContextSectionInput(
                    section_type="task_spec",
                    item_count=1,
                    token_count=1300,
                    source_hash=sha("task-spec"),
                    source_refs=(source_ref,),
                    critical=True,
                ),
                ContextSectionInput(
                    section_type="memory",
                    item_count=18,
                    token_count=8200,
                    source_hash=sha("memory-selection"),
                    source_refs=("memory:rev-001", "memory:rev-002"),
                    critical=False,
                ),
            ),
            authority_fingerprint=sha("task-authority"),
            compaction=compaction,
            created_at=created_at,
        )

    def test_builder_computes_hard_token_budget(self) -> None:
        manifest = self.build()
        self.assertEqual(manifest.token_budget.compiled_input, 9500)
        self.assertEqual(manifest.token_budget.input_capacity, 108000)
        self.assertAlmostEqual(manifest.token_budget.utilization, 9500 / 108000)
        self.assertEqual(sum(section.token_count for section in manifest.sections), 9500)

    def test_budget_overflow_and_output_reserve_fail_closed(self) -> None:
        with self.assertRaisesRegex(
            ContextManifestError,
            "CONTEXT_TOKEN_BUDGET_EXCEEDED",
        ):
            self.build(max_input=10000, reserved_output=1000)

        with self.assertRaisesRegex(
            ContextManifestError,
            "OUTPUT_RESERVE_EXHAUSTS_CONTEXT",
        ):
            self.build(max_input=10000, reserved_output=10000)

    def test_manifest_is_audit_safe_and_hashes_sensitive_source_refs(self) -> None:
        secret_ref = "https://user:password@example.invalid/path?token=SUPERSECRET"
        manifest = self.build(source_ref=secret_ref)
        payload = json.dumps(manifest.canonical_dict(), sort_keys=True)

        self.assertNotIn("SUPERSECRET", payload)
        self.assertNotIn("password", payload)
        self.assertNotIn("example.invalid", payload)
        self.assertIn(sha(secret_ref), payload)
        self.assertNotIn("prompt", manifest.canonical_dict())
        self.assertNotIn("content", manifest.canonical_dict())

    def test_compaction_metadata_is_strict_and_does_not_claim_unapplied_modes(self) -> None:
        manifest = self.build(
            compaction=CompactionState(
                applied=True,
                modes=("structural", "extractive"),
            )
        )
        self.assertTrue(manifest.compaction.applied)
        self.assertEqual(manifest.compaction.modes, ("structural", "extractive"))

        with self.assertRaisesRegex(ContextManifestError, "COMPACTION_MODE_REQUIRED"):
            CompactionState(applied=True, modes=()).validate()
        with self.assertRaisesRegex(
            ContextManifestError,
            "COMPACTION_MODE_WITHOUT_APPLICATION",
        ):
            CompactionState(applied=False, modes=("structural",)).validate()

    def test_manifest_round_trip_reopen_and_immutability(self) -> None:
        manifest = self.build("ctx-reopen")
        digest = self.store.save(manifest)
        self.assertEqual(
            self.store.get(context_manifest_id="ctx-reopen", project_id="workspace"),
            manifest,
        )

        reopened = ContextManifestStore(TaskStore(self.db_path))
        recovered = reopened.get(
            context_manifest_id="ctx-reopen",
            project_id="workspace",
        )
        self.assertEqual(recovered.fingerprint, digest)

        with self.task_store.connect() as conn:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute(
                    "UPDATE harness_context_manifests SET model_id='tampered' "
                    "WHERE context_manifest_id='ctx-reopen'"
                )

    def test_direct_read_and_listing_are_project_scoped(self) -> None:
        project_a = self.build("ctx-a", project_id="project-a")
        project_b = self.build("ctx-b", project_id="project-b")
        self.store.save(project_a)
        self.store.save(project_b)

        self.assertEqual(
            [m.context_manifest_id for m in self.store.list_manifests(project_id="project-a")],
            ["ctx-a"],
        )
        with self.assertRaises(KeyError):
            self.store.get(context_manifest_id="ctx-a", project_id="project-b")

    def test_duplicate_identifier_is_idempotent_only_for_identical_manifest(self) -> None:
        original = self.build("ctx-dup")
        self.assertEqual(self.store.save(original), original.fingerprint)
        self.assertEqual(self.store.save(original), original.fingerprint)

        conflicting = ContextManifestBuilder.build(
            context_manifest_id="ctx-dup",
            project_id="workspace",
            conversation_id="conv-001",
            task_id=self.task.task_id,
            model_id="local/qwen3.6:35b",
            max_input=120000,
            reserved_output=12000,
            section_inputs=(
                ContextSectionInput(
                    section_type="task_spec",
                    item_count=1,
                    token_count=1400,
                    source_hash=sha("changed-task-spec"),
                    source_refs=("event:evt-002",),
                    critical=True,
                ),
            ),
            authority_fingerprint=sha("task-authority"),
            created_at="2026-09-03T02:55:00Z",
        )
        with self.assertRaisesRegex(
            ContextManifestError,
            "CONTEXT_MANIFEST_ID_CONFLICT",
        ):
            self.store.save(conflicting)

    def test_manifest_requires_existing_task_and_rejects_future_timestamp(self) -> None:
        future = self.build("ctx-future", created_at="2999-01-01T00:00:00Z")
        with self.assertRaisesRegex(
            ContextManifestError,
            "CONTEXT_MANIFEST_CREATED_AT_IN_FUTURE",
        ):
            self.store.save(future)

        unknown = ContextManifestBuilder.build(
            context_manifest_id="ctx-unknown",
            project_id="workspace",
            conversation_id="conv-001",
            task_id="TASK-20990101-9999",
            model_id="local/model",
            max_input=1000,
            reserved_output=100,
            section_inputs=(
                ContextSectionInput(
                    section_type="task_spec",
                    item_count=1,
                    token_count=10,
                    source_hash=sha("task"),
                ),
            ),
            authority_fingerprint=sha("authority"),
            created_at="2026-09-03T02:55:00Z",
        )
        with self.assertRaisesRegex(
            ContextManifestError,
            "CONTEXT_MANIFEST_TASK_SCOPE_UNKNOWN",
        ):
            self.store.save(unknown)

    def test_manual_manifest_cannot_lie_about_compiled_token_count(self) -> None:
        manifest = ContextManifest(
            context_manifest_id="ctx-liar",
            project_id="workspace",
            conversation_id="conv-001",
            task_id=self.task.task_id,
            model_id="local/model",
            token_budget=TokenBudget(
                max_input=1000,
                reserved_output=100,
                compiled_input=1,
            ),
            sections=(
                ContextManifestSection(
                    section_type="task_spec",
                    item_count=1,
                    token_count=100,
                    source_hash=sha("task"),
                    source_ref_hashes=(),
                    critical=True,
                ),
            ),
            compaction=CompactionState(),
            authority_fingerprint=sha("authority"),
            created_at="2026-09-03T02:55:00Z",
        )
        with self.assertRaisesRegex(
            ContextManifestError,
            "COMPILED_INPUT_TOKEN_MISMATCH",
        ):
            manifest.validate()

    def test_tampered_persisted_manifest_fails_integrity_check(self) -> None:
        manifest = self.build("ctx-tamper")
        self.store.save(manifest)

        with self.task_store.connect() as conn:
            conn.execute("DROP TRIGGER harness_context_manifests_no_update")
            conn.execute(
                "UPDATE harness_context_manifests SET manifest_json='{}' "
                "WHERE context_manifest_id='ctx-tamper'"
            )

        with self.assertRaisesRegex(
            ContextManifestError,
            "CONTEXT_MANIFEST_INTEGRITY_FAILED",
        ):
            self.store.get(
                context_manifest_id="ctx-tamper",
                project_id="workspace",
            )


if __name__ == "__main__":
    unittest.main()
