from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from three_agent.harness_checkpoint import (
    HarnessCheckpoint,
    HarnessCheckpointError,
    HarnessCheckpointStore,
)
from three_agent.store import TaskStore


class HarnessH2CheckpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.tempdir.name) / "workspace.db"
        self.task_store = TaskStore(self.db_path)
        self.task_store.initialize()
        self.task = self.task_store.create_task(
            "Harness checkpoint test",
            "Verify immutable reconstruction anchors.",
        )
        self.store = HarnessCheckpointStore(self.task_store)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def checkpoint(
        self,
        checkpoint_id: str = "chk-001",
        *,
        project_id: str = "workspace",
        conversation_id: str = "conv-001",
        task_id: str | None = None,
        created_at: str = "2026-09-03T02:40:00Z",
        current_state: str = "H2 checkpoint foundation is under test.",
        source_refs: tuple[str, ...] = ("event:evt-001", "commit:26dc5a6"),
    ) -> HarnessCheckpoint:
        return HarnessCheckpoint(
            checkpoint_id=checkpoint_id,
            project_id=project_id,
            conversation_id=conversation_id,
            task_id=task_id or self.task.task_id,
            goal="Finish Harness H2 without losing recoverability.",
            current_state=current_state,
            completed=("task compiler", "acceptance contract", "memory foundation"),
            open_tasks=("checkpoint foundation",),
            decisions=("reuse existing TaskStore SQLite",),
            constraints=("no parallel authority model",),
            known_failures=(),
            important_entities=("TaskStore", "HarnessCheckpointStore"),
            latest_evidence=("harness-ci passed on prior exact head",),
            next_action="Rehydrate from the latest immutable checkpoint.",
            source_refs=source_refs,
            created_at=created_at,
        )

    def test_checkpoint_round_trip_hash_and_idempotency(self) -> None:
        checkpoint = self.checkpoint()
        digest = self.store.save(checkpoint)
        recovered = self.store.get(
            checkpoint_id=checkpoint.checkpoint_id,
            project_id=checkpoint.project_id,
        )

        self.assertEqual(recovered, checkpoint)
        self.assertEqual(recovered.fingerprint, digest)
        self.assertEqual(self.store.save(checkpoint), digest)

    def test_checkpoint_requires_source_pointers_and_existing_task(self) -> None:
        with self.assertRaisesRegex(
            HarnessCheckpointError,
            "CHECKPOINT_SOURCE_REFS_REQUIRED",
        ):
            self.store.save(self.checkpoint(source_refs=()))

        unknown = self.checkpoint(
            checkpoint_id="chk-unknown-task",
            task_id="TASK-20990101-9999",
        )
        with self.assertRaisesRegex(
            HarnessCheckpointError,
            "CHECKPOINT_TASK_SCOPE_UNKNOWN",
        ):
            self.store.save(unknown)

    def test_checkpoint_rows_are_immutable(self) -> None:
        checkpoint = self.checkpoint("chk-immutable")
        self.store.save(checkpoint)

        with self.task_store.connect() as conn:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute(
                    "UPDATE harness_checkpoints SET project_id='other' "
                    "WHERE checkpoint_id='chk-immutable'"
                )
        with self.task_store.connect() as conn:
            with self.assertRaises(sqlite3.DatabaseError):
                conn.execute(
                    "DELETE FROM harness_checkpoints "
                    "WHERE checkpoint_id='chk-immutable'"
                )

    def test_direct_read_is_project_scoped(self) -> None:
        checkpoint = self.checkpoint("chk-scope", project_id="project-a")
        self.store.save(checkpoint)

        self.assertEqual(
            self.store.get(checkpoint_id="chk-scope", project_id="project-a"),
            checkpoint,
        )
        with self.assertRaises(KeyError):
            self.store.get(checkpoint_id="chk-scope", project_id="project-b")

    def test_latest_and_list_are_deterministic_and_scope_bounded(self) -> None:
        first = self.checkpoint(
            "chk-100",
            project_id="project-a",
            created_at="2026-09-03T02:40:00Z",
            current_state="first",
        )
        second = self.checkpoint(
            "chk-200",
            project_id="project-a",
            created_at="2026-09-03T02:41:00Z",
            current_state="second",
        )
        other = self.checkpoint(
            "chk-300",
            project_id="project-b",
            created_at="2026-09-03T02:42:00Z",
            current_state="other project",
        )
        for checkpoint in (first, second, other):
            self.store.save(checkpoint)

        self.assertEqual(
            self.store.latest(
                project_id="project-a",
                conversation_id="conv-001",
                task_id=self.task.task_id,
            ),
            second,
        )
        self.assertEqual(
            [item.checkpoint_id for item in self.store.list_checkpoints(project_id="project-a")],
            ["chk-100", "chk-200"],
        )

    def test_rehydration_anchor_survives_store_reopen(self) -> None:
        checkpoint = self.checkpoint("chk-reopen")
        self.store.save(checkpoint)

        reopened = HarnessCheckpointStore(TaskStore(self.db_path))
        anchor = reopened.rehydration_anchor(
            project_id=checkpoint.project_id,
            conversation_id=checkpoint.conversation_id,
            task_id=checkpoint.task_id,
        )

        self.assertIsNotNone(anchor)
        assert anchor is not None
        self.assertEqual(anchor["checkpoint"], checkpoint.canonical_dict())
        self.assertEqual(anchor["integrity"]["content_hash"], checkpoint.fingerprint)
        self.assertEqual(anchor["integrity"]["source_ref_count"], 2)

    def test_duplicate_checkpoint_id_conflict_fails_closed(self) -> None:
        original = self.checkpoint("chk-dup")
        self.store.save(original)
        conflicting = self.checkpoint(
            "chk-dup",
            current_state="different state with same identifier",
        )
        with self.assertRaisesRegex(
            HarnessCheckpointError,
            "CHECKPOINT_ID_CONFLICT",
        ):
            self.store.save(conflicting)

    def test_future_checkpoint_cannot_eclipse_current_state(self) -> None:
        future = self.checkpoint(
            "chk-future",
            created_at="2999-01-01T00:00:00Z",
        )
        with self.assertRaisesRegex(
            HarnessCheckpointError,
            "CHECKPOINT_CREATED_AT_IN_FUTURE",
        ):
            self.store.save(future)

    def test_checkpoint_input_rejects_noncanonical_container_shapes(self) -> None:
        invalid = HarnessCheckpoint(
            checkpoint_id="chk-shape",
            project_id="workspace",
            conversation_id="conv-001",
            task_id=self.task.task_id,
            goal="Goal",
            current_state="State",
            completed=["not", "a", "tuple"],  # type: ignore[arg-type]
            next_action="Next",
            source_refs=("event:evt-001",),
            created_at="2026-09-03T02:40:00Z",
        )
        with self.assertRaisesRegex(
            HarnessCheckpointError,
            "COMPLETED_MUST_BE_TUPLE",
        ):
            self.store.save(invalid)

        spaced = self.checkpoint(" chk-space ")
        with self.assertRaisesRegex(HarnessCheckpointError, "INVALID_CHECKPOINT_ID"):
            self.store.save(spaced)

    def test_tampered_persisted_checkpoint_fails_integrity_check(self) -> None:
        checkpoint = self.checkpoint("chk-tamper")
        self.store.save(checkpoint)

        with self.task_store.connect() as conn:
            conn.execute("DROP TRIGGER harness_checkpoints_no_update")
            conn.execute(
                "UPDATE harness_checkpoints SET checkpoint_json='{}' "
                "WHERE checkpoint_id='chk-tamper'"
            )

        with self.assertRaisesRegex(
            HarnessCheckpointError,
            "CHECKPOINT_INTEGRITY_FAILED",
        ):
            self.store.get(
                checkpoint_id="chk-tamper",
                project_id="workspace",
            )


if __name__ == "__main__":
    unittest.main()
