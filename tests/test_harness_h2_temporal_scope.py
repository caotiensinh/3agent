from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from three_agent.harness_memory import (
    HarnessEvent,
    HarnessMemoryError,
    HarnessMemoryStore,
    MemoryRecord,
)
from three_agent.store import TaskStore


class HarnessH2TemporalScopeRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.task_store = TaskStore(Path(self.tempdir.name) / "workspace.db")
        self.task_store.initialize()
        self.store = HarnessMemoryStore(self.task_store)

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    @staticmethod
    def event(
        event_id: str,
        *,
        task_id: str | None = None,
        created_at: str = "2026-09-03T00:00:00Z",
    ) -> HarnessEvent:
        return HarnessEvent(
            event_id=event_id,
            project_id="workspace",
            conversation_id="conv-001",
            task_id=task_id,
            event_type="message",
            source_type="user",
            source_ref=f"conversation:conv-001:{event_id}",
            trust_domain="trusted",
            payload={"text": event_id},
            created_at=created_at,
        )

    @staticmethod
    def memory(
        revision_id: str,
        memory_id: str,
        event_id: str,
        *,
        valid_from: str,
        task_id: str | None = None,
        supersedes_revision_id: str | None = None,
        content: str | None = None,
    ) -> MemoryRecord:
        return MemoryRecord(
            revision_id=revision_id,
            memory_id=memory_id,
            project_id="workspace",
            conversation_id="conv-001",
            task_id=task_id,
            layer="M3",
            kind="fact",
            content=content or revision_id,
            provenance_event_ids=(event_id,),
            trust_domain="trusted",
            confidence=0.95,
            valid_from=valid_from,
            supersedes_revision_id=supersedes_revision_id,
            created_at="2026-09-03T00:00:00Z",
        )

    def test_future_revision_does_not_become_current_before_valid_from(self) -> None:
        self.store.append_event(self.event("evt-present"))
        self.store.append_event(
            self.event("evt-future", created_at="2026-09-03T00:00:01Z")
        )
        present = self.memory(
            "rev-present",
            "router-address",
            "evt-present",
            valid_from="2026-09-03T00:00:00Z",
            content="192.168.11.1",
        )
        future = self.memory(
            "rev-future",
            "router-address",
            "evt-future",
            valid_from="2099-01-01T00:00:00Z",
            supersedes_revision_id="rev-present",
            content="192.168.11.254",
        )
        self.store.remember(present)
        self.store.remember(future)

        self.assertEqual(
            self.store.current_memory(
                memory_id="router-address",
                project_id="workspace",
            ),
            present,
        )
        self.assertEqual(
            self.store.memory_at(
                memory_id="router-address",
                project_id="workspace",
                at="2100-01-01T00:00:00Z",
            ),
            future,
        )

    def test_task_scoped_memory_rejects_provenance_from_another_task(self) -> None:
        task_a = self.task_store.create_task("Task A", "first scope")
        task_b = self.task_store.create_task("Task B", "second scope")
        self.store.append_event(self.event("evt-task-a", task_id=task_a.task_id))
        self.store.append_event(self.event("evt-task-b", task_id=task_b.task_id))

        wrong_scope = self.memory(
            "rev-task-a",
            "task-scoped-fact",
            "evt-task-b",
            valid_from="2026-09-03T00:00:02Z",
            task_id=task_a.task_id,
        )
        with self.assertRaisesRegex(
            HarnessMemoryError,
            "MEMORY_PROVENANCE_TASK_SCOPE_MISMATCH",
        ):
            self.store.remember(wrong_scope)

        correct_scope = self.memory(
            "rev-task-a-good",
            "task-scoped-fact-good",
            "evt-task-a",
            valid_from="2026-09-03T00:00:03Z",
            task_id=task_a.task_id,
        )
        self.store.remember(correct_scope)
        self.assertEqual(
            self.store.current_memory(
                memory_id="task-scoped-fact-good",
                project_id="workspace",
            ),
            correct_scope,
        )


if __name__ == "__main__":
    unittest.main()
