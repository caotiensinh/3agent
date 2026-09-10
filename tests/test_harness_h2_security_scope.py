from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any, cast

from three_agent.harness_memory import (
    HarnessEvent,
    HarnessMemoryError,
    HarnessMemoryStore,
    MemoryRecord,
)
from three_agent.store import TaskStore


class HarnessH2SecurityScopeTests(unittest.TestCase):
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
        project_id: str = "project-a",
        payload: dict[str, Any] | None = None,
    ) -> HarnessEvent:
        return HarnessEvent(
            event_id=event_id,
            project_id=project_id,
            conversation_id="conv-001",
            event_type="message",
            source_type="user",
            source_ref=f"conversation:conv-001:{event_id}",
            trust_domain="trusted",
            payload=payload or {"text": event_id},
            created_at="2026-09-03T00:00:00Z",
        )

    @staticmethod
    def memory(event_id: str) -> MemoryRecord:
        return MemoryRecord(
            revision_id="rev-project-a",
            memory_id="secret-key",
            project_id="project-a",
            conversation_id="conv-001",
            layer="M3",
            kind="fact",
            content="Project A internal value.",
            provenance_event_ids=(event_id,),
            trust_domain="trusted",
            confidence=0.95,
            valid_from="2026-09-03T00:00:01Z",
            created_at="2026-09-03T00:00:01Z",
        )

    def test_direct_event_and_revision_reads_require_matching_project_scope(self) -> None:
        event = self.event("evt-project-a")
        record = self.memory(event.event_id)
        self.store.append_event(event)
        self.store.remember(record)

        self.assertEqual(
            self.store.get_event(event.event_id, project_id="project-a"),
            event,
        )
        self.assertEqual(
            self.store.get_revision(record.revision_id, project_id="project-a"),
            record,
        )
        with self.assertRaises(KeyError):
            self.store.get_event(event.event_id, project_id="project-b")
        with self.assertRaises(KeyError):
            self.store.get_revision(record.revision_id, project_id="project-b")

    def test_non_finite_payload_numbers_are_rejected_before_persistence(self) -> None:
        event = self.event("evt-nan", payload={"value": float("nan")})
        with self.assertRaisesRegex(HarnessMemoryError, "PAYLOAD_NON_FINITE_NUMBER"):
            self.store.append_event(event)
        self.assertEqual(self.store.list_events(project_id="project-a"), ())

    def test_non_string_json_object_keys_are_rejected(self) -> None:
        unsafe_payload = cast(dict[str, Any], {1: "not-a-string-key"})
        event = self.event("evt-key", payload=unsafe_payload)
        with self.assertRaisesRegex(
            HarnessMemoryError,
            "PAYLOAD_OBJECT_KEY_MUST_BE_STRING",
        ):
            self.store.append_event(event)

    def test_tuple_payload_values_are_rejected_instead_of_silently_normalized(self) -> None:
        event = self.event("evt-tuple", payload={"value": ("a", "b")})
        with self.assertRaisesRegex(HarnessMemoryError, "PAYLOAD_NOT_CANONICAL_JSON"):
            self.store.append_event(event)

    def test_identifiers_with_surrounding_whitespace_fail_closed(self) -> None:
        event = self.event(" evt-whitespace ")
        with self.assertRaisesRegex(HarnessMemoryError, "INVALID_EVENT_ID"):
            self.store.append_event(event)


if __name__ == "__main__":
    unittest.main()
