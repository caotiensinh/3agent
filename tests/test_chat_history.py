import tempfile
import unittest
from pathlib import Path

from three_agent.chat_history import ChatHistoryStore


class ChatHistoryStoreTests(unittest.TestCase):
    def test_history_is_persistent_owner_scoped_searchable_and_pinnable(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "workspace.db"
            store = ChatHistoryStore(db)
            store.initialize()

            owner_a = "a" * 64
            owner_b = "b" * 64
            conversation = store.create_conversation(owner_a, "Upgrade database safely")
            other = store.create_conversation(owner_b, "Foreign conversation")

            store.record_message(
                conversation,
                role="user",
                content="Plan a PostgreSQL migration",
                job_id="job-a",
            )
            store.record_message(
                conversation,
                role="assistant",
                content="Use a staged migration with rollback evidence.",
                job_id="job-a",
                task_id="TASK-1",
            )
            store.record_message(
                other,
                role="user",
                content="Secret from another owner",
                job_id="job-b",
            )

            # Re-open through a new store instance to prove restart persistence.
            restarted = ChatHistoryStore(db)
            restarted.initialize()
            rows = restarted.list_conversations(owner_a)
            self.assertEqual([row["conversation_id"] for row in rows], [conversation])
            self.assertNotIn("Secret from another owner", str(rows))

            result = restarted.get_conversation(owner_a, conversation)
            self.assertEqual(
                [message["role"] for message in result["messages"]],
                ["user", "assistant"],
            )
            self.assertEqual(result["messages"][1]["task_id"], "TASK-1")

            searched = restarted.list_conversations(owner_a, query="rollback")
            self.assertEqual([row["conversation_id"] for row in searched], [conversation])

            pinned = restarted.set_pinned(owner_a, conversation, True)
            self.assertTrue(pinned["pinned"])
            self.assertTrue(restarted.list_conversations(owner_a)[0]["pinned"])

            with self.assertRaises(KeyError):
                restarted.get_conversation(owner_a, other)
            with self.assertRaisesRegex(ValueError, "unavailable"):
                restarted.ensure_conversation(owner_a, other, "ignored")

    def test_message_upsert_does_not_duplicate_final_assistant_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = ChatHistoryStore(Path(tmp) / "workspace.db")
            store.initialize()
            owner = "a" * 64
            conversation = store.create_conversation(owner, "Test")
            store.record_message(
                conversation,
                role="assistant",
                content="temporary",
                job_id="job-1",
                status="running",
            )
            store.record_message(
                conversation,
                role="assistant",
                content="final",
                job_id="job-1",
                status="completed",
            )
            result = store.get_conversation(owner, conversation)
            self.assertEqual(len(result["messages"]), 1)
            self.assertEqual(result["messages"][0]["content"], "final")
            self.assertEqual(result["messages"][0]["status"], "completed")


if __name__ == "__main__":
    unittest.main()
