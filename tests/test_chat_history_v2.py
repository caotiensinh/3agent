import tempfile
import unittest
from pathlib import Path

from three_agent.chat_history import ChatHistoryStore
from three_agent.chat_history_v2 import ConversationHistoryStore


class ConversationHistoryStoreTests(unittest.TestCase):
    def make_store(self):
        tmp = tempfile.TemporaryDirectory()
        path = Path(tmp.name) / "workspace.db"
        store = ConversationHistoryStore(path)
        store.initialize()
        self.addCleanup(tmp.cleanup)
        return store

    def test_existing_v1_history_migrates_active_without_data_loss(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        path = Path(tmp.name) / "workspace.db"
        old = ChatHistoryStore(path)
        old.initialize()
        conversation_id = old.create_conversation("owner-a", "Legacy chat")
        old.record_message(
            conversation_id,
            role="user",
            content="legacy message",
            job_id="job-legacy",
        )

        store = ConversationHistoryStore(path)
        store.initialize()
        payload = store.get_conversation("owner-a", conversation_id)
        self.assertFalse(payload["archived"])
        self.assertEqual(payload["messages"][0]["content"], "legacy message")

    def test_rename_archive_restore_and_delete_lifecycle(self):
        store = self.make_store()
        conversation_id = store.create_conversation("owner-a", "Original")
        store.record_message(
            conversation_id,
            role="user",
            content="hello workspace",
            job_id="job-1",
        )

        renamed = store.rename_conversation("owner-a", conversation_id, "  Renamed   chat ")
        self.assertEqual(renamed["title"], "Renamed chat")

        archived = store.set_archived("owner-a", conversation_id, True)
        self.assertTrue(archived["archived"])
        self.assertFalse(archived["pinned"])
        self.assertEqual(store.list_conversations("owner-a", archived=False), [])
        self.assertEqual(
            store.list_conversations("owner-a", archived=True)[0]["conversation_id"],
            conversation_id,
        )
        self.assertEqual(
            store.list_conversations(
                "owner-a", query="workspace", archived=None
            )[0]["conversation_id"],
            conversation_id,
        )
        with self.assertRaisesRegex(ValueError, "archived"):
            store.ensure_conversation("owner-a", conversation_id, "unused")
        with self.assertRaisesRegex(ValueError, "cannot be pinned"):
            store.set_pinned("owner-a", conversation_id, True)

        restored = store.set_archived("owner-a", conversation_id, False)
        self.assertFalse(restored["archived"])
        self.assertEqual(
            store.ensure_conversation("owner-a", conversation_id, "unused"),
            conversation_id,
        )

        result = store.delete_conversation("owner-a", conversation_id)
        self.assertTrue(result["deleted"])
        with self.assertRaises(KeyError):
            store.get_conversation("owner-a", conversation_id)
        with store.connect() as conn:
            count = int(
                conn.execute(
                    "SELECT COUNT(*) FROM chat_messages WHERE conversation_id=?",
                    (conversation_id,),
                ).fetchone()[0]
            )
        self.assertEqual(count, 0)

    def test_lifecycle_operations_reject_foreign_owner(self):
        store = self.make_store()
        conversation_id = store.create_conversation("owner-a", "Private")
        for operation in (
            lambda: store.rename_conversation("owner-b", conversation_id, "stolen"),
            lambda: store.set_archived("owner-b", conversation_id, True),
            lambda: store.delete_conversation("owner-b", conversation_id),
        ):
            with self.assertRaises(KeyError):
                operation()

    def test_empty_rename_is_rejected(self):
        store = self.make_store()
        conversation_id = store.create_conversation("owner-a", "Private")
        with self.assertRaisesRegex(ValueError, "cannot be empty"):
            store.rename_conversation("owner-a", conversation_id, "   ")


if __name__ == "__main__":
    unittest.main()
