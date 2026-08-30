from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from three_agent.chat_history_v3 import ProjectConversationStore


class ProjectConversationStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def store(self) -> ProjectConversationStore:
        store = ProjectConversationStore(self.root / "workspace.db")
        store.initialize()
        return store

    def test_project_migration_preserves_existing_conversations(self) -> None:
        db = self.root / "workspace.db"
        conn = sqlite3.connect(db)
        conn.executescript(
            """
            CREATE TABLE chat_conversations (
                conversation_id TEXT PRIMARY KEY,
                owner_key TEXT NOT NULL,
                title TEXT NOT NULL,
                pinned INTEGER NOT NULL DEFAULT 0,
                archived INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                conversation_id TEXT NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                job_id TEXT NOT NULL,
                task_id TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'completed',
                created_at TEXT NOT NULL,
                FOREIGN KEY(conversation_id)
                    REFERENCES chat_conversations(conversation_id)
                    ON DELETE CASCADE,
                UNIQUE(conversation_id, role, job_id)
            );
            INSERT INTO chat_conversations VALUES(
                'aaaaaaaaaaaaaaaa','owner-a','Existing',0,0,
                '2026-08-30T00:00:00+09:00','2026-08-30T00:00:00+09:00'
            );
            """
        )
        conn.commit()
        conn.close()

        store = ProjectConversationStore(db)
        store.initialize()

        chat = store.get_conversation("owner-a", "aaaaaaaaaaaaaaaa")
        self.assertEqual(chat["project_id"], "")
        with store.connect() as check:
            columns = {
                row["name"]
                for row in check.execute(
                    "PRAGMA table_info(chat_conversations)"
                ).fetchall()
            }
            self.assertIn("project_id", columns)
            self.assertEqual(
                check.execute("SELECT COUNT(*) FROM workspace_projects").fetchone()[0],
                0,
            )

    def test_project_create_move_rename_and_delete_detaches_chat(self) -> None:
        store = self.store()
        conversation_id = store.create_conversation("owner-a", "Network review")
        project = store.create_project("owner-a", "Network")

        moved = store.move_conversation(
            "owner-a", conversation_id, project["project_id"]
        )
        self.assertEqual(moved["project_id"], project["project_id"])
        self.assertEqual(store.list_projects("owner-a")[0]["conversation_count"], 1)
        self.assertEqual(
            store.list_conversations(
                "owner-a", project_id=project["project_id"]
            )[0]["conversation_id"],
            conversation_id,
        )

        renamed = store.rename_project(
            "owner-a", project["project_id"], "R&D Network"
        )
        self.assertEqual(renamed["name"], "R&D Network")

        deleted = store.delete_project("owner-a", project["project_id"])
        self.assertTrue(deleted["deleted"])
        self.assertEqual(deleted["detached_conversations"], 1)
        self.assertEqual(
            store.get_conversation("owner-a", conversation_id)["project_id"], ""
        )
        self.assertEqual(store.list_projects("owner-a"), [])

    def test_project_operations_fail_closed_across_owners(self) -> None:
        store = self.store()
        conversation_id = store.create_conversation("owner-a", "Secret")
        project = store.create_project("owner-a", "Private")
        other_project = store.create_project("owner-b", "Other")

        with self.assertRaises(KeyError):
            store.rename_project("owner-b", project["project_id"], "Stolen")
        with self.assertRaises(KeyError):
            store.delete_project("owner-b", project["project_id"])
        with self.assertRaises(KeyError):
            store.move_conversation(
                "owner-b", conversation_id, project["project_id"]
            )
        with self.assertRaises(KeyError):
            store.move_conversation(
                "owner-a", conversation_id, other_project["project_id"]
            )

        self.assertEqual(
            store.get_conversation("owner-a", conversation_id)["project_id"], ""
        )

    def test_project_names_are_owner_local_and_duplicate_names_rejected(self) -> None:
        store = self.store()
        store.create_project("owner-a", "Animal")
        store.create_project("owner-b", "Animal")

        with self.assertRaisesRegex(ValueError, "already exists"):
            store.create_project("owner-a", "animal")

    def test_unfiled_filter_and_archive_state_work_with_projects(self) -> None:
        store = self.store()
        unfiled = store.create_conversation("owner-a", "Unfiled")
        filed = store.create_conversation("owner-a", "Filed")
        project = store.create_project("owner-a", "AI")
        store.move_conversation("owner-a", filed, project["project_id"])
        store.set_archived("owner-a", filed, True)

        self.assertEqual(
            [
                item["conversation_id"]
                for item in store.list_conversations("owner-a", project_id="")
            ],
            [unfiled],
        )
        archived = store.list_conversations(
            "owner-a", archived=True, project_id=project["project_id"]
        )
        self.assertEqual(
            [item["conversation_id"] for item in archived],
            [filed],
        )


if __name__ == "__main__":
    unittest.main()
