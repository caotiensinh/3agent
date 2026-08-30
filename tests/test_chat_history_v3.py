from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from three_agent.chat_history_v3 import ProjectConversationStore


def _store(tmp_path: Path) -> ProjectConversationStore:
    store = ProjectConversationStore(tmp_path / "workspace.db")
    store.initialize()
    return store


def test_project_migration_preserves_existing_conversations(tmp_path: Path) -> None:
    db = tmp_path / "workspace.db"
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
            FOREIGN KEY(conversation_id) REFERENCES chat_conversations(conversation_id) ON DELETE CASCADE,
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
    assert chat["project_id"] == ""
    with store.connect() as check:
        columns = {row["name"] for row in check.execute("PRAGMA table_info(chat_conversations)")}
        assert "project_id" in columns
        assert check.execute("SELECT COUNT(*) FROM workspace_projects").fetchone()[0] == 0


def test_project_create_move_rename_and_delete_detaches_chat(tmp_path: Path) -> None:
    store = _store(tmp_path)
    conversation_id = store.create_conversation("owner-a", "Network review")
    project = store.create_project("owner-a", "Network")

    moved = store.move_conversation("owner-a", conversation_id, project["project_id"])
    assert moved["project_id"] == project["project_id"]
    assert store.list_projects("owner-a")[0]["conversation_count"] == 1
    assert store.list_conversations(
        "owner-a", project_id=project["project_id"]
    )[0]["conversation_id"] == conversation_id

    renamed = store.rename_project("owner-a", project["project_id"], "R&D Network")
    assert renamed["name"] == "R&D Network"

    deleted = store.delete_project("owner-a", project["project_id"])
    assert deleted["deleted"] is True
    assert deleted["detached_conversations"] == 1
    assert store.get_conversation("owner-a", conversation_id)["project_id"] == ""
    assert store.list_projects("owner-a") == []


def test_project_operations_fail_closed_across_owners(tmp_path: Path) -> None:
    store = _store(tmp_path)
    conversation_id = store.create_conversation("owner-a", "Secret")
    project = store.create_project("owner-a", "Private")

    with pytest.raises(KeyError):
        store.rename_project("owner-b", project["project_id"], "Stolen")
    with pytest.raises(KeyError):
        store.delete_project("owner-b", project["project_id"])
    with pytest.raises(KeyError):
        store.move_conversation("owner-b", conversation_id, project["project_id"])
    with pytest.raises(KeyError):
        store.move_conversation("owner-a", conversation_id, store.create_project("owner-b", "Other")["project_id"])

    assert store.get_conversation("owner-a", conversation_id)["project_id"] == ""


def test_project_names_are_owner_local_and_duplicate_names_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.create_project("owner-a", "Animal")
    store.create_project("owner-b", "Animal")

    with pytest.raises(ValueError, match="already exists"):
        store.create_project("owner-a", "animal")


def test_unfiled_filter_and_archive_state_work_with_projects(tmp_path: Path) -> None:
    store = _store(tmp_path)
    unfiled = store.create_conversation("owner-a", "Unfiled")
    filed = store.create_conversation("owner-a", "Filed")
    project = store.create_project("owner-a", "AI")
    store.move_conversation("owner-a", filed, project["project_id"])
    store.set_archived("owner-a", filed, True)

    assert [x["conversation_id"] for x in store.list_conversations("owner-a", project_id="")] == [unfiled]
    archived = store.list_conversations(
        "owner-a", archived=True, project_id=project["project_id"]
    )
    assert [x["conversation_id"] for x in archived] == [filed]
