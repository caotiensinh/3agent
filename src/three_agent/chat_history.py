from __future__ import annotations

import re
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Tokyo")
_CONVERSATION_ID_RE = re.compile(r"^[a-f0-9]{16}$")
_VALID_ROLES = {"user", "assistant"}


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class ChatHistoryStore:
    """Persistent, owner-scoped WorkSpace conversation history.

    The store intentionally keeps only chat text and compact task/job references.
    Upload contents, credentials, browser session IDs, and filesystem paths are not
    copied into the history tables.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, factory=_ClosingConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(TZ).isoformat()

    @staticmethod
    def _conversation_id(value: str) -> str:
        candidate = str(value or "").strip().lower()
        if not _CONVERSATION_ID_RE.fullmatch(candidate):
            raise ValueError("Invalid conversation_id")
        return candidate

    @staticmethod
    def _title(value: str) -> str:
        text = " ".join(str(value or "").split()).strip()
        return (text or "New chat")[:96]

    @staticmethod
    def _like_literal(value: str) -> str:
        return (
            str(value or "")
            .replace("\\", "\\\\")
            .replace("%", "\\%")
            .replace("_", "\\_")
        )

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS chat_conversations (
                    conversation_id TEXT PRIMARY KEY,
                    owner_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    pinned INTEGER NOT NULL DEFAULT 0 CHECK(pinned IN (0, 1)),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_chat_conversations_owner_updated
                    ON chat_conversations(owner_key, pinned DESC, updated_at DESC);

                CREATE TABLE IF NOT EXISTS chat_messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK(role IN ('user', 'assistant')),
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
                CREATE INDEX IF NOT EXISTS idx_chat_messages_conversation
                    ON chat_messages(conversation_id, id);
                CREATE INDEX IF NOT EXISTS idx_chat_messages_job
                    ON chat_messages(job_id);
                """
            )

    def create_conversation(self, owner_key: str, title: str) -> str:
        owner = str(owner_key or "").strip()
        if not owner:
            raise ValueError("owner_key is required")
        conversation_id = uuid.uuid4().hex[:16]
        now = self._now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO chat_conversations(
                    conversation_id,owner_key,title,pinned,created_at,updated_at
                ) VALUES(?,?,?,0,?,?)
                """,
                (conversation_id, owner, self._title(title), now, now),
            )
        return conversation_id

    def ensure_conversation(
        self,
        owner_key: str,
        conversation_id: str | None,
        title: str,
    ) -> str:
        if not conversation_id:
            return self.create_conversation(owner_key, title)
        value = self._conversation_id(conversation_id)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT conversation_id
                FROM chat_conversations
                WHERE conversation_id = ? AND owner_key = ?
                """,
                (value, owner_key),
            ).fetchone()
        if row is None:
            raise ValueError("Conversation is unavailable for this WorkSpace user")
        return value

    def record_message(
        self,
        conversation_id: str,
        *,
        role: str,
        content: str,
        job_id: str,
        task_id: str = "",
        status: str = "completed",
    ) -> None:
        value = self._conversation_id(conversation_id)
        if role not in _VALID_ROLES:
            raise ValueError("Unsupported chat history role")
        job = str(job_id or "").strip()
        if not job:
            raise ValueError("job_id is required")
        text = str(content or "")
        now = self._now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO chat_messages(
                    conversation_id,role,content,job_id,task_id,status,created_at
                ) VALUES(?,?,?,?,?,?,?)
                ON CONFLICT(conversation_id,role,job_id) DO UPDATE SET
                    content=excluded.content,
                    task_id=excluded.task_id,
                    status=excluded.status
                """,
                (
                    value,
                    role,
                    text,
                    job[:64],
                    str(task_id or "")[:96],
                    str(status or "completed")[:32],
                    now,
                ),
            )
            conn.execute(
                """
                UPDATE chat_conversations
                SET updated_at = ?
                WHERE conversation_id = ?
                """,
                (now, value),
            )

    def link_task(self, conversation_id: str, job_id: str, task_id: str) -> None:
        value = self._conversation_id(conversation_id)
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE chat_messages
                SET task_id = ?
                WHERE conversation_id = ? AND job_id = ?
                """,
                (str(task_id or "")[:96], value, str(job_id or "")[:64]),
            )

    def _owned_row(self, owner_key: str, conversation_id: str) -> sqlite3.Row:
        value = self._conversation_id(conversation_id)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT conversation_id,title,pinned,created_at,updated_at
                FROM chat_conversations
                WHERE conversation_id = ? AND owner_key = ?
                """,
                (value, owner_key),
            ).fetchone()
        if row is None:
            raise KeyError("Conversation not found")
        return row

    def get_conversation(self, owner_key: str, conversation_id: str) -> dict[str, Any]:
        row = self._owned_row(owner_key, conversation_id)
        with self.connect() as conn:
            messages = conn.execute(
                """
                SELECT role,content,job_id,task_id,status,created_at
                FROM chat_messages
                WHERE conversation_id = ?
                ORDER BY id
                """,
                (row["conversation_id"],),
            ).fetchall()
        return {
            "conversation_id": str(row["conversation_id"]),
            "title": str(row["title"]),
            "pinned": bool(row["pinned"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "messages": [
                {
                    "role": str(message["role"]),
                    "content": str(message["content"]),
                    "job_id": str(message["job_id"]),
                    "task_id": str(message["task_id"]),
                    "status": str(message["status"]),
                    "created_at": str(message["created_at"]),
                }
                for message in messages
            ],
        }

    def list_conversations(
        self,
        owner_key: str,
        *,
        query: str = "",
        limit: int = 80,
    ) -> list[dict[str, Any]]:
        maximum = max(1, min(200, int(limit)))
        search = " ".join(str(query or "").split()).strip()
        params: list[Any] = [owner_key]
        where = "c.owner_key = ?"
        if search:
            pattern = f"%{self._like_literal(search)}%"
            where += (
                " AND (c.title COLLATE NOCASE LIKE ? ESCAPE '\\' "
                "OR EXISTS ("
                "SELECT 1 FROM chat_messages sm "
                "WHERE sm.conversation_id = c.conversation_id "
                "AND sm.content COLLATE NOCASE LIKE ? ESCAPE '\\'"
                "))"
            )
            params.extend([pattern, pattern])
        params.append(maximum)
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    c.conversation_id,
                    c.title,
                    c.pinned,
                    c.created_at,
                    c.updated_at,
                    (
                        SELECT m.content
                        FROM chat_messages m
                        WHERE m.conversation_id = c.conversation_id
                        ORDER BY m.id DESC
                        LIMIT 1
                    ) AS last_message,
                    (
                        SELECT COUNT(*)
                        FROM chat_messages mc
                        WHERE mc.conversation_id = c.conversation_id
                    ) AS message_count
                FROM chat_conversations c
                WHERE {where}
                ORDER BY c.pinned DESC, c.updated_at DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        return [
            {
                "conversation_id": str(row["conversation_id"]),
                "title": str(row["title"]),
                "pinned": bool(row["pinned"]),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
                "last_message": str(row["last_message"] or "")[:240],
                "message_count": int(row["message_count"]),
            }
            for row in rows
        ]

    def set_pinned(
        self,
        owner_key: str,
        conversation_id: str,
        pinned: bool,
    ) -> dict[str, Any]:
        row = self._owned_row(owner_key, conversation_id)
        now = self._now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE chat_conversations
                SET pinned = ?, updated_at = ?
                WHERE conversation_id = ? AND owner_key = ?
                """,
                (
                    1 if pinned else 0,
                    now,
                    str(row["conversation_id"]),
                    owner_key,
                ),
            )
        return self.get_conversation(owner_key, str(row["conversation_id"]))


class ConversationHistoryStore(ChatHistoryStore):
    """Owner-scoped conversation lifecycle on top of the v5 history schema.

    The migration is intentionally additive: existing conversations remain active,
    while rename/archive/delete operations always require the exact owner key.
    """

    def initialize(self) -> None:
        super().initialize()
        with self.connect() as conn:
            columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(chat_conversations)").fetchall()
            }
            if "archived" not in columns:
                conn.execute(
                    """
                    ALTER TABLE chat_conversations
                    ADD COLUMN archived INTEGER NOT NULL DEFAULT 0
                    CHECK(archived IN (0, 1))
                    """
                )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_chat_conversations_owner_archive_updated
                ON chat_conversations(owner_key, archived, pinned DESC, updated_at DESC)
                """
            )

    def ensure_conversation(
        self,
        owner_key: str,
        conversation_id: str | None,
        title: str,
    ) -> str:
        if not conversation_id:
            return self.create_conversation(owner_key, title)
        value = self._conversation_id(conversation_id)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT conversation_id
                FROM chat_conversations
                WHERE conversation_id = ? AND owner_key = ? AND archived = 0
                """,
                (value, owner_key),
            ).fetchone()
        if row is None:
            raise ValueError(
                "Conversation is unavailable or archived for this WorkSpace user"
            )
        return value

    def _owned_row(self, owner_key: str, conversation_id: str):
        value = self._conversation_id(conversation_id)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT conversation_id,title,pinned,archived,created_at,updated_at
                FROM chat_conversations
                WHERE conversation_id = ? AND owner_key = ?
                """,
                (value, owner_key),
            ).fetchone()
        if row is None:
            raise KeyError("Conversation not found")
        return row

    def get_conversation(self, owner_key: str, conversation_id: str) -> dict[str, Any]:
        payload = super().get_conversation(owner_key, conversation_id)
        row = self._owned_row(owner_key, conversation_id)
        payload["archived"] = bool(row["archived"])
        return payload

    def list_conversations(
        self,
        owner_key: str,
        *,
        query: str = "",
        limit: int = 80,
        archived: bool | None = False,
    ) -> list[dict[str, Any]]:
        maximum = max(1, min(200, int(limit)))
        search = " ".join(str(query or "").split()).strip()
        params: list[Any] = [owner_key]
        where = "c.owner_key = ?"
        if archived is not None:
            where += " AND c.archived = ?"
            params.append(1 if archived else 0)
        if search:
            pattern = f"%{self._like_literal(search)}%"
            where += (
                " AND (c.title COLLATE NOCASE LIKE ? ESCAPE '\\' "
                "OR EXISTS ("
                "SELECT 1 FROM chat_messages sm "
                "WHERE sm.conversation_id = c.conversation_id "
                "AND sm.content COLLATE NOCASE LIKE ? ESCAPE '\\'"
                "))"
            )
            params.extend([pattern, pattern])
        params.append(maximum)
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    c.conversation_id,
                    c.title,
                    c.pinned,
                    c.archived,
                    c.created_at,
                    c.updated_at,
                    (
                        SELECT m.content
                        FROM chat_messages m
                        WHERE m.conversation_id = c.conversation_id
                        ORDER BY m.id DESC
                        LIMIT 1
                    ) AS last_message,
                    (
                        SELECT COUNT(*)
                        FROM chat_messages mc
                        WHERE mc.conversation_id = c.conversation_id
                    ) AS message_count
                FROM chat_conversations c
                WHERE {where}
                ORDER BY c.pinned DESC, c.updated_at DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        return [
            {
                "conversation_id": str(row["conversation_id"]),
                "title": str(row["title"]),
                "pinned": bool(row["pinned"]),
                "archived": bool(row["archived"]),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
                "last_message": str(row["last_message"] or "")[:240],
                "message_count": int(row["message_count"]),
            }
            for row in rows
        ]

    def rename_conversation(
        self,
        owner_key: str,
        conversation_id: str,
        title: str,
    ) -> dict[str, Any]:
        row = self._owned_row(owner_key, conversation_id)
        normalized = " ".join(str(title or "").split()).strip()
        if not normalized:
            raise ValueError("Conversation title cannot be empty")
        now = self._now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE chat_conversations
                SET title = ?, updated_at = ?
                WHERE conversation_id = ? AND owner_key = ?
                """,
                (
                    normalized[:96],
                    now,
                    str(row["conversation_id"]),
                    owner_key,
                ),
            )
        return self.get_conversation(owner_key, str(row["conversation_id"]))

    def set_archived(
        self,
        owner_key: str,
        conversation_id: str,
        archived: bool,
    ) -> dict[str, Any]:
        row = self._owned_row(owner_key, conversation_id)
        now = self._now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE chat_conversations
                SET archived = ?,
                    pinned = CASE WHEN ? = 1 THEN 0 ELSE pinned END,
                    updated_at = ?
                WHERE conversation_id = ? AND owner_key = ?
                """,
                (
                    1 if archived else 0,
                    1 if archived else 0,
                    now,
                    str(row["conversation_id"]),
                    owner_key,
                ),
            )
        return self.get_conversation(owner_key, str(row["conversation_id"]))

    def set_pinned(
        self,
        owner_key: str,
        conversation_id: str,
        pinned: bool,
    ) -> dict[str, Any]:
        row = self._owned_row(owner_key, conversation_id)
        if pinned and bool(row["archived"]):
            raise ValueError("Archived conversations cannot be pinned")
        now = self._now()
        with self.connect() as conn:
            conn.execute(
                """
                UPDATE chat_conversations
                SET pinned = ?, updated_at = ?
                WHERE conversation_id = ? AND owner_key = ?
                """,
                (
                    1 if pinned else 0,
                    now,
                    str(row["conversation_id"]),
                    owner_key,
                ),
            )
        return self.get_conversation(owner_key, str(row["conversation_id"]))

    def delete_conversation(self, owner_key: str, conversation_id: str) -> dict[str, Any]:
        row = self._owned_row(owner_key, conversation_id)
        value = str(row["conversation_id"])
        with self.connect() as conn:
            cursor = conn.execute(
                """
                DELETE FROM chat_conversations
                WHERE conversation_id = ? AND owner_key = ?
                """,
                (value, owner_key),
            )
            if int(cursor.rowcount or 0) != 1:
                raise KeyError("Conversation not found")
        return {"conversation_id": value, "deleted": True}


_PROJECT_ID_RE = re.compile(r"^[a-f0-9]{16}$")


class ProjectConversationStore(ConversationHistoryStore):
    """Owner-scoped WorkSpace projects layered on conversation history.

    Projects organize conversations only. Deleting a project never deletes chats;
    its conversations are detached back to the unfiled chat list. Project and
    conversation ownership are always checked server-side.
    """

    @staticmethod
    def _project_id(value: str) -> str:
        candidate = str(value or "").strip().lower()
        if not _PROJECT_ID_RE.fullmatch(candidate):
            raise ValueError("Invalid project_id")
        return candidate

    @staticmethod
    def _project_name(value: str) -> str:
        text = " ".join(str(value or "").split()).strip()
        if not text:
            raise ValueError("Project name cannot be empty")
        return text[:64]

    def initialize(self) -> None:
        super().initialize()
        with self.connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS workspace_projects (
                    project_id TEXT PRIMARY KEY,
                    owner_key TEXT NOT NULL,
                    name TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(owner_key, name COLLATE NOCASE)
                )
                """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_workspace_projects_owner_updated
                ON workspace_projects(owner_key, updated_at DESC)
                """
            )
            columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(chat_conversations)").fetchall()
            }
            if "project_id" not in columns:
                conn.execute(
                    """
                    ALTER TABLE chat_conversations
                    ADD COLUMN project_id TEXT NOT NULL DEFAULT ''
                    """
                )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_chat_conversations_owner_project_updated
                ON chat_conversations(owner_key, project_id, archived, updated_at DESC)
                """
            )

    def _owned_project(self, owner_key: str, project_id: str):
        value = self._project_id(project_id)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT project_id,name,created_at,updated_at
                FROM workspace_projects
                WHERE project_id = ? AND owner_key = ?
                """,
                (value, owner_key),
            ).fetchone()
        if row is None:
            raise KeyError("Project not found")
        return row

    def create_project(self, owner_key: str, name: str) -> dict[str, Any]:
        owner = str(owner_key or "").strip()
        if not owner:
            raise ValueError("owner_key is required")
        project_id = uuid.uuid4().hex[:16]
        normalized = self._project_name(name)
        now = self._now()
        try:
            with self.connect() as conn:
                conn.execute(
                    """
                    INSERT INTO workspace_projects(project_id,owner_key,name,created_at,updated_at)
                    VALUES(?,?,?,?,?)
                    """,
                    (project_id, owner, normalized, now, now),
                )
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise ValueError("A project with this name already exists") from exc
            raise
        return self.get_project(owner, project_id)

    def get_project(self, owner_key: str, project_id: str) -> dict[str, Any]:
        row = self._owned_project(owner_key, project_id)
        with self.connect() as conn:
            counts = conn.execute(
                """
                SELECT
                    COUNT(*) AS total_count,
                    SUM(CASE WHEN archived = 0 THEN 1 ELSE 0 END) AS active_count
                FROM chat_conversations
                WHERE owner_key = ? AND project_id = ?
                """,
                (owner_key, str(row["project_id"])),
            ).fetchone()
        return {
            "project_id": str(row["project_id"]),
            "name": str(row["name"]),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "conversation_count": int(counts["active_count"] or 0),
            "total_conversation_count": int(counts["total_count"] or 0),
        }

    def list_projects(self, owner_key: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    p.project_id,p.name,p.created_at,p.updated_at,
                    SUM(CASE WHEN c.archived = 0 THEN 1 ELSE 0 END) AS active_count,
                    COUNT(c.conversation_id) AS total_count
                FROM workspace_projects p
                LEFT JOIN chat_conversations c
                    ON c.owner_key = p.owner_key AND c.project_id = p.project_id
                WHERE p.owner_key = ?
                GROUP BY p.project_id,p.name,p.created_at,p.updated_at
                ORDER BY p.updated_at DESC, p.name COLLATE NOCASE
                """,
                (owner_key,),
            ).fetchall()
        return [
            {
                "project_id": str(row["project_id"]),
                "name": str(row["name"]),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
                "conversation_count": int(row["active_count"] or 0),
                "total_conversation_count": int(row["total_count"] or 0),
            }
            for row in rows
        ]

    def rename_project(self, owner_key: str, project_id: str, name: str) -> dict[str, Any]:
        row = self._owned_project(owner_key, project_id)
        normalized = self._project_name(name)
        now = self._now()
        try:
            with self.connect() as conn:
                conn.execute(
                    """
                    UPDATE workspace_projects
                    SET name = ?, updated_at = ?
                    WHERE project_id = ? AND owner_key = ?
                    """,
                    (normalized, now, str(row["project_id"]), owner_key),
                )
        except Exception as exc:
            if "UNIQUE constraint failed" in str(exc):
                raise ValueError("A project with this name already exists") from exc
            raise
        return self.get_project(owner_key, str(row["project_id"]))

    def delete_project(self, owner_key: str, project_id: str) -> dict[str, Any]:
        row = self._owned_project(owner_key, project_id)
        value = str(row["project_id"])
        now = self._now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            detached = conn.execute(
                """
                UPDATE chat_conversations
                SET project_id = '', updated_at = ?
                WHERE owner_key = ? AND project_id = ?
                """,
                (now, owner_key, value),
            ).rowcount
            deleted = conn.execute(
                """
                DELETE FROM workspace_projects
                WHERE owner_key = ? AND project_id = ?
                """,
                (owner_key, value),
            ).rowcount
            if int(deleted or 0) != 1:
                raise KeyError("Project not found")
        return {
            "project_id": value,
            "deleted": True,
            "detached_conversations": max(0, int(detached or 0)),
        }

    def move_conversation(
        self,
        owner_key: str,
        conversation_id: str,
        project_id: str | None,
    ) -> dict[str, Any]:
        row = self._owned_row(owner_key, conversation_id)
        target = str(project_id or "").strip().lower()
        if target:
            project = self._owned_project(owner_key, target)
            target = str(project["project_id"])
        now = self._now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                UPDATE chat_conversations
                SET project_id = ?, updated_at = ?
                WHERE conversation_id = ? AND owner_key = ?
                """,
                (target, now, str(row["conversation_id"]), owner_key),
            )
            if target:
                conn.execute(
                    """
                    UPDATE workspace_projects SET updated_at = ?
                    WHERE project_id = ? AND owner_key = ?
                    """,
                    (now, target, owner_key),
                )
        return self.get_conversation(owner_key, str(row["conversation_id"]))

    def get_conversation(self, owner_key: str, conversation_id: str) -> dict[str, Any]:
        payload = super().get_conversation(owner_key, conversation_id)
        value = self._conversation_id(conversation_id)
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT project_id FROM chat_conversations
                WHERE conversation_id = ? AND owner_key = ?
                """,
                (value, owner_key),
            ).fetchone()
        if row is None:
            raise KeyError("Conversation not found")
        payload["project_id"] = str(row["project_id"] or "")
        return payload

    def list_conversations(
        self,
        owner_key: str,
        *,
        query: str = "",
        limit: int = 80,
        archived: bool | None = False,
        project_id: str | None = None,
    ) -> list[dict[str, Any]]:
        maximum = max(1, min(200, int(limit)))
        search = " ".join(str(query or "").split()).strip()
        params: list[Any] = [owner_key]
        where = "c.owner_key = ?"
        if archived is not None:
            where += " AND c.archived = ?"
            params.append(1 if archived else 0)
        if project_id is not None:
            target = str(project_id or "").strip().lower()
            if target:
                self._owned_project(owner_key, target)
            where += " AND c.project_id = ?"
            params.append(target)
        if search:
            pattern = f"%{self._like_literal(search)}%"
            where += (
                " AND (c.title COLLATE NOCASE LIKE ? ESCAPE '\\' "
                "OR EXISTS (SELECT 1 FROM chat_messages sm "
                "WHERE sm.conversation_id = c.conversation_id "
                "AND sm.content COLLATE NOCASE LIKE ? ESCAPE '\\'))"
            )
            params.extend([pattern, pattern])
        params.append(maximum)
        with self.connect() as conn:
            rows = conn.execute(
                f"""
                SELECT c.conversation_id,c.title,c.pinned,c.archived,c.project_id,
                       c.created_at,c.updated_at,
                       (SELECT m.content FROM chat_messages m
                        WHERE m.conversation_id=c.conversation_id
                        ORDER BY m.id DESC LIMIT 1) AS last_message,
                       (SELECT COUNT(*) FROM chat_messages mc
                        WHERE mc.conversation_id=c.conversation_id) AS message_count
                FROM chat_conversations c
                WHERE {where}
                ORDER BY c.pinned DESC,c.updated_at DESC
                LIMIT ?
                """,
                tuple(params),
            ).fetchall()
        return [
            {
                "conversation_id": str(row["conversation_id"]),
                "title": str(row["title"]),
                "pinned": bool(row["pinned"]),
                "archived": bool(row["archived"]),
                "project_id": str(row["project_id"] or ""),
                "created_at": str(row["created_at"]),
                "updated_at": str(row["updated_at"]),
                "last_message": str(row["last_message"] or "")[:240],
                "message_count": int(row["message_count"]),
            }
            for row in rows
        ]
