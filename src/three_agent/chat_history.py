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
