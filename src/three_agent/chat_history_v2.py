from __future__ import annotations

from typing import Any

from .chat_history import ChatHistoryStore


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
