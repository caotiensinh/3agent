from __future__ import annotations

import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Tokyo")
_CONVERSATION_ID_RE = re.compile(r"^[a-f0-9]{16}$")
_UPLOAD_ID_RE = re.compile(r"^[a-f0-9]{16}$")


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class ConversationAttachmentMemory:
    """Persist message-to-upload references without copying attachment contents.

    Raw bytes and extracted text remain in KnowledgeGateway. This table stores only
    opaque upload ids, scoped by conversation/job, so a later turn can re-resolve
    the most recent attachment through the normal owner validation path.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, factory=_ClosingConnection)
        conn.row_factory = sqlite3.Row
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
    def _upload_id(value: str) -> str:
        candidate = str(value or "").strip().lower()
        if not _UPLOAD_ID_RE.fullmatch(candidate):
            raise ValueError("Invalid upload_id")
        return candidate

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS chat_message_attachments (
                    conversation_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    upload_id TEXT NOT NULL,
                    ordinal INTEGER NOT NULL CHECK(ordinal >= 0),
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(conversation_id, job_id, upload_id)
                );
                CREATE INDEX IF NOT EXISTS idx_chat_message_attachments_recent
                    ON chat_message_attachments(conversation_id, created_at DESC, ordinal ASC);
                """
            )

    def record(
        self,
        conversation_id: str,
        job_id: str,
        upload_ids: Iterable[str],
    ) -> None:
        conversation = self._conversation_id(conversation_id)
        job = str(job_id or "").strip()[:64]
        if not job:
            raise ValueError("job_id is required")
        unique: list[str] = []
        for raw in upload_ids:
            upload_id = self._upload_id(raw)
            if upload_id not in unique:
                unique.append(upload_id)
        if not unique:
            return
        now = self._now()
        with self.connect() as conn:
            for ordinal, upload_id in enumerate(unique):
                conn.execute(
                    """
                    INSERT INTO chat_message_attachments(
                        conversation_id,job_id,upload_id,ordinal,created_at
                    ) VALUES(?,?,?,?,?)
                    ON CONFLICT(conversation_id,job_id,upload_id) DO UPDATE SET
                        ordinal=excluded.ordinal,
                        created_at=excluded.created_at
                    """,
                    (conversation, job, upload_id, ordinal, now),
                )

    def recent_upload_ids(
        self,
        conversation_id: str,
        *,
        exclude_job_id: str = "",
        max_messages: int = 2,
        max_uploads: int = 8,
    ) -> list[str]:
        """Return uploads from the most recent attachment-bearing user turns."""

        conversation = self._conversation_id(conversation_id)
        message_limit = max(1, min(8, int(max_messages)))
        upload_limit = max(1, min(16, int(max_uploads)))
        excluded = str(exclude_job_id or "").strip()[:64]
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT conversation_id,job_id,upload_id,ordinal,created_at
                FROM chat_message_attachments
                WHERE conversation_id = ? AND (? = '' OR job_id <> ?)
                ORDER BY created_at DESC, job_id DESC, ordinal ASC
                """,
                (conversation, excluded, excluded),
            ).fetchall()

        jobs: list[str] = []
        result: list[str] = []
        for row in rows:
            job = str(row["job_id"])
            if job not in jobs:
                if len(jobs) >= message_limit:
                    break
                jobs.append(job)
            upload_id = str(row["upload_id"])
            if upload_id not in result:
                result.append(upload_id)
            if len(result) >= upload_limit:
                break
        return result
