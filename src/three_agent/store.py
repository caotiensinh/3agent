from __future__ import annotations

import sqlite3
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .models import Task, TaskStatus

TZ = ZoneInfo("Asia/Tokyo")


class _ClosingConnection(sqlite3.Connection):
    """Connection that closes its database handle after a ``with`` scope."""

    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class TaskStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, factory=_ClosingConnection)
        conn.row_factory = sqlite3.Row
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    title TEXT NOT NULL,
                    request TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS activities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    task_id TEXT,
                    agent_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details TEXT NOT NULL DEFAULT ''
                );
                CREATE TABLE IF NOT EXISTS artifacts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    task_id TEXT,
                    agent_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    metadata TEXT NOT NULL DEFAULT '{}'
                );
                CREATE TABLE IF NOT EXISTS task_uploads (
                    task_id TEXT NOT NULL,
                    upload_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(task_id, upload_id),
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                """
            )

    def _next_task_id(self) -> str:
        today = datetime.now(TZ).strftime("%Y%m%d")
        prefix = f"TASK-{today}-"
        with self.connect() as conn:
            row = conn.execute(
                "SELECT task_id FROM tasks WHERE task_id LIKE ? ORDER BY task_id DESC LIMIT 1",
                (f"{prefix}%",),
            ).fetchone()
        seq = int(row["task_id"].split("-")[-1]) + 1 if row else 1
        return f"{prefix}{seq:04d}"

    def create_task(self, title: str, request: str) -> Task:
        now = datetime.now(TZ).isoformat()
        task = Task(self._next_task_id(), title, request, TaskStatus.NEW, now, now)
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO tasks(task_id,title,request,status,created_at,updated_at) VALUES(?,?,?,?,?,?)",
                (task.task_id, task.title, task.request, task.status.value, task.created_at, task.updated_at),
            )
        self.record_activity(task.task_id, "harness", "task_created", "ok", title)
        return task

    def get_task(self, task_id: str) -> Task:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE task_id = ?", (task_id,)).fetchone()
        if not row:
            raise KeyError(f"Unknown task_id: {task_id}")
        return Task(
            row["task_id"], row["title"], row["request"], TaskStatus(row["status"]), row["created_at"], row["updated_at"]
        )

    def list_tasks(self) -> list[Task]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM tasks ORDER BY created_at DESC").fetchall()
        return [
            Task(r["task_id"], r["title"], r["request"], TaskStatus(r["status"]), r["created_at"], r["updated_at"])
            for r in rows
        ]

    def tasks_for_date(self, date: str) -> list[sqlite3.Row]:
        """Return every task created, updated, or referenced by activity on a date."""
        with self.connect() as conn:
            return conn.execute(
                """
                SELECT * FROM tasks
                WHERE substr(created_at,1,10) = ?
                   OR substr(updated_at,1,10) = ?
                   OR task_id IN (
                        SELECT DISTINCT task_id
                        FROM activities
                        WHERE substr(timestamp,1,10) = ? AND task_id IS NOT NULL
                   )
                ORDER BY created_at, task_id
                """,
                (date, date, date),
            ).fetchall()

    def set_status(self, task_id: str, status: TaskStatus) -> Task:
        now = datetime.now(TZ).isoformat()
        with self.connect() as conn:
            conn.execute("UPDATE tasks SET status = ?, updated_at = ? WHERE task_id = ?", (status.value, now, task_id))
        return self.get_task(task_id)

    def attach_uploads(self, task_id: str, upload_ids: list[str]) -> None:
        if not upload_ids:
            return
        now = datetime.now(TZ).isoformat()
        with self.connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO task_uploads(task_id,upload_id,created_at) VALUES(?,?,?)",
                [(task_id, upload_id, now) for upload_id in upload_ids],
            )

    def upload_ids_for_task(self, task_id: str) -> list[str]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT upload_id FROM task_uploads WHERE task_id = ? ORDER BY created_at, upload_id",
                (task_id,),
            ).fetchall()
        return [str(row["upload_id"]) for row in rows]

    def record_activity(self, task_id: str | None, agent_id: str, action: str, status: str, details: str = "") -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO activities(timestamp,task_id,agent_id,action,status,details) VALUES(?,?,?,?,?,?)",
                (datetime.now(TZ).isoformat(), task_id, agent_id, action, status, details),
            )

    def activities_for_date(self, date: str) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM activities WHERE substr(timestamp,1,10) = ? ORDER BY timestamp, id",
                (date,),
            ).fetchall()

    def artifacts_for_date(self, date: str) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM artifacts WHERE substr(timestamp,1,10) = ? ORDER BY timestamp, id",
                (date,),
            ).fetchall()

    def record_artifact(self, task_id: str | None, agent_id: str, artifact_type: str, path: str, metadata: str = "{}") -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO artifacts(timestamp,task_id,agent_id,artifact_type,path,metadata) VALUES(?,?,?,?,?,?)",
                (datetime.now(TZ).isoformat(), task_id, agent_id, artifact_type, path, metadata),
            )
