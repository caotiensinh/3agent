from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any
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
                CREATE TABLE IF NOT EXISTS task_contracts (
                    task_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    contract_json TEXT NOT NULL,
                    contract_sha256 TEXT NOT NULL,
                    bound_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE TABLE IF NOT EXISTS task_execution_budget_usage (
                    task_id TEXT PRIMARY KEY,
                    max_retries INTEGER NOT NULL,
                    max_escalations INTEGER NOT NULL,
                    retries_used INTEGER NOT NULL DEFAULT 0,
                    escalations_used INTEGER NOT NULL DEFAULT 0,
                    bound_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE TABLE IF NOT EXISTS validator_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    validator TEXT NOT NULL,
                    validator_version TEXT NOT NULL,
                    status TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    evidence_refs TEXT NOT NULL DEFAULT '[]',
                    attempt INTEGER NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_validator_results_task
                    ON validator_results(task_id, validator, id);
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

    @staticmethod
    def _canonical_json(payload: dict[str, Any]) -> tuple[str, str]:
        text = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()
        return text, digest

    def bind_task_contract(self, task_id: str, contract: dict[str, Any]) -> str:
        """Bind one immutable TaskContract payload to a task."""
        self.get_task(task_id)
        if not isinstance(contract, dict):
            raise TypeError("contract must be a dictionary")
        schema_version = str(contract.get("schema_version") or "").strip()
        if not schema_version:
            raise ValueError("contract schema_version is required")
        if str(contract.get("task_id") or "") != task_id:
            raise ValueError("contract task_id does not match task")

        text, digest = self._canonical_json(contract)
        now = datetime.now(TZ).isoformat()
        with self.connect() as conn:
            existing = conn.execute(
                "SELECT contract_sha256 FROM task_contracts WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if existing:
                if str(existing["contract_sha256"]) != digest:
                    raise ValueError("task contract is immutable once bound")
                return digest
            conn.execute(
                """
                INSERT INTO task_contracts(
                    task_id,schema_version,contract_json,contract_sha256,bound_at
                ) VALUES(?,?,?,?,?)
                """,
                (task_id, schema_version, text, digest, now),
            )
        self.record_activity(
            task_id,
            "validator_bus",
            "task_contract_bound",
            "ok",
            f"schema={schema_version} digest={digest}",
        )
        return digest

    def task_contract_for_task(self, task_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT contract_json FROM task_contracts WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(str(row["contract_json"]))
        return payload if isinstance(payload, dict) else None

    def task_contract_record(self, task_id: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM task_contracts WHERE task_id = ?",
                (task_id,),
            ).fetchone()

    @staticmethod
    def _budget_value(value: Any, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"{field} must be an integer >= 0")
        return value

    def _bound_execution_limits(self, task_id: str) -> tuple[int, int]:
        contract = self.task_contract_for_task(task_id)
        if contract is None:
            raise ValueError("TASK_CONTRACT_NOT_BOUND")
        execution = contract.get("execution_budget")
        if not isinstance(execution, dict):
            raise ValueError("BOUND_TASK_CONTRACT_EXECUTION_BUDGET_MISSING")
        retries = self._budget_value(execution.get("max_retries"), "max_retries")
        escalations = self._budget_value(execution.get("max_escalations"), "max_escalations")
        return retries, escalations

    def bind_task_execution_budget(self, task_id: str) -> dict[str, int | str]:
        """Persist immutable retry/escalation limits derived only from TaskContract.

        Rebinding after a process restart is idempotent and preserves usage. A
        caller cannot supply or inflate limits independently from the already-bound
        authoritative contract.
        """
        self.get_task(task_id)
        retries, escalations = self._bound_execution_limits(task_id)
        now = datetime.now(TZ).isoformat()
        created = False
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM task_execution_budget_usage WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO task_execution_budget_usage(
                        task_id,max_retries,max_escalations,retries_used,
                        escalations_used,bound_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (task_id, retries, escalations, 0, 0, now, now),
                )
                created = True
            elif int(row["max_retries"]) != retries or int(row["max_escalations"]) != escalations:
                raise ValueError("TASK_EXECUTION_BUDGET_IMMUTABLE_MISMATCH")
        if created:
            self.record_activity(
                task_id,
                "execution_budget",
                "execution_budget_bound",
                "ok",
                f"max_retries={retries} max_escalations={escalations}",
            )
        return self.task_execution_budget_for_task(task_id)

    def task_execution_budget_for_task(self, task_id: str) -> dict[str, int | str]:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM task_execution_budget_usage WHERE task_id = ?",
                (task_id,),
            ).fetchone()
        if row is None:
            raise ValueError("TASK_EXECUTION_BUDGET_NOT_BOUND")
        return {
            "task_id": str(row["task_id"]),
            "max_retries": int(row["max_retries"]),
            "max_escalations": int(row["max_escalations"]),
            "retries_used": int(row["retries_used"]),
            "escalations_used": int(row["escalations_used"]),
            "bound_at": str(row["bound_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def reserve_task_execution_budget(
        self,
        task_id: str,
        *,
        retries: int = 0,
        escalations: int = 0,
    ) -> dict[str, int | str]:
        retry_delta = self._budget_value(retries, "retries")
        escalation_delta = self._budget_value(escalations, "escalations")
        if retry_delta == 0 and escalation_delta == 0:
            return self.task_execution_budget_for_task(task_id)
        now = datetime.now(TZ).isoformat()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM task_execution_budget_usage WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if row is None:
                raise ValueError("TASK_EXECUTION_BUDGET_NOT_BOUND")
            current_retries = int(row["retries_used"])
            current_escalations = int(row["escalations_used"])
            max_retries = int(row["max_retries"])
            max_escalations = int(row["max_escalations"])
            new_retries = current_retries + retry_delta
            new_escalations = current_escalations + escalation_delta
            if new_retries > max_retries:
                raise ValueError("MODEL_RETRY_BUDGET_EXHAUSTED")
            if new_escalations > max_escalations:
                raise ValueError("MODEL_ESCALATION_BUDGET_EXHAUSTED")
            conn.execute(
                """
                UPDATE task_execution_budget_usage
                SET retries_used = ?, escalations_used = ?, updated_at = ?
                WHERE task_id = ?
                """,
                (new_retries, new_escalations, now, task_id),
            )
        return self.task_execution_budget_for_task(task_id)

    def record_validator_result(
        self,
        task_id: str,
        validator: str,
        validator_version: str,
        status: str,
        reason_code: str,
        evidence_refs: list[str],
        attempt: int,
    ) -> int:
        self.get_task(task_id)
        now = datetime.now(TZ).isoformat()
        refs_json = json.dumps(evidence_refs, ensure_ascii=False, separators=(",", ":"))
        with self.connect() as conn:
            cursor = conn.execute(
                """
                INSERT INTO validator_results(
                    timestamp,task_id,validator,validator_version,status,
                    reason_code,evidence_refs,attempt
                ) VALUES(?,?,?,?,?,?,?,?)
                """,
                (
                    now,
                    task_id,
                    validator,
                    validator_version,
                    status,
                    reason_code,
                    refs_json,
                    attempt,
                ),
            )
            result_id = int(cursor.lastrowid)
        return result_id

    def validator_results_for_task(self, task_id: str) -> list[sqlite3.Row]:
        with self.connect() as conn:
            return conn.execute(
                "SELECT * FROM validator_results WHERE task_id = ? ORDER BY id",
                (task_id,),
            ).fetchall()

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
