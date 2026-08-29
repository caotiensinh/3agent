from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
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

    @staticmethod
    def _ensure_execution_budget_columns(conn: sqlite3.Connection) -> None:
        """Forward-migrate D6 retry/escalation rows to the complete D0 budget state."""
        rows = conn.execute("PRAGMA table_info(task_execution_budget_usage)").fetchall()
        present = {str(row["name"]) for row in rows}
        additions = (
            ("max_steps", "max_steps INTEGER NOT NULL DEFAULT -1"),
            ("max_tool_calls", "max_tool_calls INTEGER NOT NULL DEFAULT -1"),
            ("max_wall_time_ms", "max_wall_time_ms INTEGER NOT NULL DEFAULT -1"),
            ("steps_used", "steps_used INTEGER NOT NULL DEFAULT 0"),
            ("tool_calls_used", "tool_calls_used INTEGER NOT NULL DEFAULT 0"),
            ("deadline_at", "deadline_at TEXT NOT NULL DEFAULT ''"),
        )
        for name, ddl in additions:
            if name not in present:
                conn.execute(f"ALTER TABLE task_execution_budget_usage ADD COLUMN {ddl}")

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
                    max_steps INTEGER NOT NULL,
                    max_tool_calls INTEGER NOT NULL,
                    max_retries INTEGER NOT NULL,
                    max_escalations INTEGER NOT NULL,
                    max_wall_time_ms INTEGER NOT NULL,
                    steps_used INTEGER NOT NULL DEFAULT 0,
                    tool_calls_used INTEGER NOT NULL DEFAULT 0,
                    retries_used INTEGER NOT NULL DEFAULT 0,
                    escalations_used INTEGER NOT NULL DEFAULT 0,
                    deadline_at TEXT NOT NULL,
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
            self._ensure_execution_budget_columns(conn)

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

    def _bound_execution_limits(self, task_id: str) -> tuple[int, int, int, int, int]:
        contract = self.task_contract_for_task(task_id)
        if contract is None:
            raise ValueError("TASK_CONTRACT_NOT_BOUND")
        execution = contract.get("execution_budget")
        if not isinstance(execution, dict):
            raise ValueError("BOUND_TASK_CONTRACT_EXECUTION_BUDGET_MISSING")
        return (
            self._budget_value(execution.get("max_steps"), "max_steps"),
            self._budget_value(execution.get("max_tool_calls"), "max_tool_calls"),
            self._budget_value(execution.get("max_retries"), "max_retries"),
            self._budget_value(execution.get("max_escalations"), "max_escalations"),
            self._budget_value(execution.get("max_wall_time_ms"), "max_wall_time_ms"),
        )

    @staticmethod
    def _deadline(bound_at: str, max_wall_time_ms: int) -> str:
        started = datetime.fromisoformat(str(bound_at))
        if started.tzinfo is None:
            started = started.replace(tzinfo=TZ)
        return (started + timedelta(milliseconds=max_wall_time_ms)).isoformat()

    @staticmethod
    def _deadline_expired(deadline_at: str, now: datetime) -> bool:
        try:
            deadline = datetime.fromisoformat(str(deadline_at))
        except ValueError as exc:
            raise ValueError("TASK_EXECUTION_BUDGET_DEADLINE_INVALID") from exc
        if deadline.tzinfo is None:
            deadline = deadline.replace(tzinfo=TZ)
        return now >= deadline

    def bind_task_execution_budget(self, task_id: str) -> dict[str, int | str]:
        """Persist all immutable execution limits derived only from TaskContract.

        Rebinding after a restart is idempotent and preserves counters/deadline.
        Existing D6 retry/escalation rows are forward-migrated without extending
        their original bound-at wall-time window.
        """
        self.get_task(task_id)
        max_steps, max_tools, retries, escalations, max_wall = self._bound_execution_limits(task_id)
        now = datetime.now(TZ)
        now_text = now.isoformat()
        created = False
        migrated = False
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM task_execution_budget_usage WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if row is None:
                deadline = self._deadline(now_text, max_wall)
                conn.execute(
                    """
                    INSERT INTO task_execution_budget_usage(
                        task_id,max_steps,max_tool_calls,max_retries,max_escalations,
                        max_wall_time_ms,steps_used,tool_calls_used,retries_used,
                        escalations_used,deadline_at,bound_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        task_id, max_steps, max_tools, retries, escalations, max_wall,
                        0, 0, 0, 0, deadline, now_text, now_text,
                    ),
                )
                created = True
            else:
                if int(row["max_retries"]) != retries or int(row["max_escalations"]) != escalations:
                    raise ValueError("TASK_EXECUTION_BUDGET_IMMUTABLE_MISMATCH")
                legacy = (
                    int(row["max_steps"]) < 0
                    or int(row["max_tool_calls"]) < 0
                    or int(row["max_wall_time_ms"]) < 0
                    or not str(row["deadline_at"])
                )
                if legacy:
                    deadline = self._deadline(str(row["bound_at"]), max_wall)
                    conn.execute(
                        """
                        UPDATE task_execution_budget_usage
                        SET max_steps = ?, max_tool_calls = ?, max_wall_time_ms = ?,
                            deadline_at = ?, updated_at = ?
                        WHERE task_id = ?
                        """,
                        (max_steps, max_tools, max_wall, deadline, now_text, task_id),
                    )
                    migrated = True
                elif (
                    int(row["max_steps"]) != max_steps
                    or int(row["max_tool_calls"]) != max_tools
                    or int(row["max_wall_time_ms"]) != max_wall
                ):
                    raise ValueError("TASK_EXECUTION_BUDGET_IMMUTABLE_MISMATCH")
        if created or migrated:
            self.record_activity(
                task_id,
                "execution_budget",
                "execution_budget_bound" if created else "execution_budget_extended",
                "ok",
                (
                    f"max_steps={max_steps} max_tool_calls={max_tools} "
                    f"max_retries={retries} max_escalations={escalations} "
                    f"max_wall_time_ms={max_wall}"
                ),
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
            "max_steps": int(row["max_steps"]),
            "max_tool_calls": int(row["max_tool_calls"]),
            "max_retries": int(row["max_retries"]),
            "max_escalations": int(row["max_escalations"]),
            "max_wall_time_ms": int(row["max_wall_time_ms"]),
            "steps_used": int(row["steps_used"]),
            "tool_calls_used": int(row["tool_calls_used"]),
            "retries_used": int(row["retries_used"]),
            "escalations_used": int(row["escalations_used"]),
            "deadline_at": str(row["deadline_at"]),
            "bound_at": str(row["bound_at"]),
            "updated_at": str(row["updated_at"]),
        }

    def reserve_task_execution_budget(
        self,
        task_id: str,
        *,
        steps: int = 0,
        tool_calls: int = 0,
        retries: int = 0,
        escalations: int = 0,
    ) -> dict[str, int | str]:
        step_delta = self._budget_value(steps, "steps")
        tool_delta = self._budget_value(tool_calls, "tool_calls")
        retry_delta = self._budget_value(retries, "retries")
        escalation_delta = self._budget_value(escalations, "escalations")
        now = datetime.now(TZ)
        now_text = now.isoformat()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM task_execution_budget_usage WHERE task_id = ?",
                (task_id,),
            ).fetchone()
            if row is None:
                raise ValueError("TASK_EXECUTION_BUDGET_NOT_BOUND")
            if self._deadline_expired(str(row["deadline_at"]), now):
                raise ValueError("TASK_WALL_TIME_BUDGET_EXHAUSTED")

            new_steps = int(row["steps_used"]) + step_delta
            new_tools = int(row["tool_calls_used"]) + tool_delta
            new_retries = int(row["retries_used"]) + retry_delta
            new_escalations = int(row["escalations_used"]) + escalation_delta
            if new_steps > int(row["max_steps"]):
                raise ValueError("TASK_STEP_BUDGET_EXHAUSTED")
            if new_tools > int(row["max_tool_calls"]):
                raise ValueError("TASK_TOOL_CALL_BUDGET_EXHAUSTED")
            if new_retries > int(row["max_retries"]):
                raise ValueError("MODEL_RETRY_BUDGET_EXHAUSTED")
            if new_escalations > int(row["max_escalations"]):
                raise ValueError("MODEL_ESCALATION_BUDGET_EXHAUSTED")

            if step_delta or tool_delta or retry_delta or escalation_delta:
                conn.execute(
                    """
                    UPDATE task_execution_budget_usage
                    SET steps_used = ?, tool_calls_used = ?, retries_used = ?,
                        escalations_used = ?, updated_at = ?
                    WHERE task_id = ?
                    """,
                    (
                        new_steps, new_tools, new_retries, new_escalations,
                        now_text, task_id,
                    ),
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
