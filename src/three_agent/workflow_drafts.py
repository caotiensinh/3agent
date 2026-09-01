from __future__ import annotations

import hashlib
import json
import re
import secrets
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

from .workflow_design import WorkflowDesignError
from .workflow_design_v4 import (
    V4_WORKFLOW_SCHEMA_VERSION,
    render_mermaid_v4,
    render_svg_v4,
    validate_contract_v4,
)

TZ = ZoneInfo("Asia/Tokyo")
DRAFT_ID_RE = re.compile(r"^wfd_[a-f0-9]{16}$")
OWNER_KEY_RE = re.compile(r"^[a-f0-9]{64}$")
ACTOR_ID_RE = re.compile(r"^usr_[a-f0-9]{16}$")
VALID_ORIGINS = {"human", "workspace_ai", "import"}
MAX_TITLE_CHARS = 120
MAX_DESCRIPTION_CHARS = 8000
MAX_QUERY_CHARS = 200
MAX_LIST_LIMIT = 100


class WorkflowDraftError(ValueError):
    pass


class WorkflowDraftConflict(WorkflowDraftError):
    pass


class WorkflowDraftNotFound(KeyError):
    pass


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _bounded_text(value: Any, *, field: str, limit: int, allow_empty: bool = False) -> str:
    text = " ".join(str(value or "").split()).strip()
    if not text and not allow_empty:
        raise WorkflowDraftError(f"{field} is required")
    if len(text) > limit:
        raise WorkflowDraftError(f"{field} exceeds {limit} characters")
    return text


def _normalize_contract(value: Any) -> dict[str, Any]:
    try:
        return validate_contract_v4(value)
    except WorkflowDesignError as exc:
        raise WorkflowDraftError(str(exc)) from exc


def _content_sha(title: str, description: str, contract_json: str) -> str:
    payload = _canonical_json(
        {"title": title, "description": description, "contract": json.loads(contract_json)}
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _escape_like(value: str) -> str:
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class WorkflowDraftStore:
    """Owner-scoped, local-only workflow design storage with immutable revisions.

    A saved draft is design data only. This store has no reference to the runtime
    execution controller and therefore cannot grant or trigger workflow authority.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, factory=_ClosingConnection, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA busy_timeout = 10000")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(TZ).isoformat()

    @staticmethod
    def _owner(value: str) -> str:
        value = str(value or "").strip().lower()
        if not OWNER_KEY_RE.fullmatch(value):
            raise WorkflowDraftError("invalid workflow owner key")
        return value

    @staticmethod
    def _actor(value: str) -> str:
        value = str(value or "").strip().lower()
        if not ACTOR_ID_RE.fullmatch(value):
            raise WorkflowDraftError("invalid workflow actor id")
        return value

    @staticmethod
    def _draft_id(value: str) -> str:
        value = str(value or "").strip().lower()
        if not DRAFT_ID_RE.fullmatch(value):
            raise WorkflowDraftError("invalid workflow draft id")
        return value

    @staticmethod
    def _origin(value: str) -> str:
        value = str(value or "").strip().lower()
        if value not in VALID_ORIGINS:
            raise WorkflowDraftError("origin must be human, workspace_ai or import")
        return value

    @staticmethod
    def _status_view(value: str) -> str:
        value = str(value or "active").strip().lower()
        if value not in {"active", "archived", "all"}:
            raise WorkflowDraftError("view must be active, archived or all")
        return value

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS workspace_workflow_drafts (
                    draft_id TEXT PRIMARY KEY,
                    owner_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    contract_json TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK(revision >= 1),
                    status TEXT NOT NULL CHECK(status IN ('active','archived')),
                    origin TEXT NOT NULL CHECK(origin IN ('human','workspace_ai','import')),
                    created_by TEXT NOT NULL,
                    updated_by TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    archived_at TEXT,
                    lineage_parent_draft_id TEXT,
                    lineage_parent_revision INTEGER,
                    UNIQUE(owner_key, draft_id)
                );
                CREATE INDEX IF NOT EXISTS idx_workspace_workflow_drafts_owner
                ON workspace_workflow_drafts(owner_key, status, updated_at DESC);

                CREATE TABLE IF NOT EXISTS workspace_workflow_draft_versions (
                    draft_id TEXT NOT NULL,
                    revision INTEGER NOT NULL CHECK(revision >= 1),
                    owner_key TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    contract_json TEXT NOT NULL,
                    content_sha256 TEXT NOT NULL,
                    origin TEXT NOT NULL CHECK(origin IN ('human','workspace_ai','import')),
                    actor_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(draft_id, revision),
                    FOREIGN KEY(draft_id) REFERENCES workspace_workflow_drafts(draft_id)
                        ON DELETE RESTRICT
                );
                CREATE INDEX IF NOT EXISTS idx_workspace_workflow_versions_owner
                ON workspace_workflow_draft_versions(owner_key, draft_id, revision DESC);

                CREATE TABLE IF NOT EXISTS workspace_workflow_draft_audit (
                    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    draft_id TEXT NOT NULL,
                    owner_key TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    base_revision INTEGER,
                    new_revision INTEGER,
                    before_sha256 TEXT,
                    after_sha256 TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_workspace_workflow_draft_audit_owner
                ON workspace_workflow_draft_audit(owner_key, draft_id, audit_id DESC);
                """
            )

    def _normalize_payload(self, *, title: Any, description: Any, contract: Any, origin: Any) -> tuple[str, str, dict[str, Any], str, str]:
        normalized = _normalize_contract(contract)
        fallback_title = normalized.get("title") or "Untitled workflow"
        title_text = _bounded_text(
            title if str(title or "").strip() else fallback_title,
            field="title",
            limit=MAX_TITLE_CHARS,
        )
        description_text = _bounded_text(
            description,
            field="description",
            limit=MAX_DESCRIPTION_CHARS,
            allow_empty=True,
        )
        self._origin(str(origin or "human"))
        contract_json = _canonical_json(normalized)
        digest = _content_sha(title_text, description_text, contract_json)
        return title_text, description_text, normalized, contract_json, digest

    @staticmethod
    def _summary_from_row(row: sqlite3.Row) -> dict[str, Any]:
        contract = json.loads(str(row["contract_json"]))
        return {
            "draft_id": str(row["draft_id"]),
            "title": str(row["title"]),
            "revision": int(row["revision"]),
            "content_sha256": str(row["content_sha256"]),
            "status": str(row["status"]),
            "origin": str(row["origin"]),
            "updated_at": str(row["updated_at"]),
            "created_at": str(row["created_at"]),
            "archived_at": str(row["archived_at"] or ""),
            "node_count": len(contract.get("nodes") or []),
            "risk_level": str(contract.get("risk_level") or ""),
            "data_class": str(contract.get("data_class") or ""),
            "trigger": str(contract.get("trigger") or ""),
            "lineage_parent_draft_id": str(row["lineage_parent_draft_id"] or ""),
            "lineage_parent_revision": int(row["lineage_parent_revision"]) if row["lineage_parent_revision"] is not None else None,
            "execution_authorized": False,
            "execution_mode": "design_only",
        }

    def _full_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        summary = self._summary_from_row(row)
        contract = json.loads(str(row["contract_json"]))
        summary.update(
            {
                "description": str(row["description"]),
                "contract": contract,
                "schema_version": V4_WORKFLOW_SCHEMA_VERSION,
                "diagram": {
                    "mermaid": render_mermaid_v4(contract),
                    "svg": render_svg_v4(contract),
                },
            }
        )
        return summary

    @staticmethod
    def _insert_version(conn: sqlite3.Connection, *, draft_id: str, revision: int, owner_key: str, title: str, description: str, contract_json: str, content_sha256: str, origin: str, actor_id: str, now: str) -> None:
        conn.execute(
            """
            INSERT INTO workspace_workflow_draft_versions(
                draft_id,revision,owner_key,title,description,contract_json,
                content_sha256,origin,actor_id,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (draft_id, revision, owner_key, title, description, contract_json, content_sha256, origin, actor_id, now),
        )

    @staticmethod
    def _audit(conn: sqlite3.Connection, *, draft_id: str, owner_key: str, actor_id: str, operation: str, base_revision: int | None, new_revision: int | None, before_sha256: str | None, after_sha256: str | None, now: str) -> None:
        conn.execute(
            """
            INSERT INTO workspace_workflow_draft_audit(
                draft_id,owner_key,actor_id,operation,base_revision,new_revision,
                before_sha256,after_sha256,created_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (draft_id, owner_key, actor_id, operation, base_revision, new_revision, before_sha256, after_sha256, now),
        )

    def create(self, owner_key: str, actor_id: str, *, title: Any, description: Any, contract: Any, origin: Any = "workspace_ai", lineage_parent_draft_id: str | None = None, lineage_parent_revision: int | None = None) -> dict[str, Any]:
        owner_key = self._owner(owner_key)
        actor_id = self._actor(actor_id)
        title_text, description_text, _, contract_json, digest = self._normalize_payload(title=title, description=description, contract=contract, origin=origin)
        origin_text = self._origin(str(origin or "workspace_ai"))
        parent_id = None
        if lineage_parent_draft_id:
            parent_id = self._draft_id(lineage_parent_draft_id)
            if lineage_parent_revision is None or int(lineage_parent_revision) < 1:
                raise WorkflowDraftError("lineage parent revision is required")
            lineage_parent_revision = int(lineage_parent_revision)
        else:
            lineage_parent_revision = None

        now = self._now()
        for _ in range(8):
            draft_id = "wfd_" + secrets.token_hex(8)
            try:
                with self.connect() as conn:
                    conn.execute("BEGIN IMMEDIATE")
                    if parent_id is not None:
                        parent = conn.execute("SELECT revision FROM workspace_workflow_drafts WHERE owner_key=? AND draft_id=?", (owner_key, parent_id)).fetchone()
                        if parent is None:
                            raise WorkflowDraftNotFound(parent_id)
                        version = conn.execute("SELECT 1 FROM workspace_workflow_draft_versions WHERE owner_key=? AND draft_id=? AND revision=?", (owner_key, parent_id, lineage_parent_revision)).fetchone()
                        if version is None:
                            raise WorkflowDraftNotFound(f"{parent_id}@{lineage_parent_revision}")
                    conn.execute(
                        """
                        INSERT INTO workspace_workflow_drafts(
                            draft_id,owner_key,title,description,contract_json,
                            content_sha256,revision,status,origin,created_by,updated_by,
                            created_at,updated_at,archived_at,
                            lineage_parent_draft_id,lineage_parent_revision
                        ) VALUES(?,?,?,?,?,?,1,'active',?,?,?,?,?,NULL,?,?)
                        """,
                        (draft_id, owner_key, title_text, description_text, contract_json, digest, origin_text, actor_id, actor_id, now, now, parent_id, lineage_parent_revision),
                    )
                    self._insert_version(conn, draft_id=draft_id, revision=1, owner_key=owner_key, title=title_text, description=description_text, contract_json=contract_json, content_sha256=digest, origin=origin_text, actor_id=actor_id, now=now)
                    self._audit(conn, draft_id=draft_id, owner_key=owner_key, actor_id=actor_id, operation="duplicate" if parent_id else "create", base_revision=lineage_parent_revision if parent_id else None, new_revision=1, before_sha256=None, after_sha256=digest, now=now)
                return self.get(owner_key, draft_id)
            except sqlite3.IntegrityError:
                continue
        raise WorkflowDraftError("unable to allocate workflow draft id")

    def get(self, owner_key: str, draft_id: str) -> dict[str, Any]:
        owner_key = self._owner(owner_key)
        draft_id = self._draft_id(draft_id)
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM workspace_workflow_drafts WHERE owner_key=? AND draft_id=?", (owner_key, draft_id)).fetchone()
        if row is None:
            raise WorkflowDraftNotFound(draft_id)
        return self._full_from_row(row)

    def list(self, owner_key: str, *, query: str = "", view: str = "active", limit: int = 50) -> list[dict[str, Any]]:
        owner_key = self._owner(owner_key)
        view = self._status_view(view)
        query = _bounded_text(query, field="query", limit=MAX_QUERY_CHARS, allow_empty=True)
        try:
            limit = int(limit)
        except (TypeError, ValueError) as exc:
            raise WorkflowDraftError("limit must be an integer") from exc
        if not 1 <= limit <= MAX_LIST_LIMIT:
            raise WorkflowDraftError(f"limit must be between 1 and {MAX_LIST_LIMIT}")
        clauses = ["owner_key=?"]
        params: list[Any] = [owner_key]
        if view != "all":
            clauses.append("status=?")
            params.append(view)
        if query:
            escaped = f"%{_escape_like(query)}%"
            clauses.append("(title LIKE ? ESCAPE '\\' OR description LIKE ? ESCAPE '\\')")
            params.extend([escaped, escaped])
        sql = "SELECT * FROM workspace_workflow_drafts WHERE " + " AND ".join(clauses) + " ORDER BY updated_at DESC, draft_id ASC LIMIT ?"
        params.append(limit)
        with self.connect() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._summary_from_row(row) for row in rows]

    def save(self, owner_key: str, actor_id: str, draft_id: str, *, expected_revision: Any, expected_content_sha256: Any, title: Any, description: Any, contract: Any, origin: Any = "human") -> dict[str, Any]:
        owner_key = self._owner(owner_key)
        actor_id = self._actor(actor_id)
        draft_id = self._draft_id(draft_id)
        origin_text = self._origin(str(origin or "human"))
        try:
            expected_revision = int(expected_revision)
        except (TypeError, ValueError) as exc:
            raise WorkflowDraftError("expected_revision must be an integer") from exc
        expected_sha = str(expected_content_sha256 or "").strip().lower()
        if not re.fullmatch(r"[a-f0-9]{64}", expected_sha):
            raise WorkflowDraftError("expected_content_sha256 is required")
        title_text, description_text, _, contract_json, digest = self._normalize_payload(title=title, description=description, contract=contract, origin=origin_text)
        now = self._now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM workspace_workflow_drafts WHERE owner_key=? AND draft_id=?", (owner_key, draft_id)).fetchone()
            if row is None:
                raise WorkflowDraftNotFound(draft_id)
            current_revision = int(row["revision"])
            current_sha = str(row["content_sha256"])
            if str(row["status"]) != "active":
                raise WorkflowDraftConflict("archived workflow must be restored before editing")
            if current_revision != expected_revision or current_sha != expected_sha:
                raise WorkflowDraftConflict("stale workflow revision; reload before saving")
            if digest == current_sha:
                return self._full_from_row(row)
            new_revision = current_revision + 1
            conn.execute("UPDATE workspace_workflow_drafts SET title=?,description=?,contract_json=?,content_sha256=?,revision=?,origin=?,updated_by=?,updated_at=? WHERE owner_key=? AND draft_id=?", (title_text, description_text, contract_json, digest, new_revision, origin_text, actor_id, now, owner_key, draft_id))
            self._insert_version(conn, draft_id=draft_id, revision=new_revision, owner_key=owner_key, title=title_text, description=description_text, contract_json=contract_json, content_sha256=digest, origin=origin_text, actor_id=actor_id, now=now)
            self._audit(conn, draft_id=draft_id, owner_key=owner_key, actor_id=actor_id, operation="save", base_revision=current_revision, new_revision=new_revision, before_sha256=current_sha, after_sha256=digest, now=now)
        return self.get(owner_key, draft_id)

    def set_archived(self, owner_key: str, actor_id: str, draft_id: str, *, archived: bool) -> dict[str, Any]:
        owner_key = self._owner(owner_key)
        actor_id = self._actor(actor_id)
        draft_id = self._draft_id(draft_id)
        if not isinstance(archived, bool):
            raise WorkflowDraftError("archived must be a boolean")
        desired = "archived" if archived else "active"
        now = self._now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute("SELECT * FROM workspace_workflow_drafts WHERE owner_key=? AND draft_id=?", (owner_key, draft_id)).fetchone()
            if row is None:
                raise WorkflowDraftNotFound(draft_id)
            if str(row["status"]) != desired:
                conn.execute("UPDATE workspace_workflow_drafts SET status=?,archived_at=?,updated_by=?,updated_at=? WHERE owner_key=? AND draft_id=?", (desired, now if archived else None, actor_id, now, owner_key, draft_id))
                self._audit(conn, draft_id=draft_id, owner_key=owner_key, actor_id=actor_id, operation="archive" if archived else "restore", base_revision=int(row["revision"]), new_revision=int(row["revision"]), before_sha256=str(row["content_sha256"]), after_sha256=str(row["content_sha256"]), now=now)
        return self.get(owner_key, draft_id)

    def duplicate(self, owner_key: str, actor_id: str, draft_id: str) -> dict[str, Any]:
        source = self.get(owner_key, draft_id)
        return self.create(owner_key, actor_id, title=f"Copy of {source['title']}"[:MAX_TITLE_CHARS], description=source["description"], contract=source["contract"], origin="human", lineage_parent_draft_id=source["draft_id"], lineage_parent_revision=source["revision"])

    def versions(self, owner_key: str, draft_id: str) -> list[dict[str, Any]]:
        owner_key = self._owner(owner_key)
        draft_id = self._draft_id(draft_id)
        with self.connect() as conn:
            exists = conn.execute("SELECT 1 FROM workspace_workflow_drafts WHERE owner_key=? AND draft_id=?", (owner_key, draft_id)).fetchone()
            if exists is None:
                raise WorkflowDraftNotFound(draft_id)
            rows = conn.execute("SELECT revision,title,content_sha256,origin,actor_id,created_at,contract_json FROM workspace_workflow_draft_versions WHERE owner_key=? AND draft_id=? ORDER BY revision DESC", (owner_key, draft_id)).fetchall()
        result = []
        for row in rows:
            contract = json.loads(str(row["contract_json"]))
            result.append({"revision": int(row["revision"]), "title": str(row["title"]), "content_sha256": str(row["content_sha256"]), "origin": str(row["origin"]), "actor_id": str(row["actor_id"]), "created_at": str(row["created_at"]), "node_count": len(contract.get("nodes") or []), "risk_level": str(contract.get("risk_level") or ""), "data_class": str(contract.get("data_class") or "")})
        return result

    def audit(self, owner_key: str, draft_id: str, *, limit: int = 100) -> list[dict[str, Any]]:
        owner_key = self._owner(owner_key)
        draft_id = self._draft_id(draft_id)
        limit = max(1, min(MAX_LIST_LIMIT, int(limit)))
        with self.connect() as conn:
            exists = conn.execute("SELECT 1 FROM workspace_workflow_drafts WHERE owner_key=? AND draft_id=?", (owner_key, draft_id)).fetchone()
            if exists is None:
                raise WorkflowDraftNotFound(draft_id)
            rows = conn.execute("SELECT actor_id,operation,base_revision,new_revision,before_sha256,after_sha256,created_at FROM workspace_workflow_draft_audit WHERE owner_key=? AND draft_id=? ORDER BY audit_id DESC LIMIT ?", (owner_key, draft_id, limit)).fetchall()
        return [{"actor_id": str(row["actor_id"]), "operation": str(row["operation"]), "base_revision": row["base_revision"], "new_revision": row["new_revision"], "before_sha256": str(row["before_sha256"] or ""), "after_sha256": str(row["after_sha256"] or ""), "created_at": str(row["created_at"])} for row in rows]
