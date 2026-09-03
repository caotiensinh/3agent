from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .contracts import MonitoringContractError
from .ui_config import SecurityMonitoringUIConfigManager

GOVERNANCE_SCHEMA = "workspace-security-monitoring/config-governance-v1"
MAX_ACTOR_LENGTH = 160
MAX_REASON_LENGTH = 1200


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def config_fingerprint(payload: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _event_hash(event: dict[str, Any]) -> str:
    body = {key: value for key, value in event.items() if key != "event_hash"}
    return "sha256:" + hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()


def _required_text(value: Any, *, field: str, max_length: int) -> str:
    text = str(value or "").strip()
    if not text:
        raise MonitoringContractError(f"{field} is required for governed configuration changes")
    if len(text) > max_length:
        raise MonitoringContractError(f"{field} exceeds maximum length {max_length}")
    return text


@dataclass(frozen=True)
class GovernanceState:
    revision: int
    config_sha256: str | None
    active_config_sha256: str | None
    drift_detected: bool
    audit_chain_valid: bool


class SecurityMonitoringConfigGovernance:
    """Enterprise change-control boundary for monitoring configuration.

    The existing UI config manager remains the runtime validation and atomic-file
    boundary. This layer adds immutable revision history, required actor/reason,
    optimistic concurrency, rollback-as-new-revision and a hash-chained audit
    trail. Raw secrets never enter this store because the runtime contract rejects
    them before any governed write is attempted.
    """

    def __init__(
        self,
        manager: SecurityMonitoringUIConfigManager,
        *,
        database_path: Path | None = None,
    ) -> None:
        self.manager = manager
        self.database_path = database_path or manager.path.parent / "security_monitoring_governance.sqlite3"
        if not self.database_path.is_absolute():
            raise MonitoringContractError("governance database path must be absolute")
        if self.database_path == manager.path:
            raise MonitoringContractError("governance database must not replace the runtime configuration")
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.database_path, timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    def _init_db(self) -> None:
        parent = self.database_path.parent
        if parent.exists() and parent.is_symlink():
            raise MonitoringContractError("governance database directory must not be a symlink")
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(parent, 0o700)
        except OSError:
            pass
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS config_revisions (
                    revision INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    config_sha256 TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    source_revision INTEGER,
                    FOREIGN KEY(source_revision) REFERENCES config_revisions(revision)
                );
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    revision INTEGER NOT NULL,
                    config_sha256 TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    source_revision INTEGER,
                    previous_hash TEXT,
                    event_hash TEXT NOT NULL UNIQUE,
                    FOREIGN KEY(revision) REFERENCES config_revisions(revision)
                );
                CREATE INDEX IF NOT EXISTS idx_audit_events_revision
                    ON audit_events(revision);
                """
            )
        try:
            os.chmod(self.database_path, 0o600)
        except OSError:
            pass

    def _latest_revision_row(self, conn: sqlite3.Connection) -> sqlite3.Row | None:
        return conn.execute(
            "SELECT revision,config_sha256,payload_json FROM config_revisions ORDER BY revision DESC LIMIT 1"
        ).fetchone()

    def _previous_hash(self, conn: sqlite3.Connection) -> str | None:
        row = conn.execute("SELECT event_hash FROM audit_events ORDER BY event_id DESC LIMIT 1").fetchone()
        return str(row["event_hash"]) if row else None

    def _active_payload(self) -> dict[str, Any] | None:
        if not self.manager.path.is_file():
            return None
        loaded = self.manager.get().get("config")
        return loaded if isinstance(loaded, dict) else None

    def state(self) -> GovernanceState:
        with self._connect() as conn:
            latest = self._latest_revision_row(conn)
        active = self._active_payload()
        active_sha = config_fingerprint(active) if active is not None else None
        expected_sha = str(latest["config_sha256"]) if latest else None
        revision = int(latest["revision"]) if latest else 0
        return GovernanceState(
            revision=revision,
            config_sha256=expected_sha,
            active_config_sha256=active_sha,
            drift_detected=expected_sha != active_sha,
            audit_chain_valid=self.verify_audit_chain(),
        )

    def status(self) -> dict[str, Any]:
        state = self.state()
        tracked = state.revision > 0
        active_exists = state.active_config_sha256 is not None
        if not state.audit_chain_valid:
            change_state = "audit_invalid"
        elif state.drift_detected and tracked:
            change_state = "drift"
        elif active_exists and not tracked:
            change_state = "adoption_required"
        elif tracked:
            change_state = "governed"
        else:
            change_state = "unconfigured"
        return {
            "schema_version": GOVERNANCE_SCHEMA,
            "revision": state.revision,
            "config_sha256": state.config_sha256,
            "active_config_sha256": state.active_config_sha256,
            "drift_detected": state.drift_detected,
            "audit_chain_valid": state.audit_chain_valid,
            "tracked": tracked,
            "change_state": change_state,
            "writes_allowed": state.audit_chain_valid and change_state in {"governed", "unconfigured"},
            "adoption_required": change_state == "adoption_required",
        }

    def verify_audit_chain(self) -> bool:
        previous: str | None = None
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT event_id,created_at,actor,action,revision,config_sha256,reason,source_revision,previous_hash,event_hash "
                "FROM audit_events ORDER BY event_id"
            ).fetchall()
        for row in rows:
            event = {
                "event_id": int(row["event_id"]),
                "created_at": str(row["created_at"]),
                "actor": str(row["actor"]),
                "action": str(row["action"]),
                "revision": int(row["revision"]),
                "config_sha256": str(row["config_sha256"]),
                "reason": str(row["reason"]),
                "source_revision": int(row["source_revision"]) if row["source_revision"] is not None else None,
                "previous_hash": str(row["previous_hash"]) if row["previous_hash"] is not None else None,
            }
            if event["previous_hash"] != previous:
                return False
            expected = _event_hash(event)
            if expected != str(row["event_hash"]):
                return False
            previous = str(row["event_hash"])
        return True

    def _restore_active(self, previous_payload: dict[str, Any] | None) -> None:
        if previous_payload is None:
            try:
                self.manager.path.unlink()
            except FileNotFoundError:
                pass
            return
        self.manager.save(previous_payload)

    def _assert_pre_write_integrity(
        self,
        *,
        latest: sqlite3.Row | None,
        previous_payload: dict[str, Any] | None,
        action: str,
    ) -> None:
        expected_sha = str(latest["config_sha256"]) if latest else None
        active_sha = config_fingerprint(previous_payload) if previous_payload is not None else None
        if latest is None:
            if previous_payload is not None and action != "CONFIG_ADOPT":
                raise MonitoringContractError(
                    "existing configuration is untracked; explicit adoption is required before governed changes"
                )
            return
        if expected_sha != active_sha:
            raise MonitoringContractError(
                "configuration drift detected; governed changes are blocked until drift is resolved"
            )

    def apply_change(
        self,
        payload: Any,
        *,
        actor: str,
        reason: str,
        expected_revision: int,
        action: str = "CONFIG_UPDATE",
        source_revision: int | None = None,
    ) -> dict[str, Any]:
        actor_text = _required_text(actor, field="actor", max_length=MAX_ACTOR_LENGTH)
        reason_text = _required_text(reason, field="change_reason", max_length=MAX_REASON_LENGTH)
        if not isinstance(expected_revision, int) or expected_revision < 0:
            raise MonitoringContractError("expected_revision must be a non-negative integer")
        if not isinstance(payload, dict):
            raise MonitoringContractError("monitoring config must be a JSON object")
        validation = self.manager.validate(payload)
        fingerprint = config_fingerprint(payload)
        previous_payload = self._active_payload()

        conn = self._connect()
        runtime_written = False
        try:
            conn.execute("BEGIN IMMEDIATE")
            latest = self._latest_revision_row(conn)
            current_revision = int(latest["revision"]) if latest else 0
            if current_revision != expected_revision:
                raise MonitoringContractError(
                    f"configuration revision conflict: expected {expected_revision}, current {current_revision}"
                )
            if not self.verify_audit_chain():
                raise MonitoringContractError("configuration audit chain verification failed")
            self._assert_pre_write_integrity(
                latest=latest,
                previous_payload=previous_payload,
                action=action,
            )
            created_at = _utc_now()
            cursor = conn.execute(
                "INSERT INTO config_revisions(created_at,actor,reason,config_sha256,payload_json,source_revision) "
                "VALUES(?,?,?,?,?,?)",
                (created_at, actor_text, reason_text, fingerprint, _canonical_json(payload), source_revision),
            )
            revision = int(cursor.lastrowid)
            previous_hash = self._previous_hash(conn)
            event_without_id = {
                "created_at": created_at,
                "actor": actor_text,
                "action": action,
                "revision": revision,
                "config_sha256": fingerprint,
                "reason": reason_text,
                "source_revision": source_revision,
                "previous_hash": previous_hash,
            }
            event_id = int(
                conn.execute(
                    "SELECT COALESCE(MAX(event_id),0)+1 AS next_id FROM audit_events"
                ).fetchone()["next_id"]
            )
            event = {"event_id": event_id, **event_without_id}
            event_hash = _event_hash(event)
            conn.execute(
                "INSERT INTO audit_events(event_id,created_at,actor,action,revision,config_sha256,reason,source_revision,previous_hash,event_hash) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    created_at,
                    actor_text,
                    action,
                    revision,
                    fingerprint,
                    reason_text,
                    source_revision,
                    previous_hash,
                    event_hash,
                ),
            )
            save_result = self.manager.save(payload)
            runtime_written = True
            conn.commit()
        except Exception:
            conn.rollback()
            if runtime_written:
                self._restore_active(previous_payload)
            raise
        finally:
            conn.close()

        state = self.state()
        if state.drift_detected or not state.audit_chain_valid:
            raise MonitoringContractError("post-commit governance integrity verification failed")
        return {
            "schema_version": GOVERNANCE_SCHEMA,
            "saved": True,
            "revision": revision,
            "config_sha256": fingerprint,
            "actor": actor_text,
            "change_reason": reason_text,
            "audit_event_hash": event_hash,
            "readiness": save_result["readiness"],
            "summary": validation["summary"],
            "drift_detected": False,
            "audit_chain_valid": True,
        }

    def adopt_existing(self, *, actor: str, reason: str) -> dict[str, Any]:
        if self.state().revision != 0:
            raise MonitoringContractError("configuration governance already has a tracked revision")
        payload = self._active_payload()
        if payload is None:
            raise MonitoringContractError("no existing configuration is available for adoption")
        return self.apply_change(
            payload,
            actor=actor,
            reason=reason,
            expected_revision=0,
            action="CONFIG_ADOPT",
        )

    def revision(self, revision: int) -> dict[str, Any]:
        if not isinstance(revision, int) or revision <= 0:
            raise MonitoringContractError("revision must be a positive integer")
        with self._connect() as conn:
            row = conn.execute(
                "SELECT revision,created_at,actor,reason,config_sha256,payload_json,source_revision "
                "FROM config_revisions WHERE revision=?",
                (revision,),
            ).fetchone()
        if row is None:
            raise MonitoringContractError(f"configuration revision {revision} does not exist")
        return {
            "revision": int(row["revision"]),
            "created_at": str(row["created_at"]),
            "actor": str(row["actor"]),
            "reason": str(row["reason"]),
            "config_sha256": str(row["config_sha256"]),
            "source_revision": int(row["source_revision"]) if row["source_revision"] is not None else None,
            "config": json.loads(str(row["payload_json"])),
        }

    def history(self, *, limit: int = 50) -> list[dict[str, Any]]:
        if not isinstance(limit, int) or not 1 <= limit <= 200:
            raise MonitoringContractError("history limit must be between 1 and 200")
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT revision,created_at,actor,reason,config_sha256,source_revision "
                "FROM config_revisions ORDER BY revision DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [
            {
                "revision": int(row["revision"]),
                "created_at": str(row["created_at"]),
                "actor": str(row["actor"]),
                "reason": str(row["reason"]),
                "config_sha256": str(row["config_sha256"]),
                "source_revision": int(row["source_revision"]) if row["source_revision"] is not None else None,
            }
            for row in rows
        ]

    def rollback(
        self,
        source_revision: int,
        *,
        actor: str,
        reason: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        source = self.revision(source_revision)
        return self.apply_change(
            source["config"],
            actor=actor,
            reason=reason,
            expected_revision=expected_revision,
            action="CONFIG_ROLLBACK",
            source_revision=source_revision,
        )
