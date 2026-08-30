"""Local, deterministic storage for staged and promoted WorkSpace learning.

Phase 3 deliberately contains no background learner, networking, shell, or
deployment capability. It persists validated learning proposals locally and
keeps a metadata-only, hash-chained append-only audit ledger.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .adaptive_learning_contract import (
    AdaptiveLearningPolicy,
    ContradictionRecord,
    KnowledgeCandidate,
    LearningValidationReceipt,
)

STORE_SCHEMA = "workspace-adaptive-learning-store/v1"
LEDGER_SCHEMA = "workspace-adaptive-learning-ledger/v1"
GENESIS_HASH = "sha256:" + "0" * 64
ACTIVE_LEVELS = {"approved", "enterprise"}
_ALLOWED_EVENTS = {"stage", "validate", "activate", "enterprise", "archive", "rollback"}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASON = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")


class AdaptiveLearningStoreError(ValueError):
    """A learning-store transition is incomplete, stale, or unauthorized."""


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _compact_id(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not _ID.fullmatch(text):
        raise AdaptiveLearningStoreError(f"invalid {field}")
    return text


def _sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise AdaptiveLearningStoreError(f"invalid {field}")
    return text


def _reason(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not _REASON.fullmatch(text):
        raise AdaptiveLearningStoreError("invalid reason_code")
    return text


def _knowledge_payload(item_id: str, candidate: KnowledgeCandidate) -> dict[str, Any]:
    """Return the reusable knowledge identity without task-specific provenance."""
    return {
        "schema_version": STORE_SCHEMA,
        "item_id": item_id,
        "domain": candidate.domain,
        "kind": candidate.kind,
        "title": candidate.title,
        "content": candidate.content,
        "scope": candidate.scope,
        "sensitivity": candidate.sensitivity,
        "risk_level": candidate.risk_level,
        "ownership": candidate.ownership,
        "execution_mode": candidate.execution_mode,
    }


def _receipt_sha256(receipt: LearningValidationReceipt) -> str:
    receipt.validate()
    return _digest(receipt.to_payload())


class AdaptiveLearningStore:
    """Isolated SQLite store for learner-managed knowledge.

    Candidate/version rows are immutable snapshots. Active state is derived
    from the append-only ledger, so there is no mutable active pointer to trust.
    Phase 3 accepts only ``learner_managed`` content; adoption into team/system
    ownership is intentionally outside this API.
    """

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()
        try:
            self.db_path.chmod(0o600)
        except OSError:
            pass

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, factory=_ClosingConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS learning_versions (
                    version_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    item_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    candidate_sha256 TEXT NOT NULL,
                    knowledge_sha256 TEXT NOT NULL,
                    candidate_json TEXT NOT NULL,
                    level TEXT NOT NULL CHECK(level IN ('candidate','validated','approved','enterprise')),
                    disposition TEXT NOT NULL CHECK(disposition IN ('staged','active_snapshot')),
                    validation_receipt_sha256 TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE(candidate_id, level)
                );
                CREATE INDEX IF NOT EXISTS idx_learning_versions_item
                    ON learning_versions(item_id, version_id);
                CREATE INDEX IF NOT EXISTS idx_learning_versions_candidate
                    ON learning_versions(candidate_id, version_id);

                CREATE TABLE IF NOT EXISTS learning_ledger (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    schema_version TEXT NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    candidate_id TEXT,
                    candidate_sha256 TEXT,
                    knowledge_sha256 TEXT,
                    before_sha256 TEXT,
                    after_sha256 TEXT,
                    validation_receipt_sha256 TEXT,
                    source_experience_hashes_json TEXT NOT NULL,
                    evidence_hashes_json TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    previous_entry_sha256 TEXT NOT NULL,
                    entry_sha256 TEXT NOT NULL UNIQUE
                );

                CREATE TRIGGER IF NOT EXISTS learning_versions_no_update
                BEFORE UPDATE ON learning_versions
                BEGIN
                    SELECT RAISE(ABORT, 'learning versions are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS learning_versions_no_delete
                BEFORE DELETE ON learning_versions
                BEGIN
                    SELECT RAISE(ABORT, 'learning versions are immutable');
                END;

                CREATE TRIGGER IF NOT EXISTS learning_ledger_no_update
                BEFORE UPDATE ON learning_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'learning ledger is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS learning_ledger_no_delete
                BEFORE DELETE ON learning_ledger
                BEGIN
                    SELECT RAISE(ABORT, 'learning ledger is append-only');
                END;
                """
            )

    @staticmethod
    def _item_id(candidate: KnowledgeCandidate) -> str:
        value = candidate.target_item_id if candidate.action != "create" else candidate.candidate_id
        return _compact_id(value, "item_id")

    @staticmethod
    def _candidate_from_row(row: sqlite3.Row) -> KnowledgeCandidate:
        payload = json.loads(str(row["candidate_json"]))
        return KnowledgeCandidate.from_payload(payload)

    def _active_row(self, conn: sqlite3.Connection, item_id: str) -> sqlite3.Row | None:
        """Derive active state from the append-only ledger; no mutable pointer exists."""
        event = conn.execute(
            """
            SELECT * FROM learning_ledger
            WHERE item_id=? AND event_type IN ('activate','enterprise','archive','rollback')
            ORDER BY seq DESC LIMIT 1
            """,
            (item_id,),
        ).fetchone()
        if event is None or str(event["event_type"]) == "archive" or event["after_sha256"] is None:
            return None
        candidate_id = str(event["candidate_id"] or "")
        return conn.execute(
            """
            SELECT * FROM learning_versions
            WHERE item_id=? AND candidate_id=? AND knowledge_sha256=?
              AND disposition='active_snapshot'
            ORDER BY version_id DESC LIMIT 1
            """,
            (item_id, candidate_id, str(event["after_sha256"])),
        ).fetchone()

    def _candidate_level_row(
        self, conn: sqlite3.Connection, candidate_id: str
    ) -> sqlite3.Row | None:
        return conn.execute(
            """
            SELECT * FROM learning_versions
            WHERE candidate_id=?
            ORDER BY version_id DESC LIMIT 1
            """,
            (candidate_id,),
        ).fetchone()

    def _append_ledger(
        self,
        conn: sqlite3.Connection,
        *,
        event_type: str,
        item_id: str,
        candidate: KnowledgeCandidate | None,
        knowledge_sha256: str | None,
        before_sha256: str | None,
        after_sha256: str | None,
        receipt_sha256: str | None,
        actor_id: str,
        reason_code: str,
        timestamp: str,
    ) -> str:
        if event_type not in _ALLOWED_EVENTS:
            raise AdaptiveLearningStoreError("invalid event_type")
        actor = _compact_id(actor_id, "actor_id")
        code = _reason(reason_code)
        previous = conn.execute(
            "SELECT entry_sha256 FROM learning_ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()
        previous_hash = str(previous["entry_sha256"]) if previous else GENESIS_HASH
        experience_hashes = list(candidate.source_experience_hashes) if candidate else []
        evidence_hashes = list(candidate.evidence_hashes) if candidate else []
        next_seq = int(
            conn.execute("SELECT COALESCE(MAX(seq),0)+1 AS n FROM learning_ledger").fetchone()["n"]
        )
        event_id = (
            f"learning-event:{timestamp.replace(':','').replace('-','').replace('.','')}"
            f":{event_type}:{item_id}:{next_seq}"
        )
        payload = {
            "schema_version": LEDGER_SCHEMA,
            "seq": next_seq,
            "event_id": event_id,
            "event_type": event_type,
            "item_id": item_id,
            "candidate_id": candidate.candidate_id if candidate else None,
            "candidate_sha256": candidate.sha256 if candidate else None,
            "knowledge_sha256": knowledge_sha256,
            "before_sha256": before_sha256,
            "after_sha256": after_sha256,
            "validation_receipt_sha256": receipt_sha256,
            "source_experience_hashes": experience_hashes,
            "evidence_hashes": evidence_hashes,
            "actor_id": actor,
            "reason_code": code,
            "timestamp": timestamp,
            "previous_entry_sha256": previous_hash,
        }
        entry_hash = _digest(payload)
        conn.execute(
            """
            INSERT INTO learning_ledger(
                seq,schema_version,event_id,event_type,item_id,candidate_id,candidate_sha256,
                knowledge_sha256,before_sha256,after_sha256,validation_receipt_sha256,
                source_experience_hashes_json,evidence_hashes_json,actor_id,reason_code,
                timestamp,previous_entry_sha256,entry_sha256
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                next_seq,
                LEDGER_SCHEMA,
                event_id,
                event_type,
                item_id,
                payload["candidate_id"],
                payload["candidate_sha256"],
                knowledge_sha256,
                before_sha256,
                after_sha256,
                receipt_sha256,
                _canonical(experience_hashes),
                _canonical(evidence_hashes),
                actor,
                code,
                timestamp,
                previous_hash,
                entry_hash,
            ),
        )
        return entry_hash

    def stage(
        self,
        candidate: KnowledgeCandidate,
        *,
        actor_id: str = "learner:reflection",
        reason_code: str = "CANDIDATE_STAGED",
    ) -> dict[str, Any]:
        candidate.validate()
        if candidate.ownership != "learner_managed":
            raise AdaptiveLearningStoreError(
                "phase-3 store accepts only learner_managed candidates"
            )
        item_id = self._item_id(candidate)
        now = _now()
        candidate_json = _canonical(candidate.to_payload())
        knowledge_hash = _digest(_knowledge_payload(item_id, candidate))
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT * FROM learning_versions WHERE candidate_id=? AND level='candidate'",
                (candidate.candidate_id,),
            ).fetchone()
            if existing is not None:
                if (
                    str(existing["candidate_sha256"]) != candidate.sha256
                    or str(existing["item_id"]) != item_id
                ):
                    raise AdaptiveLearningStoreError("candidate_id is immutable")
                return dict(existing)
            active = self._active_row(conn, item_id)
            if candidate.action == "create":
                if active is not None:
                    raise AdaptiveLearningStoreError("create cannot replace an active item")
            else:
                if active is None:
                    raise AdaptiveLearningStoreError("patch/supersede requires active target")
                if candidate.base_item_sha256 != str(active["knowledge_sha256"]):
                    raise AdaptiveLearningStoreError("STALE_BASE_ITEM_SHA256")
            cursor = conn.execute(
                """
                INSERT INTO learning_versions(
                    item_id,candidate_id,candidate_sha256,knowledge_sha256,candidate_json,
                    level,disposition,validation_receipt_sha256,created_at
                ) VALUES(?,?,?,?,?,'candidate','staged',NULL,?)
                """,
                (
                    item_id,
                    candidate.candidate_id,
                    candidate.sha256,
                    knowledge_hash,
                    candidate_json,
                    now,
                ),
            )
            self._append_ledger(
                conn,
                event_type="stage",
                item_id=item_id,
                candidate=candidate,
                knowledge_sha256=knowledge_hash,
                before_sha256=str(active["knowledge_sha256"]) if active else None,
                after_sha256=None,
                receipt_sha256=None,
                actor_id=actor_id,
                reason_code=reason_code,
                timestamp=now,
            )
            row = conn.execute(
                "SELECT * FROM learning_versions WHERE version_id=?",
                (cursor.lastrowid,),
            ).fetchone()
            return dict(row)

    def promote(
        self,
        candidate_id: str,
        *,
        target_level: str,
        receipt: LearningValidationReceipt,
        contradictions: Iterable[ContradictionRecord] = (),
        actor_id: str = "operator:reviewer",
        reason_code: str = "PROMOTION_GATE_PASSED",
    ) -> dict[str, Any]:
        candidate_id = _compact_id(candidate_id, "candidate_id")
        receipt.validate()
        now = _now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            latest = self._candidate_level_row(conn, candidate_id)
            if latest is None:
                raise AdaptiveLearningStoreError("CANDIDATE_NOT_STAGED")
            current_level = str(latest["level"])
            candidate = self._candidate_from_row(latest)
            receipt_hash = _receipt_sha256(receipt)
            existing = conn.execute(
                "SELECT * FROM learning_versions WHERE candidate_id=? AND level=?",
                (candidate_id, target_level),
            ).fetchone()
            if existing is not None:
                if str(existing["validation_receipt_sha256"] or "") != receipt_hash:
                    raise AdaptiveLearningStoreError("promotion receipt is immutable")
                return dict(existing)
            decision = AdaptiveLearningPolicy.evaluate(
                candidate,
                current_level=current_level,
                target_level=str(target_level),
                receipt=receipt,
                contradictions=tuple(contradictions),
            )
            if not decision.allowed:
                raise AdaptiveLearningStoreError(
                    "PROMOTION_BLOCKED:" + ",".join(decision.reason_codes)
                )
            item_id = str(latest["item_id"])
            active = self._active_row(conn, item_id)
            activates = target_level in ACTIVE_LEVELS and not (
                target_level == "approved"
                and active is not None
                and str(active["level"]) == "enterprise"
            )
            disposition = "active_snapshot" if activates else "staged"
            cursor = conn.execute(
                """
                INSERT INTO learning_versions(
                    item_id,candidate_id,candidate_sha256,knowledge_sha256,candidate_json,
                    level,disposition,validation_receipt_sha256,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    item_id,
                    candidate.candidate_id,
                    candidate.sha256,
                    str(latest["knowledge_sha256"]),
                    str(latest["candidate_json"]),
                    target_level,
                    disposition,
                    receipt_hash,
                    now,
                ),
            )
            new_version_id = int(cursor.lastrowid)
            before_hash = str(active["knowledge_sha256"]) if active else None
            after_hash = None
            event = "validate"
            if activates:
                after_hash = str(latest["knowledge_sha256"])
                event = "enterprise" if target_level == "enterprise" else "activate"
            self._append_ledger(
                conn,
                event_type=event,
                item_id=item_id,
                candidate=candidate,
                knowledge_sha256=str(latest["knowledge_sha256"]),
                before_sha256=before_hash,
                after_sha256=after_hash,
                receipt_sha256=receipt_hash,
                actor_id=actor_id,
                reason_code=reason_code,
                timestamp=now,
            )
            row = conn.execute(
                "SELECT * FROM learning_versions WHERE version_id=?",
                (new_version_id,),
            ).fetchone()
            return dict(row)

    def active(self, item_id: str) -> dict[str, Any] | None:
        item_id = _compact_id(item_id, "item_id")
        with self.connect() as conn:
            row = self._active_row(conn, item_id)
            if row is None:
                return None
            result = dict(row)
            result["candidate"] = json.loads(str(row["candidate_json"]))
            return result

    def archive(
        self,
        item_id: str,
        *,
        expected_current_sha256: str,
        actor_id: str = "operator:reviewer",
        reason_code: str = "KNOWLEDGE_ARCHIVED",
    ) -> None:
        item_id = _compact_id(item_id, "item_id")
        expected = _sha(expected_current_sha256, "expected_current_sha256")
        now = _now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            active = self._active_row(conn, item_id)
            if active is None:
                raise AdaptiveLearningStoreError("ACTIVE_ITEM_NOT_FOUND")
            current = str(active["knowledge_sha256"])
            if current != expected:
                raise AdaptiveLearningStoreError("ACTIVE_ITEM_CHANGED")
            candidate = self._candidate_from_row(active)
            self._append_ledger(
                conn,
                event_type="archive",
                item_id=item_id,
                candidate=candidate,
                knowledge_sha256=current,
                before_sha256=current,
                after_sha256=None,
                receipt_sha256=str(active["validation_receipt_sha256"] or "") or None,
                actor_id=actor_id,
                reason_code=reason_code,
                timestamp=now,
            )

    def rollback(
        self,
        item_id: str,
        *,
        target_knowledge_sha256: str,
        expected_current_sha256: str | None,
        actor_id: str = "operator:reviewer",
        reason_code: str = "KNOWLEDGE_ROLLBACK",
    ) -> dict[str, Any]:
        item_id = _compact_id(item_id, "item_id")
        target = _sha(target_knowledge_sha256, "target_knowledge_sha256")
        expected = (
            None
            if expected_current_sha256 is None
            else _sha(expected_current_sha256, "expected_current_sha256")
        )
        now = _now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            active = self._active_row(conn, item_id)
            current = str(active["knowledge_sha256"]) if active else None
            if current != expected:
                raise AdaptiveLearningStoreError("ACTIVE_ITEM_CHANGED")
            target_row = conn.execute(
                """
                SELECT * FROM learning_versions
                WHERE item_id=? AND knowledge_sha256=? AND disposition='active_snapshot'
                ORDER BY version_id DESC LIMIT 1
                """,
                (item_id, target),
            ).fetchone()
            if target_row is None:
                raise AdaptiveLearningStoreError("ROLLBACK_TARGET_NOT_PROMOTED")
            candidate = self._candidate_from_row(target_row)
            self._append_ledger(
                conn,
                event_type="rollback",
                item_id=item_id,
                candidate=candidate,
                knowledge_sha256=target,
                before_sha256=current,
                after_sha256=target,
                receipt_sha256=str(target_row["validation_receipt_sha256"] or "") or None,
                actor_id=actor_id,
                reason_code=reason_code,
                timestamp=now,
            )
            result = dict(target_row)
            result["candidate"] = json.loads(str(target_row["candidate_json"]))
            return result

    def ledger(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM learning_ledger ORDER BY seq").fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["source_experience_hashes"] = json.loads(
                str(item.pop("source_experience_hashes_json"))
            )
            item["evidence_hashes"] = json.loads(str(item.pop("evidence_hashes_json")))
            result.append(item)
        return result

    def verify_ledger(self) -> dict[str, Any]:
        rows = self.ledger()
        previous = GENESIS_HASH
        failures: list[str] = []
        for expected_seq, row in enumerate(rows, start=1):
            seq = int(row["seq"])
            if seq != expected_seq:
                failures.append(f"SEQ_GAP:{expected_seq}:{seq}")
            if row["schema_version"] != LEDGER_SCHEMA:
                failures.append(f"SCHEMA_MISMATCH:{seq}")
            if row["previous_entry_sha256"] != previous:
                failures.append(f"CHAIN_PREVIOUS_MISMATCH:{seq}")
            payload = {
                "schema_version": row["schema_version"],
                "seq": seq,
                "event_id": row["event_id"],
                "event_type": row["event_type"],
                "item_id": row["item_id"],
                "candidate_id": row["candidate_id"],
                "candidate_sha256": row["candidate_sha256"],
                "knowledge_sha256": row["knowledge_sha256"],
                "before_sha256": row["before_sha256"],
                "after_sha256": row["after_sha256"],
                "validation_receipt_sha256": row["validation_receipt_sha256"],
                "source_experience_hashes": row["source_experience_hashes"],
                "evidence_hashes": row["evidence_hashes"],
                "actor_id": row["actor_id"],
                "reason_code": row["reason_code"],
                "timestamp": row["timestamp"],
                "previous_entry_sha256": row["previous_entry_sha256"],
            }
            actual = _digest(payload)
            if actual != row["entry_sha256"]:
                failures.append(f"ENTRY_HASH_MISMATCH:{seq}")
            previous = str(row["entry_sha256"])
        return {
            "schema_version": "workspace-adaptive-learning-ledger-verification/v1",
            "entry_count": len(rows),
            "passed": not failures,
            "failures": failures,
            "head_sha256": previous,
        }
