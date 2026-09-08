"""Append-only contradiction history bound to the canonical adaptive-learning store.

This module adds one maintenance index inside the existing AdaptiveLearningStore
SQLite database. It is not a second learning store and grants no promotion,
archive, rollback, model, tool, network, credential, shell, deployment, or
source-mutation authority.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .adaptive_learning_contract import ContradictionRecord, LearningContractError
from .adaptive_learning_store import AdaptiveLearningStore, GENESIS_HASH

CONTRADICTION_HISTORY_SCHEMA = "workspace-learning-contradiction-history/v1"
CONTRADICTION_STATISTICS_SCHEMA = "workspace-learning-contradiction-statistics/v1"
_ALLOWED_EVENTS = {"open", "resolved", "dismissed"}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASON = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_MAX_EVENTS = 10_000
_MAX_OPEN_PER_CANDIDATE = 128
_MAX_STAT_CANDIDATES = 128


class AdaptiveLearningContradictionError(ValueError):
    """Persistent contradiction history is stale, malformed, or untrusted."""


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _id(value: Any, field: str) -> str:
    text = str(value or "").strip()
    if not _ID.fullmatch(text):
        raise AdaptiveLearningContradictionError(f"invalid {field}")
    return text


def _sha(value: Any, field: str) -> str:
    text = str(value or "").strip().lower()
    if not _SHA.fullmatch(text):
        raise AdaptiveLearningContradictionError(f"invalid {field}")
    return text


def _reason(value: Any) -> str:
    text = str(value or "").strip().upper()
    if not _REASON.fullmatch(text):
        raise AdaptiveLearningContradictionError("invalid reason_code")
    return text


def _utc(value: str, field: str) -> datetime:
    text = str(value or "").strip()
    if not text.endswith("Z"):
        raise AdaptiveLearningContradictionError(f"invalid {field}")
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as exc:
        raise AdaptiveLearningContradictionError(f"invalid {field}") from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise AdaptiveLearningContradictionError(f"invalid {field}")
    return parsed


@dataclass(frozen=True)
class ContradictionHistoryEvent:
    seq: int
    event_id: str
    event_type: str
    contradiction_id: str
    candidate_id: str
    candidate_sha256: str
    item_id: str
    knowledge_sha256: str
    record_sha256: str
    actor_id: str
    reason_code: str
    timestamp: str
    entry_sha256: str
    schema_version: str = CONTRADICTION_HISTORY_SCHEMA

    def validate(self) -> "ContradictionHistoryEvent":
        if self.schema_version != CONTRADICTION_HISTORY_SCHEMA:
            raise AdaptiveLearningContradictionError("contradiction history schema mismatch")
        if not isinstance(self.seq, int) or isinstance(self.seq, bool) or self.seq < 1:
            raise AdaptiveLearningContradictionError("invalid contradiction history seq")
        _id(self.event_id, "event_id")
        if self.event_type not in _ALLOWED_EVENTS:
            raise AdaptiveLearningContradictionError("invalid contradiction event_type")
        _id(self.contradiction_id, "contradiction_id")
        _id(self.candidate_id, "candidate_id")
        _sha(self.candidate_sha256, "candidate_sha256")
        _id(self.item_id, "item_id")
        _sha(self.knowledge_sha256, "knowledge_sha256")
        _sha(self.record_sha256, "record_sha256")
        _id(self.actor_id, "actor_id")
        _reason(self.reason_code)
        _utc(self.timestamp, "timestamp")
        _sha(self.entry_sha256, "entry_sha256")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "seq": self.seq,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "contradiction_id": self.contradiction_id,
            "candidate_id": self.candidate_id,
            "candidate_sha256": self.candidate_sha256,
            "item_id": self.item_id,
            "knowledge_sha256": self.knowledge_sha256,
            "record_sha256": self.record_sha256,
            "actor_id": self.actor_id,
            "reason_code": self.reason_code,
            "timestamp": self.timestamp,
            "entry_sha256": self.entry_sha256,
        }


@dataclass(frozen=True)
class ContradictionStatistics:
    candidate_id: str
    candidate_sha256: str
    item_id: str
    knowledge_sha256: str
    total_contradictions: int
    open_contradictions: int
    resolved_contradictions: int
    dismissed_contradictions: int
    last_contradiction_at: str | None
    last_resolution_at: str | None
    schema_version: str = CONTRADICTION_STATISTICS_SCHEMA

    def _base_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "candidate_id": self.candidate_id,
            "candidate_sha256": self.candidate_sha256,
            "item_id": self.item_id,
            "knowledge_sha256": self.knowledge_sha256,
            "total_contradictions": self.total_contradictions,
            "open_contradictions": self.open_contradictions,
            "resolved_contradictions": self.resolved_contradictions,
            "dismissed_contradictions": self.dismissed_contradictions,
            "last_contradiction_at": self.last_contradiction_at,
            "last_resolution_at": self.last_resolution_at,
        }

    def validate(self) -> "ContradictionStatistics":
        if self.schema_version != CONTRADICTION_STATISTICS_SCHEMA:
            raise AdaptiveLearningContradictionError("contradiction statistics schema mismatch")
        _id(self.candidate_id, "candidate_id")
        _sha(self.candidate_sha256, "candidate_sha256")
        _id(self.item_id, "item_id")
        _sha(self.knowledge_sha256, "knowledge_sha256")
        counts = (
            self.total_contradictions,
            self.open_contradictions,
            self.resolved_contradictions,
            self.dismissed_contradictions,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
            raise AdaptiveLearningContradictionError("invalid contradiction statistics count")
        if self.total_contradictions != sum(counts[1:]):
            raise AdaptiveLearningContradictionError("contradiction statistics count mismatch")
        if self.last_contradiction_at is not None:
            _utc(self.last_contradiction_at, "last_contradiction_at")
        if self.last_resolution_at is not None:
            _utc(self.last_resolution_at, "last_resolution_at")
        return self

    @property
    def statistics_sha256(self) -> str:
        self.validate()
        return _digest(self._base_payload())

    def to_payload(self) -> dict[str, Any]:
        return {**self._base_payload(), "statistics_sha256": self.statistics_sha256}


class AdaptiveLearningContradictionIndex:
    """Tamper-evident contradiction history inside one AdaptiveLearningStore DB."""

    def __init__(self, store: AdaptiveLearningStore):
        if not isinstance(store, AdaptiveLearningStore):
            raise AdaptiveLearningContradictionError("AdaptiveLearningStore required")
        self.store = store
        self.initialize()

    def initialize(self) -> None:
        with self.store.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS learning_contradiction_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    schema_version TEXT NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL CHECK(event_type IN ('open','resolved','dismissed')),
                    contradiction_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    candidate_sha256 TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    knowledge_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    record_json TEXT NOT NULL,
                    actor_id TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    previous_entry_sha256 TEXT NOT NULL,
                    entry_sha256 TEXT NOT NULL UNIQUE
                );
                CREATE INDEX IF NOT EXISTS idx_learning_contradiction_id
                    ON learning_contradiction_events(contradiction_id, seq);
                CREATE INDEX IF NOT EXISTS idx_learning_contradiction_candidate
                    ON learning_contradiction_events(candidate_id, seq);

                CREATE TRIGGER IF NOT EXISTS learning_contradiction_events_no_update
                BEFORE UPDATE ON learning_contradiction_events
                BEGIN
                    SELECT RAISE(ABORT, 'learning contradiction history is append-only');
                END;

                CREATE TRIGGER IF NOT EXISTS learning_contradiction_events_no_delete
                BEFORE DELETE ON learning_contradiction_events
                BEGIN
                    SELECT RAISE(ABORT, 'learning contradiction history is append-only');
                END;
                """
            )

    def _record_from_row(self, row: sqlite3.Row) -> ContradictionRecord:
        try:
            payload = json.loads(str(row["record_json"]))
            record = ContradictionRecord.from_payload(payload)
        except (json.JSONDecodeError, LearningContractError, TypeError, KeyError) as exc:
            raise AdaptiveLearningContradictionError(
                "CONTRADICTION_HISTORY_INTEGRITY_FAILED:RECORD_JSON_INVALID"
            ) from exc
        if _digest(record.to_payload()) != str(row["record_sha256"]):
            raise AdaptiveLearningContradictionError(
                "CONTRADICTION_HISTORY_INTEGRITY_FAILED:RECORD_SHA_MISMATCH"
            )
        return record

    def _binding_for_candidate(
        self,
        conn: sqlite3.Connection,
        candidate_id: str,
    ) -> tuple[str, str, str]:
        row = conn.execute(
            """
            SELECT * FROM learning_versions
            WHERE candidate_id=?
            ORDER BY version_id DESC LIMIT 1
            """,
            (candidate_id,),
        ).fetchone()
        if row is None:
            raise AdaptiveLearningContradictionError("CONTRADICTION_CANDIDATE_NOT_FOUND")
        try:
            candidate = self.store._candidate_from_row(row)
        except ValueError as exc:
            raise AdaptiveLearningContradictionError(
                "CONTRADICTION_CANDIDATE_INTEGRITY_FAILED"
            ) from exc
        if candidate.candidate_id != candidate_id:
            raise AdaptiveLearningContradictionError("CONTRADICTION_CANDIDATE_ID_MISMATCH")
        return (
            str(row["candidate_sha256"]),
            str(row["item_id"]),
            str(row["knowledge_sha256"]),
        )

    @staticmethod
    def _transition_invariants(record: ContradictionRecord) -> dict[str, Any]:
        return {
            "contradiction_id": record.contradiction_id,
            "candidate_id": record.candidate_id,
            "evidence_ref_ids": list(record.evidence_ref_ids),
            "evidence_hashes": list(record.evidence_hashes),
            "summary": record.summary,
            "created_at": record.created_at,
        }

    def _verify_conn(self, conn: sqlite3.Connection) -> dict[str, Any]:
        rows = conn.execute("SELECT * FROM learning_contradiction_events ORDER BY seq").fetchall()
        failures: list[str] = []
        previous = GENESIS_HASH
        states: dict[str, ContradictionRecord] = {}
        if len(rows) > _MAX_EVENTS:
            failures.append("EVENT_CAPACITY_EXCEEDED")

        for expected_seq, row in enumerate(rows, start=1):
            seq = int(row["seq"])
            if seq != expected_seq:
                failures.append(f"SEQ_GAP:{expected_seq}:{seq}")
            if str(row["schema_version"]) != CONTRADICTION_HISTORY_SCHEMA:
                failures.append(f"SCHEMA_MISMATCH:{seq}")
            if str(row["previous_entry_sha256"]) != previous:
                failures.append(f"CHAIN_PREVIOUS_MISMATCH:{seq}")
            try:
                record = self._record_from_row(row)
                event_type = str(row["event_type"])
                if record.status != event_type:
                    failures.append(f"EVENT_STATUS_MISMATCH:{seq}")
                if record.contradiction_id != str(row["contradiction_id"]):
                    failures.append(f"CONTRADICTION_ID_MISMATCH:{seq}")
                if record.candidate_id != str(row["candidate_id"]):
                    failures.append(f"CANDIDATE_ID_MISMATCH:{seq}")
                expected_timestamp = record.created_at if event_type == "open" else record.resolved_at
                if expected_timestamp != str(row["timestamp"]):
                    failures.append(f"TIMESTAMP_MISMATCH:{seq}")
                prior = states.get(record.contradiction_id)
                if prior is None:
                    if record.status != "open":
                        failures.append(f"TERMINAL_WITHOUT_OPEN:{seq}")
                else:
                    if prior.status != "open":
                        failures.append(f"EVENT_AFTER_TERMINAL:{seq}")
                    if self._transition_invariants(prior) != self._transition_invariants(record):
                        failures.append(f"TRANSITION_IDENTITY_MISMATCH:{seq}")
                states[record.contradiction_id] = record
                try:
                    candidate_sha, item_id, knowledge_sha = self._binding_for_candidate(
                        conn, record.candidate_id
                    )
                    if candidate_sha != str(row["candidate_sha256"]):
                        failures.append(f"CANDIDATE_SHA_MISMATCH:{seq}")
                    if item_id != str(row["item_id"]):
                        failures.append(f"ITEM_ID_MISMATCH:{seq}")
                    if knowledge_sha != str(row["knowledge_sha256"]):
                        failures.append(f"KNOWLEDGE_SHA_MISMATCH:{seq}")
                except AdaptiveLearningContradictionError:
                    failures.append(f"CANDIDATE_BINDING_INVALID:{seq}")
            except AdaptiveLearningContradictionError:
                failures.append(f"RECORD_INTEGRITY_FAILED:{seq}")

            payload = {
                "schema_version": str(row["schema_version"]),
                "seq": seq,
                "event_id": str(row["event_id"]),
                "event_type": str(row["event_type"]),
                "contradiction_id": str(row["contradiction_id"]),
                "candidate_id": str(row["candidate_id"]),
                "candidate_sha256": str(row["candidate_sha256"]),
                "item_id": str(row["item_id"]),
                "knowledge_sha256": str(row["knowledge_sha256"]),
                "record_sha256": str(row["record_sha256"]),
                "actor_id": str(row["actor_id"]),
                "reason_code": str(row["reason_code"]),
                "timestamp": str(row["timestamp"]),
                "previous_entry_sha256": str(row["previous_entry_sha256"]),
            }
            actual = _digest(payload)
            if actual != str(row["entry_sha256"]):
                failures.append(f"ENTRY_HASH_MISMATCH:{seq}")
            previous = str(row["entry_sha256"])

        return {
            "schema_version": "workspace-learning-contradiction-history-verification/v1",
            "entry_count": len(rows),
            "passed": not failures,
            "failures": tuple(failures),
            "head_sha256": previous,
        }

    def _assert_integrity_conn(self, conn: sqlite3.Connection) -> None:
        verification = self._verify_conn(conn)
        if not verification["passed"]:
            raise AdaptiveLearningContradictionError(
                "CONTRADICTION_HISTORY_INTEGRITY_FAILED:"
                + ",".join(verification["failures"][:8])
            )

    def record(
        self,
        record: ContradictionRecord,
        *,
        actor_id: str,
        reason_code: str,
    ) -> ContradictionHistoryEvent:
        try:
            record.validate()
        except LearningContractError as exc:
            raise AdaptiveLearningContradictionError("invalid ContradictionRecord") from exc
        actor = _id(actor_id, "actor_id")
        code = _reason(reason_code)
        created_at = _utc(record.created_at, "created_at")
        if record.status == "open":
            timestamp = record.created_at
        else:
            if record.resolved_at is None:
                raise AdaptiveLearningContradictionError("terminal contradiction requires resolved_at")
            resolved_at = _utc(record.resolved_at, "resolved_at")
            if resolved_at < created_at:
                raise AdaptiveLearningContradictionError("contradiction resolution predates creation")
            timestamp = record.resolved_at

        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self.store._assert_ledger_integrity(conn)
            except ValueError as exc:
                raise AdaptiveLearningContradictionError(
                    "CANONICAL_LEARNING_LEDGER_INTEGRITY_FAILED"
                ) from exc
            self._assert_integrity_conn(conn)
            candidate_sha, item_id, knowledge_sha = self._binding_for_candidate(
                conn, record.candidate_id
            )
            prior_rows = conn.execute(
                "SELECT * FROM learning_contradiction_events WHERE contradiction_id=? ORDER BY seq",
                (record.contradiction_id,),
            ).fetchall()
            if not prior_rows:
                if record.status != "open":
                    raise AdaptiveLearningContradictionError("CONTRADICTION_MUST_OPEN_FIRST")
            else:
                latest = prior_rows[-1]
                prior = self._record_from_row(latest)
                if prior.to_payload() == record.to_payload():
                    if str(latest["actor_id"]) != actor or str(latest["reason_code"]) != code:
                        raise AdaptiveLearningContradictionError(
                            "CONTRADICTION_EVENT_METADATA_IMMUTABLE"
                        )
                    return self._event_from_row(latest)
                if prior.status != "open":
                    raise AdaptiveLearningContradictionError("CONTRADICTION_ALREADY_TERMINAL")
                if record.status == "open":
                    raise AdaptiveLearningContradictionError("CONTRADICTION_ALREADY_OPEN")
                if self._transition_invariants(prior) != self._transition_invariants(record):
                    raise AdaptiveLearningContradictionError(
                        "CONTRADICTION_TRANSITION_IDENTITY_CHANGED"
                    )

            next_seq = int(
                conn.execute(
                    "SELECT COALESCE(MAX(seq),0)+1 AS n FROM learning_contradiction_events"
                ).fetchone()["n"]
            )
            if next_seq > _MAX_EVENTS:
                raise AdaptiveLearningContradictionError("CONTRADICTION_EVENT_CAPACITY_EXCEEDED")
            previous = conn.execute(
                "SELECT entry_sha256 FROM learning_contradiction_events ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            previous_hash = str(previous["entry_sha256"]) if previous else GENESIS_HASH
            event_id = f"contradiction-event:{record.contradiction_id}:{record.status}:{next_seq}"
            record_payload = record.to_payload()
            record_sha = _digest(record_payload)
            payload = {
                "schema_version": CONTRADICTION_HISTORY_SCHEMA,
                "seq": next_seq,
                "event_id": event_id,
                "event_type": record.status,
                "contradiction_id": record.contradiction_id,
                "candidate_id": record.candidate_id,
                "candidate_sha256": candidate_sha,
                "item_id": item_id,
                "knowledge_sha256": knowledge_sha,
                "record_sha256": record_sha,
                "actor_id": actor,
                "reason_code": code,
                "timestamp": timestamp,
                "previous_entry_sha256": previous_hash,
            }
            entry_sha = _digest(payload)
            conn.execute(
                """
                INSERT INTO learning_contradiction_events(
                    seq,schema_version,event_id,event_type,contradiction_id,candidate_id,
                    candidate_sha256,item_id,knowledge_sha256,record_sha256,record_json,
                    actor_id,reason_code,timestamp,previous_entry_sha256,entry_sha256
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    next_seq,
                    CONTRADICTION_HISTORY_SCHEMA,
                    event_id,
                    record.status,
                    record.contradiction_id,
                    record.candidate_id,
                    candidate_sha,
                    item_id,
                    knowledge_sha,
                    record_sha,
                    _canonical(record_payload),
                    actor,
                    code,
                    timestamp,
                    previous_hash,
                    entry_sha,
                ),
            )
            row = conn.execute(
                "SELECT * FROM learning_contradiction_events WHERE seq=?", (next_seq,)
            ).fetchone()
            return self._event_from_row(row)

    def _event_from_row(self, row: sqlite3.Row) -> ContradictionHistoryEvent:
        return ContradictionHistoryEvent(
            seq=int(row["seq"]),
            event_id=str(row["event_id"]),
            event_type=str(row["event_type"]),
            contradiction_id=str(row["contradiction_id"]),
            candidate_id=str(row["candidate_id"]),
            candidate_sha256=str(row["candidate_sha256"]),
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            record_sha256=str(row["record_sha256"]),
            actor_id=str(row["actor_id"]),
            reason_code=str(row["reason_code"]),
            timestamp=str(row["timestamp"]),
            entry_sha256=str(row["entry_sha256"]),
        ).validate()

    def verify(self) -> dict[str, Any]:
        with self.store.connect() as conn:
            try:
                self.store._assert_ledger_integrity(conn)
            except ValueError as exc:
                raise AdaptiveLearningContradictionError(
                    "CANONICAL_LEARNING_LEDGER_INTEGRITY_FAILED"
                ) from exc
            return self._verify_conn(conn)

    def open_for_candidate(self, candidate_id: str) -> tuple[ContradictionRecord, ...]:
        candidate = _id(candidate_id, "candidate_id")
        with self.store.connect() as conn:
            self.store._assert_ledger_integrity(conn)
            self._assert_integrity_conn(conn)
            self._binding_for_candidate(conn, candidate)
            rows = conn.execute(
                "SELECT * FROM learning_contradiction_events WHERE candidate_id=? ORDER BY seq",
                (candidate,),
            ).fetchall()
            latest: dict[str, ContradictionRecord] = {}
            for row in rows:
                record = self._record_from_row(row)
                latest[record.contradiction_id] = record
            result = tuple(
                sorted(
                    (record for record in latest.values() if record.status == "open"),
                    key=lambda record: record.contradiction_id,
                )
            )
            if len(result) > _MAX_OPEN_PER_CANDIDATE:
                raise AdaptiveLearningContradictionError("OPEN_CONTRADICTION_CAPACITY_EXCEEDED")
            return result

    def events(self, *, max_events: int = _MAX_EVENTS) -> tuple[ContradictionHistoryEvent, ...]:
        if not isinstance(max_events, int) or isinstance(max_events, bool) or not (1 <= max_events <= _MAX_EVENTS):
            raise AdaptiveLearningContradictionError("invalid max_events")
        with self.store.connect() as conn:
            self.store._assert_ledger_integrity(conn)
            self._assert_integrity_conn(conn)
            count = int(conn.execute("SELECT COUNT(*) AS n FROM learning_contradiction_events").fetchone()["n"])
            if count > max_events:
                raise AdaptiveLearningContradictionError("CONTRADICTION_EVENT_SCAN_CAPACITY_EXCEEDED")
            rows = conn.execute("SELECT * FROM learning_contradiction_events ORDER BY seq").fetchall()
            return tuple(self._event_from_row(row) for row in rows)

    def statistics(
        self,
        *,
        max_candidates: int = _MAX_STAT_CANDIDATES,
    ) -> tuple[ContradictionStatistics, ...]:
        if (
            not isinstance(max_candidates, int)
            or isinstance(max_candidates, bool)
            or not (1 <= max_candidates <= _MAX_STAT_CANDIDATES)
        ):
            raise AdaptiveLearningContradictionError("invalid max_candidates")
        with self.store.connect() as conn:
            self.store._assert_ledger_integrity(conn)
            self._assert_integrity_conn(conn)
            rows = conn.execute("SELECT * FROM learning_contradiction_events ORDER BY seq").fetchall()
            latest: dict[str, tuple[sqlite3.Row, ContradictionRecord]] = {}
            created: dict[str, str] = {}
            for row in rows:
                record = self._record_from_row(row)
                latest[record.contradiction_id] = (row, record)
                created.setdefault(record.contradiction_id, record.created_at)

            grouped: dict[tuple[str, str, str, str], list[tuple[sqlite3.Row, ContradictionRecord]]] = {}
            for row, record in latest.values():
                key = (
                    str(row["candidate_id"]),
                    str(row["candidate_sha256"]),
                    str(row["item_id"]),
                    str(row["knowledge_sha256"]),
                )
                grouped.setdefault(key, []).append((row, record))
            if len(grouped) > max_candidates:
                raise AdaptiveLearningContradictionError(
                    "CONTRADICTION_STATISTICS_CAPACITY_EXCEEDED"
                )

            output: list[ContradictionStatistics] = []
            for key in sorted(grouped):
                candidate_id, candidate_sha, item_id, knowledge_sha = key
                values = grouped[key]
                statuses = [record.status for _, record in values]
                contradiction_times = [created[record.contradiction_id] for _, record in values]
                resolution_times = [
                    str(record.resolved_at)
                    for _, record in values
                    if record.status != "open" and record.resolved_at is not None
                ]
                output.append(
                    ContradictionStatistics(
                        candidate_id=candidate_id,
                        candidate_sha256=candidate_sha,
                        item_id=item_id,
                        knowledge_sha256=knowledge_sha,
                        total_contradictions=len(values),
                        open_contradictions=statuses.count("open"),
                        resolved_contradictions=statuses.count("resolved"),
                        dismissed_contradictions=statuses.count("dismissed"),
                        last_contradiction_at=max(contradiction_times) if contradiction_times else None,
                        last_resolution_at=max(resolution_times) if resolution_times else None,
                    ).validate()
                )
            return tuple(output)
