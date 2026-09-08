"""Bounded persistent contradiction index for canonical adaptive learning.

The index lives inside the existing :class:`AdaptiveLearningStore` SQLite
database. It stores only metadata commitments and lifecycle state; raw
contradiction summaries and evidence identifiers are never persisted here.

The index is maintenance evidence only. It cannot stage, promote, archive,
rollback, materialize, invoke tools/models, access credentials/network, or
grant runtime authority.
"""
from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .adaptive_learning_checkpoint import LearningCheckpointAuthority
from .adaptive_learning_contract import ContradictionRecord, LearningContractError
from .adaptive_learning_store import AdaptiveLearningStore, GENESIS_HASH

CONTRADICTION_EVENT_SCHEMA = "workspace-learning-contradiction-index-event/v1"
CONTRADICTION_STATE_SCHEMA = "workspace-learning-contradiction-index-state/v1"
CONTRADICTION_STATISTICS_SCHEMA = "workspace-learning-contradiction-statistics/v1"
CONTRADICTION_VERIFICATION_SCHEMA = "workspace-learning-contradiction-index-verification/v1"
_EVIDENCE_COMMITMENT_SCHEMA = "workspace-learning-contradiction-evidence-commitment/v1"

_ALLOWED_EVENTS = {"open", "resolved", "dismissed"}
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_REASON = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_MAX_EVENTS = 10_000
_MAX_OPEN_PER_CANDIDATE = 128
_MAX_STAT_CANDIDATES = 128


class AdaptiveLearningContradictionError(ValueError):
    """Contradiction index state is stale, malformed, or untrusted."""


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


def _utc(value: Any, field: str) -> datetime:
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


def _record_projection(record: ContradictionRecord) -> dict[str, Any]:
    try:
        record.validate()
    except LearningContractError as exc:
        raise AdaptiveLearningContradictionError("invalid ContradictionRecord") from exc

    evidence_commitment = _digest(
        {
            "schema_version": _EVIDENCE_COMMITMENT_SCHEMA,
            "evidence": [
                {"ref_id": ref_id, "sha256": evidence_sha}
                for ref_id, evidence_sha in zip(
                    record.evidence_ref_ids,
                    record.evidence_hashes,
                    strict=True,
                )
            ],
        }
    )
    return {
        "contradiction_id": record.contradiction_id,
        "candidate_id": record.candidate_id,
        "status": record.status,
        "evidence_count": len(record.evidence_ref_ids),
        "evidence_set_sha256": evidence_commitment,
        "summary_sha256": "sha256:"
        + hashlib.sha256(record.summary.encode("utf-8")).hexdigest(),
        "record_sha256": _digest(record.to_payload()),
        "created_at": record.created_at,
        "resolved_at": record.resolved_at,
    }


@dataclass(frozen=True)
class ContradictionIndexState:
    contradiction_id: str
    candidate_id: str
    candidate_sha256: str
    item_id: str
    knowledge_sha256: str
    status: str
    evidence_count: int
    evidence_set_sha256: str
    summary_sha256: str
    record_sha256: str
    created_at: str
    resolved_at: str | None
    latest_event_sha256: str
    schema_version: str = CONTRADICTION_STATE_SCHEMA

    def validate(self) -> "ContradictionIndexState":
        if self.schema_version != CONTRADICTION_STATE_SCHEMA:
            raise AdaptiveLearningContradictionError("contradiction state schema mismatch")
        _id(self.contradiction_id, "contradiction_id")
        _id(self.candidate_id, "candidate_id")
        _sha(self.candidate_sha256, "candidate_sha256")
        _id(self.item_id, "item_id")
        _sha(self.knowledge_sha256, "knowledge_sha256")
        if self.status not in _ALLOWED_EVENTS:
            raise AdaptiveLearningContradictionError("invalid contradiction status")
        if (
            not isinstance(self.evidence_count, int)
            or isinstance(self.evidence_count, bool)
            or self.evidence_count < 1
            or self.evidence_count > 32
        ):
            raise AdaptiveLearningContradictionError("invalid evidence_count")
        _sha(self.evidence_set_sha256, "evidence_set_sha256")
        _sha(self.summary_sha256, "summary_sha256")
        _sha(self.record_sha256, "record_sha256")
        created = _utc(self.created_at, "created_at")
        if self.status == "open":
            if self.resolved_at is not None:
                raise AdaptiveLearningContradictionError(
                    "open contradiction cannot have resolved_at"
                )
        else:
            if self.resolved_at is None:
                raise AdaptiveLearningContradictionError(
                    "terminal contradiction requires resolved_at"
                )
            if _utc(self.resolved_at, "resolved_at") < created:
                raise AdaptiveLearningContradictionError(
                    "contradiction resolution predates creation"
                )
        _sha(self.latest_event_sha256, "latest_event_sha256")
        return self

    def to_payload(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "contradiction_id": self.contradiction_id,
            "candidate_id": self.candidate_id,
            "candidate_sha256": self.candidate_sha256,
            "item_id": self.item_id,
            "knowledge_sha256": self.knowledge_sha256,
            "status": self.status,
            "evidence_count": self.evidence_count,
            "evidence_set_sha256": self.evidence_set_sha256,
            "summary_sha256": self.summary_sha256,
            "record_sha256": self.record_sha256,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
            "latest_event_sha256": self.latest_event_sha256,
        }


@dataclass(frozen=True)
class ContradictionIndexEvent:
    seq: int
    event_id: str
    event_type: str
    contradiction_id: str
    candidate_id: str
    candidate_sha256: str
    item_id: str
    knowledge_sha256: str
    evidence_count: int
    evidence_set_sha256: str
    summary_sha256: str
    record_sha256: str
    created_at: str
    resolved_at: str | None
    actor_id: str
    reason_code: str
    source_checkpoint_sha256: str
    previous_entry_sha256: str
    entry_sha256: str
    schema_version: str = CONTRADICTION_EVENT_SCHEMA

    def validate(self) -> "ContradictionIndexEvent":
        if self.schema_version != CONTRADICTION_EVENT_SCHEMA:
            raise AdaptiveLearningContradictionError("contradiction event schema mismatch")
        if not isinstance(self.seq, int) or isinstance(self.seq, bool) or self.seq < 1:
            raise AdaptiveLearningContradictionError("invalid contradiction event seq")
        _id(self.event_id, "event_id")
        if self.event_type not in _ALLOWED_EVENTS:
            raise AdaptiveLearningContradictionError("invalid contradiction event_type")
        ContradictionIndexState(
            contradiction_id=self.contradiction_id,
            candidate_id=self.candidate_id,
            candidate_sha256=self.candidate_sha256,
            item_id=self.item_id,
            knowledge_sha256=self.knowledge_sha256,
            status=self.event_type,
            evidence_count=self.evidence_count,
            evidence_set_sha256=self.evidence_set_sha256,
            summary_sha256=self.summary_sha256,
            record_sha256=self.record_sha256,
            created_at=self.created_at,
            resolved_at=self.resolved_at,
            latest_event_sha256=self.entry_sha256,
        ).validate()
        _id(self.actor_id, "actor_id")
        _reason(self.reason_code)
        _sha(self.source_checkpoint_sha256, "source_checkpoint_sha256")
        _sha(self.previous_entry_sha256, "previous_entry_sha256")
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
            "evidence_count": self.evidence_count,
            "evidence_set_sha256": self.evidence_set_sha256,
            "summary_sha256": self.summary_sha256,
            "record_sha256": self.record_sha256,
            "created_at": self.created_at,
            "resolved_at": self.resolved_at,
            "actor_id": self.actor_id,
            "reason_code": self.reason_code,
            "source_checkpoint_sha256": self.source_checkpoint_sha256,
            "previous_entry_sha256": self.previous_entry_sha256,
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
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts
        ):
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
    """Append-only contradiction metadata index within one canonical store DB."""

    def __init__(
        self,
        store: AdaptiveLearningStore,
        checkpoint_authority: LearningCheckpointAuthority,
    ):
        if not isinstance(store, AdaptiveLearningStore):
            raise AdaptiveLearningContradictionError("AdaptiveLearningStore required")
        if not isinstance(checkpoint_authority, LearningCheckpointAuthority):
            raise AdaptiveLearningContradictionError(
                "LearningCheckpointAuthority required"
            )
        self.store = store
        self.checkpoint_authority = checkpoint_authority
        self._verify_checkpoint()
        self.initialize()

    def initialize(self) -> None:
        with self.store.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS learning_contradiction_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    schema_version TEXT NOT NULL,
                    event_id TEXT NOT NULL UNIQUE,
                    event_type TEXT NOT NULL
                        CHECK(event_type IN ('open','resolved','dismissed')),
                    contradiction_id TEXT NOT NULL,
                    candidate_id TEXT NOT NULL,
                    candidate_sha256 TEXT NOT NULL,
                    item_id TEXT NOT NULL,
                    knowledge_sha256 TEXT NOT NULL,
                    evidence_count INTEGER NOT NULL,
                    evidence_set_sha256 TEXT NOT NULL,
                    summary_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT,
                    actor_id TEXT NOT NULL,
                    reason_code TEXT NOT NULL,
                    source_checkpoint_sha256 TEXT NOT NULL,
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

    def _verify_checkpoint(self):
        try:
            return self.checkpoint_authority.verify(self.store)
        except ValueError as exc:
            raise AdaptiveLearningContradictionError(
                "AUTHENTICATED_LEARNING_CHECKPOINT_INVALID"
            ) from exc

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
            raise AdaptiveLearningContradictionError(
                "CONTRADICTION_CANDIDATE_NOT_FOUND"
            )
        try:
            candidate = self.store._candidate_from_row(row)
        except ValueError as exc:
            raise AdaptiveLearningContradictionError(
                "CONTRADICTION_CANDIDATE_INTEGRITY_FAILED"
            ) from exc
        if candidate.candidate_id != candidate_id:
            raise AdaptiveLearningContradictionError(
                "CONTRADICTION_CANDIDATE_ID_MISMATCH"
            )
        return (
            str(row["candidate_sha256"]),
            str(row["item_id"]),
            str(row["knowledge_sha256"]),
        )

    @staticmethod
    def _transition_identity(state: ContradictionIndexState) -> tuple[Any, ...]:
        return (
            state.contradiction_id,
            state.candidate_id,
            state.candidate_sha256,
            state.item_id,
            state.knowledge_sha256,
            state.evidence_count,
            state.evidence_set_sha256,
            state.summary_sha256,
            state.created_at,
        )

    def _event_from_row(self, row: sqlite3.Row) -> ContradictionIndexEvent:
        return ContradictionIndexEvent(
            seq=int(row["seq"]),
            event_id=str(row["event_id"]),
            event_type=str(row["event_type"]),
            contradiction_id=str(row["contradiction_id"]),
            candidate_id=str(row["candidate_id"]),
            candidate_sha256=str(row["candidate_sha256"]),
            item_id=str(row["item_id"]),
            knowledge_sha256=str(row["knowledge_sha256"]),
            evidence_count=int(row["evidence_count"]),
            evidence_set_sha256=str(row["evidence_set_sha256"]),
            summary_sha256=str(row["summary_sha256"]),
            record_sha256=str(row["record_sha256"]),
            created_at=str(row["created_at"]),
            resolved_at=(
                None if row["resolved_at"] is None else str(row["resolved_at"])
            ),
            actor_id=str(row["actor_id"]),
            reason_code=str(row["reason_code"]),
            source_checkpoint_sha256=str(row["source_checkpoint_sha256"]),
            previous_entry_sha256=str(row["previous_entry_sha256"]),
            entry_sha256=str(row["entry_sha256"]),
        ).validate()

    def _state_from_row(self, row: sqlite3.Row) -> ContradictionIndexState:
        event = self._event_from_row(row)
        return ContradictionIndexState(
            contradiction_id=event.contradiction_id,
            candidate_id=event.candidate_id,
            candidate_sha256=event.candidate_sha256,
            item_id=event.item_id,
            knowledge_sha256=event.knowledge_sha256,
            status=event.event_type,
            evidence_count=event.evidence_count,
            evidence_set_sha256=event.evidence_set_sha256,
            summary_sha256=event.summary_sha256,
            record_sha256=event.record_sha256,
            created_at=event.created_at,
            resolved_at=event.resolved_at,
            latest_event_sha256=event.entry_sha256,
        ).validate()

    @staticmethod
    def _entry_payload_from_row(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "schema_version": str(row["schema_version"]),
            "seq": int(row["seq"]),
            "event_id": str(row["event_id"]),
            "event_type": str(row["event_type"]),
            "contradiction_id": str(row["contradiction_id"]),
            "candidate_id": str(row["candidate_id"]),
            "candidate_sha256": str(row["candidate_sha256"]),
            "item_id": str(row["item_id"]),
            "knowledge_sha256": str(row["knowledge_sha256"]),
            "evidence_count": int(row["evidence_count"]),
            "evidence_set_sha256": str(row["evidence_set_sha256"]),
            "summary_sha256": str(row["summary_sha256"]),
            "record_sha256": str(row["record_sha256"]),
            "created_at": str(row["created_at"]),
            "resolved_at": (
                None if row["resolved_at"] is None else str(row["resolved_at"])
            ),
            "actor_id": str(row["actor_id"]),
            "reason_code": str(row["reason_code"]),
            "source_checkpoint_sha256": str(row["source_checkpoint_sha256"]),
            "previous_entry_sha256": str(row["previous_entry_sha256"]),
        }

    def _verify_conn(self, conn: sqlite3.Connection) -> dict[str, Any]:
        rows = conn.execute(
            "SELECT * FROM learning_contradiction_events ORDER BY seq"
        ).fetchall()
        failures: list[str] = []
        previous = GENESIS_HASH
        states: dict[str, ContradictionIndexState] = {}
        if len(rows) > _MAX_EVENTS:
            failures.append("EVENT_CAPACITY_EXCEEDED")

        for expected_seq, row in enumerate(rows, start=1):
            seq = int(row["seq"])
            if seq != expected_seq:
                failures.append(f"SEQ_GAP:{expected_seq}:{seq}")
            if str(row["schema_version"]) != CONTRADICTION_EVENT_SCHEMA:
                failures.append(f"SCHEMA_MISMATCH:{seq}")
            if str(row["previous_entry_sha256"]) != previous:
                failures.append(f"CHAIN_PREVIOUS_MISMATCH:{seq}")
            try:
                event = self._event_from_row(row)
                state = self._state_from_row(row)
                if event.event_type != state.status:
                    failures.append(f"EVENT_STATUS_MISMATCH:{seq}")

                prior = states.get(state.contradiction_id)
                if prior is None:
                    if state.status != "open":
                        failures.append(f"TERMINAL_WITHOUT_OPEN:{seq}")
                else:
                    if prior.status != "open":
                        failures.append(f"EVENT_AFTER_TERMINAL:{seq}")
                    if self._transition_identity(prior) != self._transition_identity(
                        state
                    ):
                        failures.append(f"TRANSITION_IDENTITY_MISMATCH:{seq}")
                states[state.contradiction_id] = state

                try:
                    candidate_sha, item_id, knowledge_sha = self._binding_for_candidate(
                        conn, state.candidate_id
                    )
                    if candidate_sha != state.candidate_sha256:
                        failures.append(f"CANDIDATE_SHA_MISMATCH:{seq}")
                    if item_id != state.item_id:
                        failures.append(f"ITEM_ID_MISMATCH:{seq}")
                    if knowledge_sha != state.knowledge_sha256:
                        failures.append(f"KNOWLEDGE_SHA_MISMATCH:{seq}")
                except AdaptiveLearningContradictionError:
                    failures.append(f"CANDIDATE_BINDING_INVALID:{seq}")
            except (AdaptiveLearningContradictionError, TypeError, ValueError):
                failures.append(f"EVENT_INTEGRITY_FAILED:{seq}")

            try:
                actual = _digest(self._entry_payload_from_row(row))
            except (KeyError, TypeError, ValueError):
                actual = ""
            if actual != str(row["entry_sha256"]):
                failures.append(f"ENTRY_HASH_MISMATCH:{seq}")
            previous = str(row["entry_sha256"])

        return {
            "schema_version": CONTRADICTION_VERIFICATION_SCHEMA,
            "entry_count": len(rows),
            "passed": not failures,
            "failures": tuple(failures),
            "head_sha256": previous,
        }

    def _assert_integrity_conn(self, conn: sqlite3.Connection) -> None:
        verification = self._verify_conn(conn)
        if not verification["passed"]:
            raise AdaptiveLearningContradictionError(
                "CONTRADICTION_INDEX_INTEGRITY_FAILED:"
                + ",".join(verification["failures"][:8])
            )

    def _latest_rows_for_candidate(
        self,
        conn: sqlite3.Connection,
        candidate_id: str,
    ) -> dict[str, sqlite3.Row]:
        rows = conn.execute(
            """
            SELECT * FROM learning_contradiction_events
            WHERE candidate_id=? ORDER BY seq
            """,
            (candidate_id,),
        ).fetchall()
        latest: dict[str, sqlite3.Row] = {}
        for row in rows:
            latest[str(row["contradiction_id"])] = row
        return latest

    def record(
        self,
        record: ContradictionRecord,
        *,
        expected_candidate_sha256: str,
        expected_history_head_sha256: str,
        actor_id: str,
        reason_code: str,
    ) -> ContradictionIndexEvent:
        projection = _record_projection(record)
        expected_candidate = _sha(
            expected_candidate_sha256, "expected_candidate_sha256"
        )
        expected_head = _sha(
            expected_history_head_sha256, "expected_history_head_sha256"
        )
        actor = _id(actor_id, "actor_id")
        code = _reason(reason_code)
        created = _utc(projection["created_at"], "created_at")
        if projection["status"] != "open":
            resolved = projection["resolved_at"]
            if resolved is None:
                raise AdaptiveLearningContradictionError(
                    "terminal contradiction requires resolved_at"
                )
            if _utc(resolved, "resolved_at") < created:
                raise AdaptiveLearningContradictionError(
                    "contradiction resolution predates creation"
                )

        checkpoint = self._verify_checkpoint()
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            try:
                self.store._assert_ledger_integrity(conn)
            except ValueError as exc:
                raise AdaptiveLearningContradictionError(
                    "CANONICAL_LEARNING_LEDGER_INTEGRITY_FAILED"
                ) from exc
            self._assert_integrity_conn(conn)

            previous = conn.execute(
                """
                SELECT entry_sha256 FROM learning_contradiction_events
                ORDER BY seq DESC LIMIT 1
                """
            ).fetchone()
            previous_hash = str(previous["entry_sha256"]) if previous else GENESIS_HASH
            if previous_hash != expected_head:
                raise AdaptiveLearningContradictionError(
                    "CONTRADICTION_INDEX_HEAD_CHANGED"
                )

            candidate_sha, item_id, knowledge_sha = self._binding_for_candidate(
                conn, record.candidate_id
            )
            if candidate_sha != expected_candidate:
                raise AdaptiveLearningContradictionError(
                    "CONTRADICTION_CANDIDATE_SHA_CHANGED"
                )

            prior_rows = conn.execute(
                """
                SELECT * FROM learning_contradiction_events
                WHERE contradiction_id=? ORDER BY seq
                """,
                (record.contradiction_id,),
            ).fetchall()
            if not prior_rows:
                if record.status != "open":
                    raise AdaptiveLearningContradictionError(
                        "CONTRADICTION_MUST_OPEN_FIRST"
                    )
                latest = self._latest_rows_for_candidate(conn, record.candidate_id)
                open_count = sum(
                    1
                    for row in latest.values()
                    if str(row["event_type"]) == "open"
                )
                if open_count >= _MAX_OPEN_PER_CANDIDATE:
                    raise AdaptiveLearningContradictionError(
                        "OPEN_CONTRADICTION_CAPACITY_EXCEEDED"
                    )
            else:
                latest_row = prior_rows[-1]
                prior = self._state_from_row(latest_row)
                projected_state = ContradictionIndexState(
                    contradiction_id=record.contradiction_id,
                    candidate_id=record.candidate_id,
                    candidate_sha256=candidate_sha,
                    item_id=item_id,
                    knowledge_sha256=knowledge_sha,
                    status=record.status,
                    evidence_count=projection["evidence_count"],
                    evidence_set_sha256=projection["evidence_set_sha256"],
                    summary_sha256=projection["summary_sha256"],
                    record_sha256=projection["record_sha256"],
                    created_at=record.created_at,
                    resolved_at=record.resolved_at,
                    latest_event_sha256=str(latest_row["entry_sha256"]),
                ).validate()

                if (
                    prior.status == projected_state.status
                    and prior.record_sha256 == projected_state.record_sha256
                ):
                    if (
                        str(latest_row["actor_id"]) != actor
                        or str(latest_row["reason_code"]) != code
                    ):
                        raise AdaptiveLearningContradictionError(
                            "CONTRADICTION_EVENT_METADATA_IMMUTABLE"
                        )
                    return self._event_from_row(latest_row)

                if prior.status != "open":
                    raise AdaptiveLearningContradictionError(
                        "CONTRADICTION_ALREADY_TERMINAL"
                    )
                if record.status == "open":
                    raise AdaptiveLearningContradictionError(
                        "CONTRADICTION_ALREADY_OPEN"
                    )
                if self._transition_identity(prior) != self._transition_identity(
                    projected_state
                ):
                    raise AdaptiveLearningContradictionError(
                        "CONTRADICTION_TRANSITION_IDENTITY_CHANGED"
                    )

            next_seq = int(
                conn.execute(
                    """
                    SELECT COALESCE(MAX(seq),0)+1 AS n
                    FROM learning_contradiction_events
                    """
                ).fetchone()["n"]
            )
            if next_seq > _MAX_EVENTS:
                raise AdaptiveLearningContradictionError(
                    "CONTRADICTION_EVENT_CAPACITY_EXCEEDED"
                )

            event_id = (
                f"contradiction-event:{next_seq}:"
                f"{projection['record_sha256'][7:23]}"
            )
            payload = {
                "schema_version": CONTRADICTION_EVENT_SCHEMA,
                "seq": next_seq,
                "event_id": event_id,
                "event_type": record.status,
                "contradiction_id": record.contradiction_id,
                "candidate_id": record.candidate_id,
                "candidate_sha256": candidate_sha,
                "item_id": item_id,
                "knowledge_sha256": knowledge_sha,
                "evidence_count": projection["evidence_count"],
                "evidence_set_sha256": projection["evidence_set_sha256"],
                "summary_sha256": projection["summary_sha256"],
                "record_sha256": projection["record_sha256"],
                "created_at": record.created_at,
                "resolved_at": record.resolved_at,
                "actor_id": actor,
                "reason_code": code,
                "source_checkpoint_sha256": checkpoint.checkpoint_sha256,
                "previous_entry_sha256": previous_hash,
            }
            entry_sha = _digest(payload)
            conn.execute(
                """
                INSERT INTO learning_contradiction_events(
                    seq,schema_version,event_id,event_type,contradiction_id,
                    candidate_id,candidate_sha256,item_id,knowledge_sha256,
                    evidence_count,evidence_set_sha256,summary_sha256,record_sha256,
                    created_at,resolved_at,actor_id,reason_code,
                    source_checkpoint_sha256,previous_entry_sha256,entry_sha256
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    next_seq,
                    CONTRADICTION_EVENT_SCHEMA,
                    event_id,
                    record.status,
                    record.contradiction_id,
                    record.candidate_id,
                    candidate_sha,
                    item_id,
                    knowledge_sha,
                    projection["evidence_count"],
                    projection["evidence_set_sha256"],
                    projection["summary_sha256"],
                    projection["record_sha256"],
                    record.created_at,
                    record.resolved_at,
                    actor,
                    code,
                    checkpoint.checkpoint_sha256,
                    previous_hash,
                    entry_sha,
                ),
            )
            row = conn.execute(
                "SELECT * FROM learning_contradiction_events WHERE seq=?",
                (next_seq,),
            ).fetchone()
            return self._event_from_row(row)

    def verify(self) -> dict[str, Any]:
        self._verify_checkpoint()
        with self.store.connect() as conn:
            try:
                self.store._assert_ledger_integrity(conn)
            except ValueError as exc:
                raise AdaptiveLearningContradictionError(
                    "CANONICAL_LEARNING_LEDGER_INTEGRITY_FAILED"
                ) from exc
            return self._verify_conn(conn)

    def events(
        self,
        *,
        max_events: int = _MAX_EVENTS,
    ) -> tuple[ContradictionIndexEvent, ...]:
        if (
            not isinstance(max_events, int)
            or isinstance(max_events, bool)
            or not (1 <= max_events <= _MAX_EVENTS)
        ):
            raise AdaptiveLearningContradictionError("invalid max_events")
        self._verify_checkpoint()
        with self.store.connect() as conn:
            self.store._assert_ledger_integrity(conn)
            self._assert_integrity_conn(conn)
            count = int(
                conn.execute(
                    "SELECT COUNT(*) AS n FROM learning_contradiction_events"
                ).fetchone()["n"]
            )
            if count > max_events:
                raise AdaptiveLearningContradictionError(
                    "CONTRADICTION_EVENT_SCAN_CAPACITY_EXCEEDED"
                )
            rows = conn.execute(
                "SELECT * FROM learning_contradiction_events ORDER BY seq"
            ).fetchall()
            return tuple(self._event_from_row(row) for row in rows)

    def open_for_candidate(
        self,
        candidate_id: str,
    ) -> tuple[ContradictionIndexState, ...]:
        candidate = _id(candidate_id, "candidate_id")
        self._verify_checkpoint()
        with self.store.connect() as conn:
            self.store._assert_ledger_integrity(conn)
            self._assert_integrity_conn(conn)
            self._binding_for_candidate(conn, candidate)
            latest = self._latest_rows_for_candidate(conn, candidate)
            result = tuple(
                sorted(
                    (
                        self._state_from_row(row)
                        for row in latest.values()
                        if str(row["event_type"]) == "open"
                    ),
                    key=lambda state: state.contradiction_id,
                )
            )
            if len(result) > _MAX_OPEN_PER_CANDIDATE:
                raise AdaptiveLearningContradictionError(
                    "OPEN_CONTRADICTION_CAPACITY_EXCEEDED"
                )
            return result

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
        self._verify_checkpoint()
        with self.store.connect() as conn:
            self.store._assert_ledger_integrity(conn)
            self._assert_integrity_conn(conn)
            rows = conn.execute(
                "SELECT * FROM learning_contradiction_events ORDER BY seq"
            ).fetchall()
            latest: dict[str, sqlite3.Row] = {}
            for row in rows:
                latest[str(row["contradiction_id"])] = row

            grouped: dict[tuple[str, str, str, str], list[ContradictionIndexState]] = {}
            for row in latest.values():
                state = self._state_from_row(row)
                key = (
                    state.candidate_id,
                    state.candidate_sha256,
                    state.item_id,
                    state.knowledge_sha256,
                )
                grouped.setdefault(key, []).append(state)
            if len(grouped) > max_candidates:
                raise AdaptiveLearningContradictionError(
                    "CONTRADICTION_STATISTICS_CAPACITY_EXCEEDED"
                )

            output: list[ContradictionStatistics] = []
            for key in sorted(grouped):
                candidate_id, candidate_sha, item_id, knowledge_sha = key
                states = grouped[key]
                statuses = [state.status for state in states]
                contradiction_times = [state.created_at for state in states]
                resolution_times = [
                    state.resolved_at
                    for state in states
                    if state.status != "open" and state.resolved_at is not None
                ]
                output.append(
                    ContradictionStatistics(
                        candidate_id=candidate_id,
                        candidate_sha256=candidate_sha,
                        item_id=item_id,
                        knowledge_sha256=knowledge_sha,
                        total_contradictions=len(states),
                        open_contradictions=statuses.count("open"),
                        resolved_contradictions=statuses.count("resolved"),
                        dismissed_contradictions=statuses.count("dismissed"),
                        last_contradiction_at=(
                            max(contradiction_times)
                            if contradiction_times
                            else None
                        ),
                        last_resolution_at=(
                            max(resolution_times) if resolution_times else None
                        ),
                    ).validate()
                )
            return tuple(output)
