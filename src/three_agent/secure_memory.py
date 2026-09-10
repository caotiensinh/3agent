from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

MEMORY_SCHEMA = "workspace-secure-memory/v1"
MEMORY_RECEIPT_SCHEMA = "workspace-secure-memory-receipt/v1"
_DEFAULT_MAX_RECORDS = 20
_DEFAULT_MAX_BYTES = 64 * 1024
_ALLOWED_CLASSIFICATIONS = frozenset({"public", "internal", "confidential", "restricted"})


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat()


def _canonical_json(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class MemoryRecord:
    record_id: str
    namespace: str
    key: str
    value: Any
    metadata: dict[str, Any]
    classification: str
    provenance: str
    created_at: str
    updated_at: str
    expires_at: str | None
    version: int
    integrity_hash: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": MEMORY_SCHEMA,
            "record_id": self.record_id,
            "namespace": self.namespace,
            "key": self.key,
            "value": self.value,
            "metadata": self.metadata,
            "classification": self.classification,
            "provenance": self.provenance,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "expires_at": self.expires_at,
            "version": self.version,
            "integrity_hash": self.integrity_hash,
        }


@dataclass(frozen=True)
class MemoryReceipt:
    sequence: int
    receipt_id: str
    prev_hash: str
    event_hash: str
    action: str
    namespace: str
    record_id: str
    actor: str
    approved_by: str
    result: str
    timestamp: str
    details: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": MEMORY_RECEIPT_SCHEMA,
            "sequence": self.sequence,
            "receipt_id": self.receipt_id,
            "prev_hash": self.prev_hash,
            "event_hash": self.event_hash,
            "action": self.action,
            "namespace": self.namespace,
            "record_id": self.record_id,
            "actor": self.actor,
            "approved_by": self.approved_by,
            "result": self.result,
            "timestamp": self.timestamp,
            "details": self.details,
        }


ApprovalPolicy = Callable[[str, str, str, str], bool]


class SecureMemoryStore:
    """Local-first persistent memory with explicit mutation approval and receipts.

    Reads are namespace-scoped and bounded. Mutations are denied unless an
    approval policy authorizes the exact action/namespace/key/actor tuple or
    the caller supplies an explicit approver. The audit chain is tamper-evident,
    not tamper-proof: verification detects modification but cannot protect a
    database from an attacker who can rewrite the entire file and recompute it.
    """

    def __init__(
        self,
        database_path: str | Path,
        *,
        approval_policy: ApprovalPolicy | None = None,
        max_records: int = _DEFAULT_MAX_RECORDS,
        max_bytes: int = _DEFAULT_MAX_BYTES,
    ):
        if max_records < 1:
            raise ValueError("max_records must be positive")
        if max_bytes < 1:
            raise ValueError("max_bytes must be positive")
        self.database_path = Path(database_path)
        self.approval_policy = approval_policy
        self.max_records = max_records
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.database_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA busy_timeout=10000")
        return conn

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Use a transactional SQLite connection and always release its file handle."""
        conn = self.connect()
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self._connection() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secure_memory_records (
                    record_id TEXT PRIMARY KEY,
                    namespace TEXT NOT NULL,
                    memory_key TEXT NOT NULL,
                    value_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    classification TEXT NOT NULL,
                    provenance TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    expires_at TEXT,
                    version INTEGER NOT NULL,
                    integrity_hash TEXT NOT NULL,
                    UNIQUE(namespace, memory_key)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS secure_memory_receipts (
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    receipt_id TEXT NOT NULL UNIQUE,
                    prev_hash TEXT NOT NULL,
                    event_hash TEXT NOT NULL,
                    action TEXT NOT NULL,
                    namespace TEXT NOT NULL,
                    record_id TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    result TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    details_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_secure_memory_namespace "
                "ON secure_memory_records(namespace, updated_at DESC)"
            )

    @staticmethod
    def _identifier(value: object, *, field: str, max_length: int = 160) -> str:
        text = str(value or "").strip()
        if not text or len(text) > max_length or any(ord(ch) < 32 for ch in text):
            raise ValueError(f"{field} must be a non-empty compact string")
        return text

    @staticmethod
    def _classification(value: object) -> str:
        text = str(value or "").strip().lower()
        if text not in _ALLOWED_CLASSIFICATIONS:
            raise ValueError(f"classification must be one of {sorted(_ALLOWED_CLASSIFICATIONS)}")
        return text

    @staticmethod
    def record_id_for(namespace: str, key: str) -> str:
        return "mem_" + _sha256(f"{namespace}\0{key}")[:32]

    def _approved(
        self,
        action: str,
        namespace: str,
        key: str,
        actor: str,
        approved_by: str | None,
    ) -> str:
        if approved_by:
            return self._identifier(approved_by, field="approved_by")
        if self.approval_policy and self.approval_policy(action, namespace, key, actor):
            return "policy"
        raise PermissionError("MEMORY_MUTATION_APPROVAL_REQUIRED")

    @staticmethod
    def _integrity_payload(
        *,
        record_id: str,
        namespace: str,
        key: str,
        value_json: str,
        metadata_json: str,
        classification: str,
        provenance: str,
        created_at: str,
        updated_at: str,
        expires_at: str | None,
        version: int,
    ) -> str:
        return _canonical_json(
            {
                "record_id": record_id,
                "namespace": namespace,
                "key": key,
                "value_json": value_json,
                "metadata_json": metadata_json,
                "classification": classification,
                "provenance": provenance,
                "created_at": created_at,
                "updated_at": updated_at,
                "expires_at": expires_at,
                "version": version,
            }
        )

    def _append_receipt(
        self,
        conn: sqlite3.Connection,
        *,
        action: str,
        namespace: str,
        record_id: str,
        actor: str,
        approved_by: str,
        result: str,
        timestamp: str,
        details: dict[str, Any],
    ) -> MemoryReceipt:
        last = conn.execute(
            "SELECT event_hash FROM secure_memory_receipts ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        prev_hash = str(last["event_hash"]) if last else "GENESIS"
        body = {
            "action": action,
            "namespace": namespace,
            "record_id": record_id,
            "actor": actor,
            "approved_by": approved_by,
            "result": result,
            "timestamp": timestamp,
            "details": details,
            "prev_hash": prev_hash,
        }
        event_hash = _sha256(_canonical_json(body))
        receipt_id = "mrc_" + event_hash[:32]
        cur = conn.execute(
            """
            INSERT INTO secure_memory_receipts(
                receipt_id, prev_hash, event_hash, action, namespace, record_id,
                actor, approved_by, result, timestamp, details_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                receipt_id,
                prev_hash,
                event_hash,
                action,
                namespace,
                record_id,
                actor,
                approved_by,
                result,
                timestamp,
                _canonical_json(details),
            ),
        )
        return MemoryReceipt(
            sequence=int(cur.lastrowid),
            receipt_id=receipt_id,
            prev_hash=prev_hash,
            event_hash=event_hash,
            action=action,
            namespace=namespace,
            record_id=record_id,
            actor=actor,
            approved_by=approved_by,
            result=result,
            timestamp=timestamp,
            details=details,
        )

    def put(
        self,
        namespace: str,
        key: str,
        value: Any,
        *,
        actor: str,
        approved_by: str | None = None,
        metadata: dict[str, Any] | None = None,
        classification: str = "internal",
        provenance: str = "operator",
        ttl_seconds: int | None = None,
    ) -> tuple[MemoryRecord, MemoryReceipt]:
        namespace = self._identifier(namespace, field="namespace")
        key = self._identifier(key, field="key")
        actor = self._identifier(actor, field="actor")
        provenance = self._identifier(provenance, field="provenance", max_length=512)
        classification = self._classification(classification)
        approver = self._approved("put", namespace, key, actor, approved_by)
        if ttl_seconds is not None and ttl_seconds < 1:
            raise ValueError("ttl_seconds must be positive")
        value_json = _canonical_json(value)
        metadata_json = _canonical_json(metadata or {})
        now_dt = _utc_now()
        now = _iso(now_dt)
        expires_at = _iso(now_dt + timedelta(seconds=ttl_seconds)) if ttl_seconds else None
        record_id = self.record_id_for(namespace, key)

        with self._lock, self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            existing = conn.execute(
                "SELECT created_at, version FROM secure_memory_records WHERE record_id = ?",
                (record_id,),
            ).fetchone()
            created_at = str(existing["created_at"]) if existing else now
            version = int(existing["version"]) + 1 if existing else 1
            integrity_hash = _sha256(
                self._integrity_payload(
                    record_id=record_id,
                    namespace=namespace,
                    key=key,
                    value_json=value_json,
                    metadata_json=metadata_json,
                    classification=classification,
                    provenance=provenance,
                    created_at=created_at,
                    updated_at=now,
                    expires_at=expires_at,
                    version=version,
                )
            )
            conn.execute(
                """
                INSERT INTO secure_memory_records(
                    record_id, namespace, memory_key, value_json, metadata_json,
                    classification, provenance, created_at, updated_at, expires_at,
                    version, integrity_hash
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(record_id) DO UPDATE SET
                    value_json=excluded.value_json,
                    metadata_json=excluded.metadata_json,
                    classification=excluded.classification,
                    provenance=excluded.provenance,
                    updated_at=excluded.updated_at,
                    expires_at=excluded.expires_at,
                    version=excluded.version,
                    integrity_hash=excluded.integrity_hash
                """,
                (
                    record_id,
                    namespace,
                    key,
                    value_json,
                    metadata_json,
                    classification,
                    provenance,
                    created_at,
                    now,
                    expires_at,
                    version,
                    integrity_hash,
                ),
            )
            receipt = self._append_receipt(
                conn,
                action="put",
                namespace=namespace,
                record_id=record_id,
                actor=actor,
                approved_by=approver,
                result="ok",
                timestamp=now,
                details={"key_hash": _sha256(key), "version": version, "classification": classification},
            )
            conn.commit()

        return (
            MemoryRecord(
                record_id=record_id,
                namespace=namespace,
                key=key,
                value=json.loads(value_json),
                metadata=json.loads(metadata_json),
                classification=classification,
                provenance=provenance,
                created_at=created_at,
                updated_at=now,
                expires_at=expires_at,
                version=version,
                integrity_hash=integrity_hash,
            ),
            receipt,
        )

    def get(self, namespace: str, key: str) -> MemoryRecord | None:
        namespace = self._identifier(namespace, field="namespace")
        key = self._identifier(key, field="key")
        record_id = self.record_id_for(namespace, key)
        with self._connection() as conn:
            row = conn.execute(
                "SELECT * FROM secure_memory_records WHERE record_id=? AND namespace=?",
                (record_id, namespace),
            ).fetchone()
        if row is None or self._expired(row["expires_at"]):
            return None
        record = self._row_to_record(row)
        self._verify_record(record)
        return record

    def query(
        self,
        namespace: str,
        *,
        prefix: str | None = None,
        limit: int | None = None,
        max_bytes: int | None = None,
        classifications: Iterable[str] | None = None,
    ) -> tuple[MemoryRecord, ...]:
        namespace = self._identifier(namespace, field="namespace")
        bounded_limit = min(limit or self.max_records, self.max_records)
        if bounded_limit < 1:
            raise ValueError("limit must be positive")
        byte_budget = min(max_bytes or self.max_bytes, self.max_bytes)
        if byte_budget < 1:
            raise ValueError("max_bytes must be positive")
        allowed = None
        if classifications is not None:
            allowed = {self._classification(item) for item in classifications}
        sql = "SELECT * FROM secure_memory_records WHERE namespace=?"
        params: list[Any] = [namespace]
        if prefix is not None:
            prefix = self._identifier(prefix, field="prefix")
            sql += " AND memory_key LIKE ? ESCAPE '\\'"
            escaped = prefix.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            params.append(escaped + "%")
        sql += " ORDER BY updated_at DESC, memory_key LIMIT ?"
        params.append(bounded_limit)
        with self._connection() as conn:
            rows = conn.execute(sql, params).fetchall()

        result: list[MemoryRecord] = []
        used = 0
        for row in rows:
            if self._expired(row["expires_at"]):
                continue
            record = self._row_to_record(row)
            if allowed is not None and record.classification not in allowed:
                continue
            self._verify_record(record)
            encoded = len(_canonical_json(record.to_dict()).encode("utf-8"))
            if used + encoded > byte_budget:
                break
            used += encoded
            result.append(record)
        return tuple(result)

    def delete(
        self,
        namespace: str,
        key: str,
        *,
        actor: str,
        approved_by: str | None = None,
    ) -> MemoryReceipt:
        namespace = self._identifier(namespace, field="namespace")
        key = self._identifier(key, field="key")
        actor = self._identifier(actor, field="actor")
        approver = self._approved("delete", namespace, key, actor, approved_by)
        record_id = self.record_id_for(namespace, key)
        now = _iso(_utc_now())
        with self._lock, self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            cur = conn.execute(
                "DELETE FROM secure_memory_records WHERE record_id=? AND namespace=?",
                (record_id, namespace),
            )
            receipt = self._append_receipt(
                conn,
                action="delete",
                namespace=namespace,
                record_id=record_id,
                actor=actor,
                approved_by=approver,
                result="ok" if cur.rowcount else "not_found",
                timestamp=now,
                details={"key_hash": _sha256(key)},
            )
            conn.commit()
        return receipt

    def purge_expired(self, *, actor: str = "system", approved_by: str = "system-policy") -> int:
        now = _iso(_utc_now())
        removed = 0
        with self._lock, self._connection() as conn:
            conn.execute("BEGIN IMMEDIATE")
            rows = conn.execute(
                "SELECT record_id, namespace, memory_key FROM secure_memory_records "
                "WHERE expires_at IS NOT NULL AND expires_at <= ? ORDER BY record_id",
                (now,),
            ).fetchall()
            for row in rows:
                conn.execute(
                    "DELETE FROM secure_memory_records WHERE record_id=?",
                    (str(row["record_id"]),),
                )
                self._append_receipt(
                    conn,
                    action="expire",
                    namespace=str(row["namespace"]),
                    record_id=str(row["record_id"]),
                    actor=actor,
                    approved_by=approved_by,
                    result="ok",
                    timestamp=now,
                    details={"key_hash": _sha256(str(row["memory_key"]))},
                )
                removed += 1
            conn.commit()
        return removed

    def list_receipts(self) -> tuple[MemoryReceipt, ...]:
        with self._connection() as conn:
            rows = conn.execute(
                "SELECT * FROM secure_memory_receipts ORDER BY sequence"
            ).fetchall()
        return tuple(self._row_to_receipt(row) for row in rows)

    def verify_audit_chain(self) -> bool:
        previous = "GENESIS"
        for receipt in self.list_receipts():
            if receipt.prev_hash != previous:
                return False
            body = {
                "action": receipt.action,
                "namespace": receipt.namespace,
                "record_id": receipt.record_id,
                "actor": receipt.actor,
                "approved_by": receipt.approved_by,
                "result": receipt.result,
                "timestamp": receipt.timestamp,
                "details": receipt.details,
                "prev_hash": receipt.prev_hash,
            }
            expected = _sha256(_canonical_json(body))
            if expected != receipt.event_hash or receipt.receipt_id != "mrc_" + expected[:32]:
                return False
            previous = receipt.event_hash
        return True

    @staticmethod
    def _expired(expires_at: object) -> bool:
        if not expires_at:
            return False
        return datetime.fromisoformat(str(expires_at)) <= _utc_now()

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> MemoryRecord:
        return MemoryRecord(
            record_id=str(row["record_id"]),
            namespace=str(row["namespace"]),
            key=str(row["memory_key"]),
            value=json.loads(str(row["value_json"])),
            metadata=json.loads(str(row["metadata_json"])),
            classification=str(row["classification"]),
            provenance=str(row["provenance"]),
            created_at=str(row["created_at"]),
            updated_at=str(row["updated_at"]),
            expires_at=str(row["expires_at"]) if row["expires_at"] else None,
            version=int(row["version"]),
            integrity_hash=str(row["integrity_hash"]),
        )

    @staticmethod
    def _row_to_receipt(row: sqlite3.Row) -> MemoryReceipt:
        return MemoryReceipt(
            sequence=int(row["sequence"]),
            receipt_id=str(row["receipt_id"]),
            prev_hash=str(row["prev_hash"]),
            event_hash=str(row["event_hash"]),
            action=str(row["action"]),
            namespace=str(row["namespace"]),
            record_id=str(row["record_id"]),
            actor=str(row["actor"]),
            approved_by=str(row["approved_by"]),
            result=str(row["result"]),
            timestamp=str(row["timestamp"]),
            details=json.loads(str(row["details_json"])),
        )

    def _verify_record(self, record: MemoryRecord) -> None:
        expected = _sha256(
            self._integrity_payload(
                record_id=record.record_id,
                namespace=record.namespace,
                key=record.key,
                value_json=_canonical_json(record.value),
                metadata_json=_canonical_json(record.metadata),
                classification=record.classification,
                provenance=record.provenance,
                created_at=record.created_at,
                updated_at=record.updated_at,
                expires_at=record.expires_at,
                version=record.version,
            )
        )
        if expected != record.integrity_hash:
            raise RuntimeError("MEMORY_RECORD_INTEGRITY_FAILED")
