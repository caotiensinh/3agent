from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint
from .forensic_evidence import (
    CaseRecord,
    CustodyEvent,
    EvidenceObject,
    EvidenceProvenance,
    EvidenceReference,
    ForensicEventTime,
    verify_custody_chain,
)
from .storage import MonitoringStore

FORENSIC_STORE_SCHEMA_VERSION = 1
FORENSIC_STORE_RECEIPT_SCHEMA = "workspace-security-forensics/store-receipt-v1"

_FORENSIC_SCHEMA = """
CREATE TABLE IF NOT EXISTS forensic_schema_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS forensic_evidence (
    evidence_id TEXT PRIMARY KEY,
    evidence_type TEXT NOT NULL,
    content_sha256 TEXT NOT NULL,
    data_class TEXT NOT NULL,
    evidence_fingerprint TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    inserted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_forensic_evidence_type ON forensic_evidence(evidence_type);
CREATE TABLE IF NOT EXISTS forensic_case_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id TEXT NOT NULL,
    case_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    authorization_fingerprint TEXT NOT NULL,
    case_json TEXT NOT NULL,
    inserted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(case_id, case_fingerprint)
);
CREATE INDEX IF NOT EXISTS idx_forensic_case_snapshots_case ON forensic_case_snapshots(case_id, id);
CREATE TABLE IF NOT EXISTS forensic_custody_events (
    case_id TEXT NOT NULL,
    event_index INTEGER NOT NULL,
    evidence_id TEXT NOT NULL,
    action TEXT NOT NULL,
    previous_event_sha256 TEXT,
    record_sha256 TEXT NOT NULL,
    event_json TEXT NOT NULL,
    inserted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY(case_id, event_index),
    UNIQUE(case_id, record_sha256)
);
CREATE INDEX IF NOT EXISTS idx_forensic_custody_evidence ON forensic_custody_events(evidence_id, case_id);
"""


@dataclass(frozen=True)
class ForensicStoreReceipt:
    operation: str
    object_ref: str
    object_fingerprint: str
    idempotent: bool
    schema_version: str = FORENSIC_STORE_RECEIPT_SCHEMA

    def validate(self) -> "ForensicStoreReceipt":
        if self.operation not in {"put_evidence", "put_case_snapshot", "append_custody"}:
            raise MonitoringContractError("unsupported forensic store operation")
        if not self.object_ref:
            raise MonitoringContractError("forensic store receipt object_ref is required")
        if not self.object_fingerprint.startswith("sha256:") or len(self.object_fingerprint) != 71:
            raise MonitoringContractError("forensic store receipt fingerprint is invalid")
        if self.schema_version != FORENSIC_STORE_RECEIPT_SCHEMA:
            raise MonitoringContractError("unsupported forensic store receipt schema")
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(
            {
                "schema_version": self.schema_version,
                "operation": self.operation,
                "object_ref": self.object_ref,
                "object_fingerprint": self.object_fingerprint,
                "idempotent": self.idempotent,
            }
        )


class ForensicMetadataStore:
    """DFIR metadata extension that reuses the existing MonitoringStore SQLite file.

    No raw evidence payload is stored here. Evidence metadata is immutable by
    evidence_id; case state is append-only snapshots; custody is append-only and
    hash chained. This class deliberately has no filesystem, network, collection,
    shell, remediation or model authority.
    """

    def __init__(self, monitoring_store: MonitoringStore):
        if not isinstance(monitoring_store, MonitoringStore):
            raise MonitoringContractError("forensic store requires MonitoringStore")
        self.monitoring_store = monitoring_store

    def initialize(self) -> None:
        # Fail closed if the canonical monitoring database was not initialized.
        self.monitoring_store.schema_version()
        with self.monitoring_store.connect() as conn:
            conn.executescript(_FORENSIC_SCHEMA)
            conn.execute(
                "INSERT INTO forensic_schema_meta(key,value) VALUES('schema_version',?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (str(FORENSIC_STORE_SCHEMA_VERSION),),
            )

    def schema_version(self) -> int:
        with self.monitoring_store.connect() as conn:
            row = conn.execute(
                "SELECT value FROM forensic_schema_meta WHERE key='schema_version'"
            ).fetchone()
        if row is None:
            raise RuntimeError("forensic metadata schema is not initialized")
        return int(row["value"])

    def put_evidence(self, evidence: EvidenceObject) -> ForensicStoreReceipt:
        evidence.validate()
        payload = json.dumps(evidence.public_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        fingerprint = evidence.fingerprint
        with self.monitoring_store.connect() as conn:
            existing = conn.execute(
                "SELECT evidence_fingerprint FROM forensic_evidence WHERE evidence_id=?",
                (evidence.evidence_id,),
            ).fetchone()
            if existing is not None:
                if existing["evidence_fingerprint"] != fingerprint:
                    raise MonitoringContractError("forensic evidence_id is immutable and conflicts with stored metadata")
                return ForensicStoreReceipt(
                    operation="put_evidence",
                    object_ref=evidence.evidence_id,
                    object_fingerprint=fingerprint,
                    idempotent=True,
                ).validate()
            conn.execute(
                """
                INSERT INTO forensic_evidence(
                    evidence_id,evidence_type,content_sha256,data_class,evidence_fingerprint,evidence_json
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    evidence.evidence_id,
                    evidence.evidence_type,
                    evidence.content_sha256,
                    evidence.data_class,
                    fingerprint,
                    payload,
                ),
            )
        return ForensicStoreReceipt(
            operation="put_evidence",
            object_ref=evidence.evidence_id,
            object_fingerprint=fingerprint,
            idempotent=False,
        ).validate()

    def get_evidence(self, evidence_id: str) -> EvidenceObject | None:
        with self.monitoring_store.connect() as conn:
            row = conn.execute(
                "SELECT evidence_json,evidence_fingerprint FROM forensic_evidence WHERE evidence_id=?",
                (str(evidence_id),),
            ).fetchone()
        if row is None:
            return None
        payload = json.loads(row["evidence_json"])
        evidence = self._evidence_from_dict(payload)
        if evidence.fingerprint != row["evidence_fingerprint"]:
            raise MonitoringContractError("stored forensic evidence fingerprint mismatch")
        return evidence

    def put_case_snapshot(self, case: CaseRecord) -> ForensicStoreReceipt:
        case.validate()
        self._require_case_evidence(case.evidence_refs)
        if case.custody_head_sha256 is not None:
            head = self.custody_head(case.case_id)
            if head != case.custody_head_sha256:
                raise MonitoringContractError("case custody_head_sha256 does not match stored custody chain")
        payload = json.dumps(case.public_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        fingerprint = case.fingerprint
        with self.monitoring_store.connect() as conn:
            existing = conn.execute(
                "SELECT 1 FROM forensic_case_snapshots WHERE case_id=? AND case_fingerprint=?",
                (case.case_id, fingerprint),
            ).fetchone()
            if existing is not None:
                return ForensicStoreReceipt(
                    operation="put_case_snapshot",
                    object_ref=case.case_id,
                    object_fingerprint=fingerprint,
                    idempotent=True,
                ).validate()
            previous = conn.execute(
                "SELECT case_json FROM forensic_case_snapshots WHERE case_id=? ORDER BY id DESC LIMIT 1",
                (case.case_id,),
            ).fetchone()
            if previous is not None:
                prior = self._case_from_dict(json.loads(previous["case_json"]))
                self._validate_case_transition(prior, case)
            conn.execute(
                """
                INSERT INTO forensic_case_snapshots(
                    case_id,case_fingerprint,status,authorization_fingerprint,case_json
                ) VALUES(?,?,?,?,?)
                """,
                (
                    case.case_id,
                    fingerprint,
                    case.status,
                    case.authorization_fingerprint,
                    payload,
                ),
            )
        return ForensicStoreReceipt(
            operation="put_case_snapshot",
            object_ref=case.case_id,
            object_fingerprint=fingerprint,
            idempotent=False,
        ).validate()

    def get_latest_case(self, case_id: str) -> CaseRecord | None:
        with self.monitoring_store.connect() as conn:
            row = conn.execute(
                "SELECT case_json,case_fingerprint FROM forensic_case_snapshots WHERE case_id=? ORDER BY id DESC LIMIT 1",
                (str(case_id),),
            ).fetchone()
        if row is None:
            return None
        case = self._case_from_dict(json.loads(row["case_json"]))
        if case.fingerprint != row["case_fingerprint"]:
            raise MonitoringContractError("stored forensic case fingerprint mismatch")
        return case

    def append_custody_event(self, case_id: str, event: CustodyEvent) -> ForensicStoreReceipt:
        event.validate()
        if self.get_latest_case(case_id) is None:
            raise MonitoringContractError("custody event requires an existing forensic case")
        if self.get_evidence(event.evidence_id) is None:
            raise MonitoringContractError("custody event references unknown forensic evidence")
        with self.monitoring_store.connect() as conn:
            rows = conn.execute(
                "SELECT event_json FROM forensic_custody_events WHERE case_id=? ORDER BY event_index",
                (str(case_id),),
            ).fetchall()
            existing_events = tuple(self._custody_from_dict(json.loads(row["event_json"])) for row in rows)
            if event.event_index <= len(existing_events):
                existing = existing_events[event.event_index - 1]
                if existing.record_sha256 != event.record_sha256:
                    raise MonitoringContractError("custody event_index conflicts with existing hash-chain record")
                return ForensicStoreReceipt(
                    operation="append_custody",
                    object_ref=f"{case_id}:{event.event_index}",
                    object_fingerprint=event.record_sha256,
                    idempotent=True,
                ).validate()
            if event.event_index != len(existing_events) + 1:
                raise MonitoringContractError("custody event_index must append contiguously")
            candidate = (*existing_events, event)
            verify_custody_chain(candidate)
            conn.execute(
                """
                INSERT INTO forensic_custody_events(
                    case_id,event_index,evidence_id,action,previous_event_sha256,record_sha256,event_json
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    str(case_id),
                    event.event_index,
                    event.evidence_id,
                    event.action,
                    event.previous_event_sha256,
                    event.record_sha256,
                    json.dumps(event.public_dict(), ensure_ascii=False, sort_keys=True, separators=(",", ":")),
                ),
            )
        return ForensicStoreReceipt(
            operation="append_custody",
            object_ref=f"{case_id}:{event.event_index}",
            object_fingerprint=event.record_sha256,
            idempotent=False,
        ).validate()

    def custody_head(self, case_id: str) -> str | None:
        with self.monitoring_store.connect() as conn:
            rows = conn.execute(
                "SELECT event_json FROM forensic_custody_events WHERE case_id=? ORDER BY event_index",
                (str(case_id),),
            ).fetchall()
        if not rows:
            return None
        events = tuple(self._custody_from_dict(json.loads(row["event_json"])) for row in rows)
        return verify_custody_chain(events)

    def count(self, table: str) -> int:
        allowed = {"forensic_evidence", "forensic_case_snapshots", "forensic_custody_events"}
        if table not in allowed:
            raise ValueError("unsupported forensic table")
        with self.monitoring_store.connect() as conn:
            return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])

    def _require_case_evidence(self, refs: Iterable[EvidenceReference]) -> None:
        for ref in refs:
            ref.validate()
            stored = self.get_evidence(ref.evidence_id)
            if stored is None:
                raise MonitoringContractError("case references unknown forensic evidence")
            if stored.content_sha256 != ref.content_sha256:
                raise MonitoringContractError("case evidence reference content hash mismatch")

    @staticmethod
    def _validate_case_transition(previous: CaseRecord, current: CaseRecord) -> None:
        if previous.case_id != current.case_id:
            raise MonitoringContractError("case transition case_id mismatch")
        if previous.authorization_fingerprint != current.authorization_fingerprint:
            raise MonitoringContractError("case authorization fingerprint is immutable")
        allowed = {
            "open": {"open", "investigating", "closed"},
            "investigating": {"investigating", "closed"},
            "closed": {"closed"},
        }
        if current.status not in allowed[previous.status]:
            raise MonitoringContractError("forensic case status transition is not monotonic")
        previous_ids = {ref.evidence_id for ref in previous.evidence_refs}
        current_ids = {ref.evidence_id for ref in current.evidence_refs}
        if not previous_ids <= current_ids:
            raise MonitoringContractError("forensic case evidence set cannot shrink")
        if current.created_at != previous.created_at:
            raise MonitoringContractError("forensic case created_at is immutable")

    @staticmethod
    def _evidence_from_dict(payload: dict[str, object]) -> EvidenceObject:
        provenance_payload = payload["provenance"]
        if not isinstance(provenance_payload, dict):
            raise MonitoringContractError("stored forensic provenance must be an object")
        provenance = EvidenceProvenance(
            source_id=str(provenance_payload["source_id"]),
            source_type=str(provenance_payload["source_type"]),
            collected_at=str(provenance_payload["collected_at"]),
            producer_id=str(provenance_payload["producer_id"]),
            producer_version=str(provenance_payload["producer_version"]),
            source_content_sha256=str(provenance_payload["source_content_sha256"]),
            upstream_evidence_refs=tuple(str(value) for value in provenance_payload["upstream_evidence_refs"]),
            schema_version=str(provenance_payload["schema_version"]),
        ).validate()
        event_time_payload = payload["event_time"]
        event_time = None
        if event_time_payload is not None:
            if not isinstance(event_time_payload, dict):
                raise MonitoringContractError("stored forensic event_time must be an object")
            event_time = ForensicEventTime(
                original_timestamp=str(event_time_payload["original_timestamp"]),
                normalized_utc=str(event_time_payload["normalized_utc"]),
                source_clock_ref=str(event_time_payload["source_clock_ref"]),
                uncertainty_ms=int(event_time_payload["uncertainty_ms"]),
                schema_version=str(event_time_payload["schema_version"]),
            ).validate()
        parents = payload["parent_evidence_refs"]
        if not isinstance(parents, list):
            raise MonitoringContractError("stored parent_evidence_refs must be an array")
        return EvidenceObject(
            evidence_id=str(payload["evidence_id"]),
            evidence_type=str(payload["evidence_type"]),
            content_sha256=str(payload["content_sha256"]),
            byte_size=int(payload["byte_size"]),
            data_class=str(payload["data_class"]),
            provenance=provenance,
            event_time=event_time,
            parent_evidence_refs=tuple(str(value) for value in parents),
            derived=bool(payload["derived"]),
            immutable=bool(payload["immutable"]),
            payload_embedded=bool(payload["payload_embedded"]),
            schema_version=str(payload["schema_version"]),
        ).validate()

    @staticmethod
    def _case_from_dict(payload: dict[str, object]) -> CaseRecord:
        refs_payload = payload["evidence_refs"]
        if not isinstance(refs_payload, list):
            raise MonitoringContractError("stored case evidence_refs must be an array")
        refs = []
        for raw in refs_payload:
            if not isinstance(raw, dict):
                raise MonitoringContractError("stored case evidence reference must be an object")
            refs.append(
                EvidenceReference(
                    evidence_id=str(raw["evidence_id"]),
                    content_sha256=str(raw["content_sha256"]),
                    relation=str(raw["relation"]),
                    schema_version=str(raw["schema_version"]),
                ).validate()
            )
        return CaseRecord(
            case_id=str(payload["case_id"]),
            status=str(payload["status"]),
            created_at=str(payload["created_at"]),
            updated_at=str(payload["updated_at"]),
            authorization_fingerprint=str(payload["authorization_fingerprint"]),
            evidence_refs=tuple(refs),
            custody_head_sha256=(
                None if payload["custody_head_sha256"] is None else str(payload["custody_head_sha256"])
            ),
            timeline_fingerprint=(
                None if payload["timeline_fingerprint"] is None else str(payload["timeline_fingerprint"])
            ),
            human_review_required=bool(payload["human_review_required"]),
            authority=str(payload["authority"]),
            schema_version=str(payload["schema_version"]),
        ).validate()

    @staticmethod
    def _custody_from_dict(payload: dict[str, object]) -> CustodyEvent:
        return CustodyEvent(
            event_index=int(payload["event_index"]),
            evidence_id=str(payload["evidence_id"]),
            action=str(payload["action"]),
            actor_ref=str(payload["actor_ref"]),
            occurred_at=str(payload["occurred_at"]),
            previous_event_sha256=(
                None if payload["previous_event_sha256"] is None else str(payload["previous_event_sha256"])
            ),
            note_sha256=None if payload["note_sha256"] is None else str(payload["note_sha256"]),
            record_sha256=str(payload["record_sha256"]),
            schema_version=str(payload["schema_version"]),
        ).validate()
