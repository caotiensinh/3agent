from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from typing import Any, Iterable

from .runtime_execution_plan import ExecutionObservation
from .runtime_plan_compiler import CompiledRuntimePlan
from .store import TZ, TaskStore

RUNTIME_OBSERVATION_LEDGER_SCHEMA = "workspace-runtime-observation-ledger/v1"
_GENESIS_SHA256 = "sha256:" + ("0" * 64)
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_OBS_RE = re.compile(r"^obs:[0-9a-f]{32}$")
_REASON_RE = re.compile(r"^[A-Z0-9][A-Z0-9_.:-]{0,127}$")
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_STATUSES = {"succeeded", "failed", "denied", "skipped"}


class RuntimeObservationLedgerError(RuntimeError):
    pass


def _canonical(payload: Any) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _sha(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _observation_identity(payload: dict[str, Any]) -> dict[str, Any]:
    return {
        "task_id": payload["task_id"],
        "plan_id": payload["plan_id"],
        "plan_fingerprint": payload["plan_fingerprint"],
        "node_id": payload["node_id"],
        "capability": payload["capability"],
        "status": payload["status"],
        "reason_code": payload["reason_code"],
        "result_sha256": payload["result_sha256"],
        "evidence_refs": payload["evidence_refs"],
        "authority_fingerprint": payload["authority_fingerprint"],
    }


def _record_digest(
    *,
    task_id: str,
    plan_id: str,
    observation_id: str,
    observation_sha256: str,
    previous_record_sha256: str,
) -> str:
    return _sha(
        {
            "task_id": task_id,
            "plan_id": plan_id,
            "observation_id": observation_id,
            "observation_sha256": observation_sha256,
            "previous_record_sha256": previous_record_sha256,
        }
    )


class RuntimeObservationLedger:
    """Durable metadata-only execution observation ledger backed by TaskStore SQLite.

    The hash chain detects accidental corruption, gaps, reordering and partial
    record tampering. It is not a cryptographic authenticity boundary against an
    attacker who can rewrite the entire SQLite database and recompute hashes.
    Production deployments needing that property must anchor/sign the chain in a
    separate trust domain.
    """

    durable = True

    def __init__(self, store: TaskStore):
        self.store = store
        self._initialize()

    def _initialize(self) -> None:
        with self.store.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runtime_observations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    plan_id TEXT NOT NULL,
                    observation_id TEXT NOT NULL UNIQUE,
                    node_id TEXT NOT NULL,
                    observation_json TEXT NOT NULL,
                    observation_sha256 TEXT NOT NULL,
                    previous_record_sha256 TEXT NOT NULL,
                    record_sha256 TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_runtime_observations_plan
                    ON runtime_observations(task_id, plan_id, id);
                CREATE UNIQUE INDEX IF NOT EXISTS idx_runtime_observations_record_sha
                    ON runtime_observations(record_sha256);
                """
            )

    @staticmethod
    def _validate_metadata(payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise RuntimeObservationLedgerError("OBSERVATION_METADATA_INVALID")
        required = {
            "schema_version",
            "observation_id",
            "task_id",
            "plan_id",
            "plan_fingerprint",
            "node_id",
            "capability",
            "status",
            "reason_code",
            "result_sha256",
            "evidence_refs",
            "authority_fingerprint",
        }
        if set(payload) != required:
            raise RuntimeObservationLedgerError("OBSERVATION_METADATA_SHAPE_INVALID")
        if payload["schema_version"] != "workspace-runtime-observation/v1":
            raise RuntimeObservationLedgerError("OBSERVATION_SCHEMA_UNSUPPORTED")
        if not _OBS_RE.fullmatch(str(payload["observation_id"])):
            raise RuntimeObservationLedgerError("OBSERVATION_ID_INVALID")
        for field in ("plan_fingerprint", "result_sha256", "authority_fingerprint"):
            if not _SHA_RE.fullmatch(str(payload[field])):
                raise RuntimeObservationLedgerError(f"OBSERVATION_{field.upper()}_INVALID")
        if str(payload["status"]) not in _STATUSES:
            raise RuntimeObservationLedgerError("OBSERVATION_STATUS_INVALID")
        if not _REASON_RE.fullmatch(str(payload["reason_code"])):
            raise RuntimeObservationLedgerError("OBSERVATION_REASON_INVALID")
        refs = payload["evidence_refs"]
        if not isinstance(refs, list) or len(refs) > 32:
            raise RuntimeObservationLedgerError("OBSERVATION_EVIDENCE_REFS_INVALID")
        if any(
            not isinstance(ref, str)
            or not _COMPACT_RE.fullmatch(ref)
            or "://" in ref
            for ref in refs
        ):
            raise RuntimeObservationLedgerError("OBSERVATION_EVIDENCE_REF_INVALID")
        if len(refs) != len(set(refs)):
            raise RuntimeObservationLedgerError("OBSERVATION_EVIDENCE_REF_DUPLICATE")
        expected = "obs:" + _sha(_observation_identity(payload)).split(":", 1)[1][:32]
        if payload["observation_id"] != expected:
            raise RuntimeObservationLedgerError("OBSERVATION_ID_INTEGRITY_MISMATCH")
        return payload

    @classmethod
    def _validate_bound(
        cls,
        *,
        compiled_plan: CompiledRuntimePlan,
        observation: ExecutionObservation,
    ) -> dict[str, Any]:
        payload = cls._validate_metadata(observation.metadata())
        plan = compiled_plan.plan
        if payload["task_id"] != plan.task_id:
            raise RuntimeObservationLedgerError("OBSERVATION_TASK_MISMATCH")
        if payload["plan_id"] != plan.plan_id:
            raise RuntimeObservationLedgerError("OBSERVATION_PLAN_MISMATCH")
        if payload["plan_fingerprint"] != plan.fingerprint:
            raise RuntimeObservationLedgerError("OBSERVATION_PLAN_FINGERPRINT_MISMATCH")
        if payload["authority_fingerprint"] != plan.authority_fingerprint:
            raise RuntimeObservationLedgerError("OBSERVATION_AUTHORITY_MISMATCH")
        by_id = {node.node_id: node for node in plan.nodes}
        node = by_id.get(str(payload["node_id"]))
        if node is None:
            raise RuntimeObservationLedgerError("OBSERVATION_NODE_NOT_IN_PLAN")
        if payload["capability"] != node.capability:
            raise RuntimeObservationLedgerError("OBSERVATION_CAPABILITY_MISMATCH")
        return payload

    def record_many(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        observations: Iterable[ExecutionObservation],
    ) -> tuple[int, ...]:
        plan = compiled_plan.plan
        self.store.get_task(plan.task_id)
        if self.store.task_contract_record(plan.task_id) is None:
            raise RuntimeObservationLedgerError("OBSERVATION_TASK_CONTRACT_NOT_BOUND")
        payloads = [
            self._validate_bound(compiled_plan=compiled_plan, observation=observation)
            for observation in observations
        ]
        if not payloads:
            return ()
        ids: list[int] = []
        with self.store.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                """
                SELECT record_sha256 FROM runtime_observations
                WHERE task_id = ? AND plan_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (plan.task_id, plan.plan_id),
            ).fetchone()
            previous = str(row["record_sha256"]) if row is not None else _GENESIS_SHA256
            for payload in payloads:
                text = _canonical(payload)
                observation_sha = _sha(payload)
                existing = conn.execute(
                    "SELECT * FROM runtime_observations WHERE observation_id = ?",
                    (payload["observation_id"],),
                ).fetchone()
                if existing is not None:
                    if (
                        str(existing["task_id"]) != plan.task_id
                        or str(existing["plan_id"]) != plan.plan_id
                        or str(existing["observation_sha256"]) != observation_sha
                        or str(existing["observation_json"]) != text
                    ):
                        raise RuntimeObservationLedgerError(
                            "OBSERVATION_IMMUTABLE_MISMATCH"
                        )
                    ids.append(int(existing["id"]))
                    continue
                record_sha = _record_digest(
                    task_id=plan.task_id,
                    plan_id=plan.plan_id,
                    observation_id=str(payload["observation_id"]),
                    observation_sha256=observation_sha,
                    previous_record_sha256=previous,
                )
                cursor = conn.execute(
                    """
                    INSERT INTO runtime_observations(
                        timestamp,task_id,plan_id,observation_id,node_id,
                        observation_json,observation_sha256,
                        previous_record_sha256,record_sha256
                    ) VALUES(?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        datetime.now(TZ).isoformat(),
                        plan.task_id,
                        plan.plan_id,
                        payload["observation_id"],
                        payload["node_id"],
                        text,
                        observation_sha,
                        previous,
                        record_sha,
                    ),
                )
                ids.append(int(cursor.lastrowid))
                previous = record_sha
        self.store.record_activity(
            plan.task_id,
            "runtime_observation_ledger",
            "runtime_observations_recorded",
            "ok",
            f"plan={plan.plan_id} count={len(payloads)} head={previous}",
        )
        return tuple(ids)

    def records_for_plan(self, task_id: str, plan_id: str) -> list[dict[str, Any]]:
        self.store.get_task(task_id)
        with self.store.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM runtime_observations
                WHERE task_id = ? AND plan_id = ? ORDER BY id
                """,
                (task_id, plan_id),
            ).fetchall()
        records: list[dict[str, Any]] = []
        for row in rows:
            try:
                observation = json.loads(str(row["observation_json"]))
            except json.JSONDecodeError as exc:
                raise RuntimeObservationLedgerError("OBSERVATION_JSON_CORRUPT") from exc
            records.append(
                {
                    "id": int(row["id"]),
                    "timestamp": str(row["timestamp"]),
                    "observation": observation,
                    "observation_sha256": str(row["observation_sha256"]),
                    "previous_record_sha256": str(row["previous_record_sha256"]),
                    "record_sha256": str(row["record_sha256"]),
                }
            )
        return records

    def verify_chain(self, task_id: str, plan_id: str) -> dict[str, Any]:
        previous = _GENESIS_SHA256
        records = self.records_for_plan(task_id, plan_id)
        for record in records:
            payload = self._validate_metadata(record["observation"])
            if _sha(payload) != record["observation_sha256"]:
                raise RuntimeObservationLedgerError("OBSERVATION_PAYLOAD_HASH_MISMATCH")
            if record["previous_record_sha256"] != previous:
                raise RuntimeObservationLedgerError("OBSERVATION_CHAIN_PREVIOUS_MISMATCH")
            expected = _record_digest(
                task_id=task_id,
                plan_id=plan_id,
                observation_id=str(payload["observation_id"]),
                observation_sha256=str(record["observation_sha256"]),
                previous_record_sha256=previous,
            )
            if record["record_sha256"] != expected:
                raise RuntimeObservationLedgerError("OBSERVATION_CHAIN_HASH_MISMATCH")
            previous = expected
        return {
            "schema_version": RUNTIME_OBSERVATION_LEDGER_SCHEMA,
            "task_id": task_id,
            "plan_id": plan_id,
            "record_count": len(records),
            "head_record_sha256": previous,
            "verified": True,
        }

    def evidence_refs_for_plan(self, task_id: str, plan_id: str) -> tuple[str, ...]:
        refs: list[str] = []
        for record in self.records_for_plan(task_id, plan_id):
            payload = self._validate_metadata(record["observation"])
            for ref in payload["evidence_refs"]:
                if ref not in refs:
                    refs.append(ref)
        return tuple(refs)
