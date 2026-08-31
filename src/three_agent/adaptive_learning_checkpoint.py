"""Authenticated checkpoint boundary for WorkSpace adaptive learning.

The learner-facing surface can stage candidates, but it never receives a raw
signing primitive. Checkpoints bind the recomputed local learning-store state
and are authenticated by a key held by a higher-trust process. A separate
trusted head witness prevents replay of an older but otherwise valid checkpoint
journal generation.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, TYPE_CHECKING

if TYPE_CHECKING:
    from .adaptive_learning_contract import (
        ContradictionRecord,
        KnowledgeCandidate,
        LearningValidationReceipt,
    )
    from .adaptive_learning_store import AdaptiveLearningStore

CHECKPOINT_SCHEMA = "workspace-adaptive-learning-checkpoint/v1"
WITNESS_SCHEMA = "workspace-adaptive-learning-checkpoint-witness/v1"
STATE_SCHEMA = "workspace-adaptive-learning-state/v1"
VERSIONS_SCHEMA = "workspace-adaptive-learning-versions/v1"
GENESIS_CHECKPOINT_SHA256 = "sha256:" + "0" * 64
_MAX_JOURNAL_BYTES = 16 * 1024 * 1024
_MAX_WITNESS_BYTES = 16 * 1024
_MAX_KEY_BYTES = 4096
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAC = re.compile(r"^hmac-sha256:[0-9a-f]{64}$")
_UTC = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
_MUTATIONS = {"bootstrap", "stage", "promote", "archive", "rollback", "key_rotation"}
_STATE_FIELDS = (
    "store_id",
    "store_schema",
    "ledger_schema",
    "ledger_head_sha256",
    "ledger_entry_count",
    "ledger_head_event_type",
    "ledger_head_item_id",
    "ledger_head_candidate_id",
    "version_count",
    "versions_sha256",
    "state_sha256",
)


class LearningCheckpointError(ValueError):
    """Authenticated checkpoint is missing, stale, or invalid."""


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _sha256(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode()).hexdigest()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _checked(value: Any, pattern: re.Pattern[str], field: str) -> str:
    text = (
        str(value or "").strip().lower()
        if field.endswith("sha256") or field == "mac"
        else str(value or "").strip()
    )
    if not pattern.fullmatch(text):
        raise LearningCheckpointError(f"invalid {field}")
    return text


def _id(value: Any, field: str) -> str:
    return _checked(value, _ID, field)


def _sha(value: Any, field: str) -> str:
    return _checked(value, _SHA, field)


def _decode_key(raw: bytes) -> bytes:
    if not raw or len(raw) > _MAX_KEY_BYTES:
        raise LearningCheckpointError("CHECKPOINT_KEY_INVALID")
    stripped = raw.strip()
    key = (
        bytes.fromhex(stripped.decode("ascii"))
        if re.fullmatch(rb"[0-9A-Fa-f]{64,512}", stripped) and len(stripped) % 2 == 0
        else raw
    )
    if len(key) < 32:
        raise LearningCheckpointError("CHECKPOINT_KEY_TOO_SHORT")
    return key


def _require_private_regular_file(path: Path, *, prefix: str, max_bytes: int) -> os.stat_result:
    try:
        info = path.lstat()
    except OSError as exc:
        raise LearningCheckpointError(f"{prefix}_MISSING") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
        raise LearningCheckpointError(f"{prefix}_PATH_INVALID")
    if info.st_size > max_bytes:
        raise LearningCheckpointError(f"{prefix}_TOO_LARGE")
    if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
        raise LearningCheckpointError(f"{prefix}_PERMISSIONS")
    return info


class HmacCheckpointKeyring:
    """Secret keyring for the trusted checkpoint process only."""

    def __init__(self, keys: Mapping[str, bytes], *, active_key_id: str):
        active = _id(active_key_id, "active_key_id")
        normalized: dict[str, bytes] = {}
        for raw_id, raw_key in dict(keys).items():
            key_id = _id(raw_id, "key_id")
            if not isinstance(raw_key, (bytes, bytearray)):
                raise LearningCheckpointError("CHECKPOINT_KEY_INVALID")
            key = bytes(raw_key)
            if not 32 <= len(key) <= _MAX_KEY_BYTES:
                raise LearningCheckpointError("CHECKPOINT_KEY_INVALID")
            normalized[key_id] = key
        if active not in normalized:
            raise LearningCheckpointError("CHECKPOINT_ACTIVE_KEY_MISSING")
        self.__keys = normalized
        self.__active = active

    @classmethod
    def from_files(
        cls, key_files: Mapping[str, Path], *, active_key_id: str
    ) -> "HmacCheckpointKeyring":
        if os.name != "posix":
            raise LearningCheckpointError("CHECKPOINT_KEY_FILE_PROVIDER_POSIX_ONLY")
        keys: dict[str, bytes] = {}
        for raw_id, raw_path in dict(key_files).items():
            key_id = _id(raw_id, "key_id")
            path = Path(raw_path)
            _require_private_regular_file(
                path,
                prefix=f"CHECKPOINT_KEY:{key_id}",
                max_bytes=_MAX_KEY_BYTES,
            )
            try:
                keys[key_id] = _decode_key(path.read_bytes())
            except OSError as exc:
                raise LearningCheckpointError(f"CHECKPOINT_KEY_READ_FAILED:{key_id}") from exc
        return cls(keys, active_key_id=active_key_id)

    @property
    def active_key_id(self) -> str:
        return self.__active

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.__keys))

    def _compute(self, key_id: str, payload: Mapping[str, Any]) -> str:
        key = self.__keys.get(key_id)
        if key is None:
            raise LearningCheckpointError(f"CHECKPOINT_KEY_MISSING:{key_id}")
        digest = hmac.new(
            key,
            _canonical(dict(payload)).encode(),
            hashlib.sha256,
        ).hexdigest()
        return "hmac-sha256:" + digest

    def _verify(self, key_id: str, payload: Mapping[str, Any], expected: str) -> bool:
        expected = _checked(expected, _MAC, "mac")
        return hmac.compare_digest(self._compute(key_id, payload), expected)


@dataclass(frozen=True)
class LearningCheckpoint:
    sequence: int
    store_id: str
    store_schema: str
    ledger_schema: str
    ledger_head_sha256: str
    ledger_entry_count: int
    ledger_head_event_type: str | None
    ledger_head_item_id: str | None
    ledger_head_candidate_id: str | None
    version_count: int
    versions_sha256: str
    state_sha256: str
    mutation_kind: str
    key_id: str
    created_at: str
    previous_checkpoint_sha256: str
    mac: str
    checkpoint_sha256: str
    schema_version: str = CHECKPOINT_SCHEMA

    FIELDS = {
        "schema_version",
        "sequence",
        "store_id",
        "store_schema",
        "ledger_schema",
        "ledger_head_sha256",
        "ledger_entry_count",
        "ledger_head_event_type",
        "ledger_head_item_id",
        "ledger_head_candidate_id",
        "version_count",
        "versions_sha256",
        "state_sha256",
        "mutation_kind",
        "key_id",
        "created_at",
        "previous_checkpoint_sha256",
        "mac",
        "checkpoint_sha256",
    }

    def signing_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "sequence": self.sequence,
            **{field: getattr(self, field) for field in _STATE_FIELDS},
            "mutation_kind": self.mutation_kind,
            "key_id": self.key_id,
            "created_at": self.created_at,
            "previous_checkpoint_sha256": self.previous_checkpoint_sha256,
        }

    def hash_payload(self) -> dict[str, Any]:
        return {**self.signing_payload(), "mac": self.mac}

    def to_payload(self) -> dict[str, Any]:
        return {**self.hash_payload(), "checkpoint_sha256": self.checkpoint_sha256}

    @classmethod
    def from_payload(cls, payload: Any) -> "LearningCheckpoint":
        if not isinstance(payload, dict) or set(payload) != cls.FIELDS:
            raise LearningCheckpointError("CHECKPOINT_RECORD_NON_STRICT")
        if payload.get("schema_version") != CHECKPOINT_SCHEMA:
            raise LearningCheckpointError("CHECKPOINT_SCHEMA_MISMATCH")
        if (
            not isinstance(payload.get("sequence"), int)
            or isinstance(payload.get("sequence"), bool)
            or payload["sequence"] < 1
        ):
            raise LearningCheckpointError("CHECKPOINT_SEQUENCE_INVALID")
        for field in ("ledger_entry_count", "version_count"):
            value = payload.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise LearningCheckpointError(f"CHECKPOINT_{field.upper()}_INVALID")
        _id(payload.get("store_id"), "store_id")
        _id(payload.get("key_id"), "key_id")
        if payload.get("mutation_kind") not in _MUTATIONS:
            raise LearningCheckpointError("CHECKPOINT_MUTATION_KIND_INVALID")
        for field in (
            "ledger_head_sha256",
            "versions_sha256",
            "state_sha256",
            "previous_checkpoint_sha256",
            "checkpoint_sha256",
        ):
            _sha(payload.get(field), field)
        _checked(payload.get("mac"), _MAC, "mac")
        if not _UTC.fullmatch(str(payload.get("created_at") or "")):
            raise LearningCheckpointError("invalid created_at")
        for field in (
            "ledger_head_event_type",
            "ledger_head_item_id",
            "ledger_head_candidate_id",
        ):
            if payload.get(field) is not None:
                _id(payload[field], field)
        return cls(**payload)


@dataclass(frozen=True)
class CheckpointHeadWitness:
    store_id: str
    sequence: int
    checkpoint_sha256: str
    key_id: str
    created_at: str
    mac: str
    schema_version: str = WITNESS_SCHEMA

    FIELDS = {
        "schema_version",
        "store_id",
        "sequence",
        "checkpoint_sha256",
        "key_id",
        "created_at",
        "mac",
    }

    def signing_payload(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "store_id": self.store_id,
            "sequence": self.sequence,
            "checkpoint_sha256": self.checkpoint_sha256,
            "key_id": self.key_id,
            "created_at": self.created_at,
        }

    def to_payload(self) -> dict[str, Any]:
        return {**self.signing_payload(), "mac": self.mac}

    @classmethod
    def from_payload(cls, payload: Any) -> "CheckpointHeadWitness":
        if not isinstance(payload, dict) or set(payload) != cls.FIELDS:
            raise LearningCheckpointError("CHECKPOINT_WITNESS_NON_STRICT")
        if payload.get("schema_version") != WITNESS_SCHEMA:
            raise LearningCheckpointError("CHECKPOINT_WITNESS_SCHEMA_MISMATCH")
        if (
            not isinstance(payload.get("sequence"), int)
            or isinstance(payload.get("sequence"), bool)
            or payload["sequence"] < 1
        ):
            raise LearningCheckpointError("CHECKPOINT_WITNESS_SEQUENCE_INVALID")
        _id(payload.get("store_id"), "store_id")
        _id(payload.get("key_id"), "key_id")
        _sha(payload.get("checkpoint_sha256"), "checkpoint_sha256")
        _checked(payload.get("mac"), _MAC, "mac")
        if not _UTC.fullmatch(str(payload.get("created_at") or "")):
            raise LearningCheckpointError("CHECKPOINT_WITNESS_TIME_INVALID")
        return cls(**payload)


def capture_learning_store_state(
    store: "AdaptiveLearningStore", *, store_id: str
) -> dict[str, Any]:
    """Recompute ledger + every immutable version before signing a checkpoint."""
    from .adaptive_learning_store import LEDGER_SCHEMA, STORE_SCHEMA

    stable_store_id = _id(store_id, "store_id")
    with store.connect() as conn:
        verification = store._verify_ledger_conn(conn)
        if not verification["passed"]:
            raise LearningCheckpointError(
                "LEARNING_LEDGER_INTEGRITY_FAILED:"
                + ",".join(verification["failures"][:8])
            )
        rows = conn.execute(
            """
            SELECT version_id,item_id,candidate_id,candidate_sha256,knowledge_sha256,
                   candidate_json,level,disposition,validation_receipt_sha256,created_at
            FROM learning_versions ORDER BY version_id
            """
        ).fetchall()
        versions = []
        for row in rows:
            try:
                candidate = store._candidate_from_row(row)
            except ValueError as exc:
                raise LearningCheckpointError(str(exc)) from exc
            versions.append(
                {
                    "version_id": int(row["version_id"]),
                    "item_id": str(row["item_id"]),
                    "candidate_id": str(row["candidate_id"]),
                    "candidate_sha256": str(row["candidate_sha256"]),
                    "knowledge_sha256": str(row["knowledge_sha256"]),
                    "candidate_payload_sha256": candidate.sha256,
                    "level": str(row["level"]),
                    "disposition": str(row["disposition"]),
                    "validation_receipt_sha256": (
                        None
                        if row["validation_receipt_sha256"] is None
                        else str(row["validation_receipt_sha256"])
                    ),
                    "created_at": str(row["created_at"]),
                }
            )
        latest = conn.execute(
            "SELECT event_type,item_id,candidate_id "
            "FROM learning_ledger ORDER BY seq DESC LIMIT 1"
        ).fetchone()

    state = {
        "schema_version": STATE_SCHEMA,
        "store_id": stable_store_id,
        "store_schema": STORE_SCHEMA,
        "ledger_schema": LEDGER_SCHEMA,
        "ledger_head_sha256": str(verification["head_sha256"]),
        "ledger_entry_count": int(verification["entry_count"]),
        "ledger_head_event_type": str(latest["event_type"]) if latest else None,
        "ledger_head_item_id": str(latest["item_id"]) if latest else None,
        "ledger_head_candidate_id": (
            None
            if latest is None or latest["candidate_id"] is None
            else str(latest["candidate_id"])
        ),
        "version_count": len(versions),
        "versions_sha256": _sha256(
            {"schema_version": VERSIONS_SCHEMA, "versions": versions}
        ),
    }
    return {**state, "state_sha256": _sha256(state)}


class LearningCheckpointAuthority:
    """Trusted authority that authenticates only exact current store state.

    ``journal_path`` and ``witness_path`` are separate persistence boundaries.
    Production deployment must place the witness outside the learner/learning-DB
    backup authority so replaying an older DB+journal cannot roll back freshness.
    """

    def __init__(
        self,
        journal_path: Path,
        witness_path: Path,
        keyring: HmacCheckpointKeyring,
        *,
        store_id: str,
    ):
        self.journal_path = Path(journal_path)
        self.witness_path = Path(witness_path)
        if self.journal_path.resolve(strict=False) == self.witness_path.resolve(strict=False):
            raise LearningCheckpointError("CHECKPOINT_WITNESS_MUST_BE_SEPARATE")
        self.store_id = _id(store_id, "store_id")
        self.__keyring = keyring
        self.__lock = threading.RLock()

    def _load(self) -> list[LearningCheckpoint]:
        path = self.journal_path
        if not path.exists():
            return []
        _require_private_regular_file(
            path,
            prefix="CHECKPOINT_JOURNAL",
            max_bytes=_MAX_JOURNAL_BYTES,
        )
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise LearningCheckpointError("CHECKPOINT_JOURNAL_READ_FAILED") from exc
        if not raw:
            return []
        lines = raw.splitlines()
        if any(not line.strip() for line in lines):
            raise LearningCheckpointError("CHECKPOINT_JOURNAL_INVALID")
        try:
            return [LearningCheckpoint.from_payload(json.loads(line)) for line in lines]
        except (json.JSONDecodeError, TypeError) as exc:
            raise LearningCheckpointError("CHECKPOINT_JOURNAL_INVALID") from exc

    def _load_witness(self, *, required: bool) -> CheckpointHeadWitness | None:
        path = self.witness_path
        if not path.exists():
            if required:
                raise LearningCheckpointError("CHECKPOINT_WITNESS_REQUIRED")
            return None
        _require_private_regular_file(
            path,
            prefix="CHECKPOINT_WITNESS",
            max_bytes=_MAX_WITNESS_BYTES,
        )
        try:
            raw = path.read_text(encoding="utf-8")
            payload = json.loads(raw)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise LearningCheckpointError("CHECKPOINT_WITNESS_INVALID") from exc
        witness = CheckpointHeadWitness.from_payload(payload)
        if witness.store_id != self.store_id:
            raise LearningCheckpointError("CHECKPOINT_WITNESS_STORE_ID_MISMATCH")
        if not self.__keyring._verify(
            witness.key_id,
            witness.signing_payload(),
            witness.mac,
        ):
            raise LearningCheckpointError("CHECKPOINT_WITNESS_MAC_MISMATCH")
        return witness

    def _write_witness(self, record: LearningCheckpoint) -> CheckpointHeadWitness:
        base = {
            "schema_version": WITNESS_SCHEMA,
            "store_id": self.store_id,
            "sequence": record.sequence,
            "checkpoint_sha256": record.checkpoint_sha256,
            "key_id": self.__keyring.active_key_id,
            "created_at": _now(),
        }
        witness = CheckpointHeadWitness(
            store_id=self.store_id,
            sequence=record.sequence,
            checkpoint_sha256=record.checkpoint_sha256,
            key_id=self.__keyring.active_key_id,
            created_at=base["created_at"],
            mac=self.__keyring._compute(self.__keyring.active_key_id, base),
        )
        path = self.witness_path
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_name(
            f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(temp, flags, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(_canonical(witness.to_payload()) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp, path)
            if os.name == "posix":
                path.chmod(0o600)
                try:
                    dir_fd = os.open(path.parent, os.O_RDONLY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except OSError:
                    pass
        except OSError as exc:
            try:
                temp.unlink(missing_ok=True)
            except OSError:
                pass
            raise LearningCheckpointError("CHECKPOINT_WITNESS_WRITE_FAILED") from exc
        return witness

    def _verify_journal(self) -> list[LearningCheckpoint]:
        records = self._load()
        if not records:
            if self._load_witness(required=False) is not None:
                raise LearningCheckpointError("CHECKPOINT_JOURNAL_REQUIRED")
            return []

        previous = GENESIS_CHECKPOINT_SHA256
        for sequence, record in enumerate(records, start=1):
            if record.sequence != sequence:
                raise LearningCheckpointError("CHECKPOINT_SEQUENCE_GAP")
            if record.store_id != self.store_id:
                raise LearningCheckpointError("CHECKPOINT_STORE_ID_MISMATCH")
            if record.previous_checkpoint_sha256 != previous:
                raise LearningCheckpointError("CHECKPOINT_CHAIN_MISMATCH")
            if _sha256(record.hash_payload()) != record.checkpoint_sha256:
                raise LearningCheckpointError("CHECKPOINT_HASH_MISMATCH")
            previous = record.checkpoint_sha256

        latest = records[-1]
        if not self.__keyring._verify(
            latest.key_id,
            latest.signing_payload(),
            latest.mac,
        ):
            raise LearningCheckpointError("CHECKPOINT_MAC_MISMATCH")
        witness = self._load_witness(required=True)
        assert witness is not None
        if (
            witness.sequence != latest.sequence
            or witness.checkpoint_sha256 != latest.checkpoint_sha256
            or witness.key_id != latest.key_id
        ):
            raise LearningCheckpointError("CHECKPOINT_WITNESS_HEAD_MISMATCH")
        return records

    @staticmethod
    def _matches(record: LearningCheckpoint, state: Mapping[str, Any]) -> bool:
        return all(getattr(record, field) == state[field] for field in _STATE_FIELDS)

    def _append(
        self,
        state: Mapping[str, Any],
        *,
        sequence: int,
        previous_checkpoint_sha256: str,
        mutation_kind: str,
    ) -> LearningCheckpoint:
        if mutation_kind not in _MUTATIONS:
            raise LearningCheckpointError("CHECKPOINT_MUTATION_KIND_INVALID")
        base = {
            "schema_version": CHECKPOINT_SCHEMA,
            "sequence": sequence,
            **{field: state[field] for field in _STATE_FIELDS},
            "mutation_kind": mutation_kind,
            "key_id": self.__keyring.active_key_id,
            "created_at": _now(),
            "previous_checkpoint_sha256": previous_checkpoint_sha256,
        }
        mac = self.__keyring._compute(self.__keyring.active_key_id, base)
        record = LearningCheckpoint(
            **{key: value for key, value in base.items() if key != "schema_version"},
            mac=mac,
            checkpoint_sha256=_sha256({**base, "mac": mac}),
        )
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            fd = os.open(self.journal_path, flags, 0o600)
            with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(_canonical(record.to_payload()) + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            if os.name == "posix":
                self.journal_path.chmod(0o600)
        except OSError as exc:
            raise LearningCheckpointError("CHECKPOINT_JOURNAL_WRITE_FAILED") from exc

        try:
            self._write_witness(record)
        except Exception as exc:
            raise LearningCheckpointError(
                "CHECKPOINT_WITNESS_ADVANCE_FAILED_AFTER_JOURNAL_APPEND"
            ) from exc
        return record

    def _verify_store(self, store: "AdaptiveLearningStore") -> LearningCheckpoint:
        records = self._verify_journal()
        if not records:
            raise LearningCheckpointError("CHECKPOINT_REQUIRED")
        latest = records[-1]
        state = capture_learning_store_state(store, store_id=self.store_id)
        if not self._matches(latest, state):
            raise LearningCheckpointError("CHECKPOINT_STORE_STATE_MISMATCH")
        return latest

    def bootstrap(self, store: "AdaptiveLearningStore") -> LearningCheckpoint:
        with self.__lock:
            if self._load() or self._load_witness(required=False) is not None:
                raise LearningCheckpointError("CHECKPOINT_ALREADY_BOOTSTRAPPED")
            state = capture_learning_store_state(store, store_id=self.store_id)
            record = self._append(
                state,
                sequence=1,
                previous_checkpoint_sha256=GENESIS_CHECKPOINT_SHA256,
                mutation_kind="bootstrap",
            )
            self._verify_store(store)
            return record

    def verify(self, store: "AdaptiveLearningStore") -> LearningCheckpoint:
        with self.__lock:
            return self._verify_store(store)

    def rotate_key(self, store: "AdaptiveLearningStore") -> LearningCheckpoint:
        with self.__lock:
            latest = self._verify_store(store)
            if latest.key_id == self.__keyring.active_key_id:
                return latest
            state = capture_learning_store_state(store, store_id=self.store_id)
            record = self._append(
                state,
                sequence=latest.sequence + 1,
                previous_checkpoint_sha256=latest.checkpoint_sha256,
                mutation_kind="key_rotation",
            )
            self._verify_store(store)
            return record

    def _advance(
        self,
        store: "AdaptiveLearningStore",
        *,
        before: LearningCheckpoint,
        mutation_kind: str,
        event_types: Iterable[str],
        version_delta: int,
    ) -> LearningCheckpoint:
        records = self._verify_journal()
        if not records or records[-1].checkpoint_sha256 != before.checkpoint_sha256:
            raise LearningCheckpointError("CHECKPOINT_CONCURRENT_CHANGE")
        state = capture_learning_store_state(store, store_id=self.store_id)
        if self._matches(before, state):
            return before
        if state["ledger_entry_count"] != before.ledger_entry_count + 1:
            raise LearningCheckpointError("CHECKPOINT_LEDGER_DELTA_INVALID")
        if state["version_count"] != before.version_count + version_delta:
            raise LearningCheckpointError("CHECKPOINT_VERSION_DELTA_INVALID")
        if state["ledger_head_event_type"] not in set(event_types):
            raise LearningCheckpointError("CHECKPOINT_EVENT_TYPE_INVALID")
        record = self._append(
            state,
            sequence=before.sequence + 1,
            previous_checkpoint_sha256=before.checkpoint_sha256,
            mutation_kind=mutation_kind,
        )
        self._verify_store(store)
        return record

    def _mutate(
        self,
        store: "AdaptiveLearningStore",
        *,
        mutation_kind: str,
        event_types: Iterable[str],
        version_delta: int,
        operation: Any,
    ) -> Any:
        with self.__lock:
            before = self._verify_store(store)
            result = operation()
            try:
                self._advance(
                    store,
                    before=before,
                    mutation_kind=mutation_kind,
                    event_types=event_types,
                    version_delta=version_delta,
                )
            except Exception as exc:
                raise LearningCheckpointError(
                    "CHECKPOINT_ADVANCE_FAILED_AFTER_STORE_MUTATION"
                ) from exc
            return result


class _CheckpointedCoordinator:
    def __init__(
        self,
        store: "AdaptiveLearningStore",
        authority: LearningCheckpointAuthority,
    ):
        self._store = store
        self._authority = authority
        authority.verify(store)

    def stage(self, candidate: "KnowledgeCandidate", **kwargs: Any) -> dict[str, Any]:
        return self._authority._mutate(
            self._store,
            mutation_kind="stage",
            event_types=("stage",),
            version_delta=1,
            operation=lambda: self._store.stage(candidate, **kwargs),
        )

    def promote(
        self,
        candidate_id: str,
        *,
        target_level: str,
        receipt: "LearningValidationReceipt",
        contradictions: Iterable["ContradictionRecord"] = (),
        **kwargs: Any,
    ) -> dict[str, Any]:
        return self._authority._mutate(
            self._store,
            mutation_kind="promote",
            event_types=("validate", "activate", "enterprise"),
            version_delta=1,
            operation=lambda: self._store.promote(
                candidate_id,
                target_level=target_level,
                receipt=receipt,
                contradictions=contradictions,
                **kwargs,
            ),
        )

    def archive(
        self,
        item_id: str,
        *,
        expected_current_sha256: str,
        **kwargs: Any,
    ) -> None:
        return self._authority._mutate(
            self._store,
            mutation_kind="archive",
            event_types=("archive",),
            version_delta=0,
            operation=lambda: self._store.archive(
                item_id,
                expected_current_sha256=expected_current_sha256,
                **kwargs,
            ),
        )

    def rollback(
        self,
        item_id: str,
        *,
        target_knowledge_sha256: str,
        expected_current_sha256: str | None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        return self._authority._mutate(
            self._store,
            mutation_kind="rollback",
            event_types=("rollback",),
            version_delta=0,
            operation=lambda: self._store.rollback(
                item_id,
                target_knowledge_sha256=target_knowledge_sha256,
                expected_current_sha256=expected_current_sha256,
                **kwargs,
            ),
        )


class LearningStagingGateway:
    """Learner-facing capability: checkpointed ``stage`` only."""

    def __init__(
        self,
        store: "AdaptiveLearningStore",
        authority: LearningCheckpointAuthority,
    ):
        self.__coordinator = _CheckpointedCoordinator(store, authority)

    def stage(self, candidate: "KnowledgeCandidate") -> dict[str, Any]:
        return self.__coordinator.stage(
            candidate,
            actor_id="learner:reflection",
            reason_code="CANDIDATE_STAGED",
        )


class LearningOperatorGateway:
    """Operator-only promotion, archive, rollback, verification, and rotation."""

    def __init__(
        self,
        store: "AdaptiveLearningStore",
        authority: LearningCheckpointAuthority,
    ):
        self.__store = store
        self.__authority = authority
        self.__coordinator = _CheckpointedCoordinator(store, authority)

    def verify(self) -> LearningCheckpoint:
        return self.__authority.verify(self.__store)

    def rotate_key(self) -> LearningCheckpoint:
        return self.__authority.rotate_key(self.__store)

    def promote(self, candidate_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.__coordinator.promote(candidate_id, **kwargs)

    def archive(self, item_id: str, **kwargs: Any) -> None:
        return self.__coordinator.archive(item_id, **kwargs)

    def rollback(self, item_id: str, **kwargs: Any) -> dict[str, Any]:
        return self.__coordinator.rollback(item_id, **kwargs)
