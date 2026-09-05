from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from .store import TaskStore

CONTEXT_MANIFEST_SCHEMA = "workspace-context-manifest/v1"

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_COMPACTION_MODES = frozenset({"structural", "extractive", "abstractive"})


class ContextManifestError(ValueError):
    """Context manifest state violates a deterministic runtime invariant."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise ContextManifestError("CONTEXT_MANIFEST_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _hash_text(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _compact_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ContextManifestError(f"INVALID_{field_name.upper()}")
    if not _ID_RE.fullmatch(value):
        raise ContextManifestError(f"INVALID_{field_name.upper()}")
    return value


def _single_line(value: Any, field_name: str, *, max_len: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ContextManifestError(f"INVALID_{field_name.upper()}")
    if len(value) > max_len or "\n" in value or "\r" in value:
        raise ContextManifestError(f"INVALID_{field_name.upper()}")
    return value


def _timestamp(value: Any, field_name: str) -> str:
    text = _single_line(value, field_name, max_len=64)
    normalized = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ContextManifestError(f"INVALID_{field_name.upper()}") from exc
    if parsed.tzinfo is None:
        raise ContextManifestError(f"{field_name.upper()}_MUST_BE_TIMEZONE_AWARE")
    return text


def _as_datetime(value: str) -> datetime:
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    return datetime.fromisoformat(normalized)


def _sha256(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise ContextManifestError(f"INVALID_{field_name.upper()}")
    return value


def _nonnegative_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContextManifestError(f"INVALID_{field_name.upper()}")
    return value


@dataclass(frozen=True)
class TokenBudget:
    max_input: int
    reserved_output: int
    compiled_input: int

    def validate(self) -> "TokenBudget":
        max_input = _nonnegative_int(self.max_input, "max_input")
        reserved = _nonnegative_int(self.reserved_output, "reserved_output")
        compiled = _nonnegative_int(self.compiled_input, "compiled_input")
        if max_input <= 0:
            raise ContextManifestError("MAX_INPUT_MUST_BE_POSITIVE")
        if reserved >= max_input:
            raise ContextManifestError("OUTPUT_RESERVE_EXHAUSTS_CONTEXT")
        capacity = max_input - reserved
        if compiled > capacity:
            raise ContextManifestError("CONTEXT_TOKEN_BUDGET_EXCEEDED")
        return self

    @property
    def input_capacity(self) -> int:
        self.validate()
        return self.max_input - self.reserved_output

    @property
    def utilization(self) -> float:
        capacity = self.input_capacity
        return self.compiled_input / capacity if capacity else 0.0

    def canonical_dict(self) -> dict[str, int]:
        self.validate()
        return {
            "max_input": self.max_input,
            "reserved_output": self.reserved_output,
            "compiled_input": self.compiled_input,
        }


@dataclass(frozen=True)
class ContextSectionInput:
    section_type: str
    item_count: int
    token_count: int
    source_hash: str
    source_refs: tuple[str, ...] = ()
    critical: bool = False

    def validate(self) -> "ContextSectionInput":
        _compact_id(self.section_type, "section_type")
        count = _nonnegative_int(self.item_count, "item_count")
        if count <= 0:
            raise ContextManifestError("SECTION_ITEM_COUNT_MUST_BE_POSITIVE")
        _nonnegative_int(self.token_count, "token_count")
        _sha256(self.source_hash, "source_hash")
        if not isinstance(self.source_refs, tuple):
            raise ContextManifestError("SOURCE_REFS_MUST_BE_TUPLE")
        if len(self.source_refs) > 512:
            raise ContextManifestError("SOURCE_REFS_TOO_MANY")
        for ref in self.source_refs:
            _single_line(ref, "source_ref", max_len=2048)
        if len(set(self.source_refs)) != len(self.source_refs):
            raise ContextManifestError("DUPLICATE_SOURCE_REF")
        if not isinstance(self.critical, bool):
            raise ContextManifestError("INVALID_SECTION_CRITICAL")
        return self


@dataclass(frozen=True)
class ContextManifestSection:
    section_type: str
    item_count: int
    token_count: int
    source_hash: str
    source_ref_hashes: tuple[str, ...]
    critical: bool

    def validate(self) -> "ContextManifestSection":
        _compact_id(self.section_type, "section_type")
        count = _nonnegative_int(self.item_count, "item_count")
        if count <= 0:
            raise ContextManifestError("SECTION_ITEM_COUNT_MUST_BE_POSITIVE")
        _nonnegative_int(self.token_count, "token_count")
        _sha256(self.source_hash, "source_hash")
        if not isinstance(self.source_ref_hashes, tuple):
            raise ContextManifestError("SOURCE_REF_HASHES_MUST_BE_TUPLE")
        for source_hash in self.source_ref_hashes:
            _sha256(source_hash, "source_ref_hash")
        if len(set(self.source_ref_hashes)) != len(self.source_ref_hashes):
            raise ContextManifestError("DUPLICATE_SOURCE_REF_HASH")
        if not isinstance(self.critical, bool):
            raise ContextManifestError("INVALID_SECTION_CRITICAL")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "type": self.section_type,
            "item_count": self.item_count,
            "tokens": self.token_count,
            "source_hash": self.source_hash,
            "source_ref_hashes": list(self.source_ref_hashes),
            "critical": self.critical,
        }


@dataclass(frozen=True)
class CompactionState:
    applied: bool = False
    modes: tuple[str, ...] = ()

    def validate(self) -> "CompactionState":
        if not isinstance(self.applied, bool):
            raise ContextManifestError("INVALID_COMPACTION_APPLIED")
        if not isinstance(self.modes, tuple):
            raise ContextManifestError("COMPACTION_MODES_MUST_BE_TUPLE")
        if len(set(self.modes)) != len(self.modes):
            raise ContextManifestError("DUPLICATE_COMPACTION_MODE")
        for mode in self.modes:
            if mode not in _COMPACTION_MODES:
                raise ContextManifestError("INVALID_COMPACTION_MODE")
        if self.applied and not self.modes:
            raise ContextManifestError("COMPACTION_MODE_REQUIRED")
        if not self.applied and self.modes:
            raise ContextManifestError("COMPACTION_MODE_WITHOUT_APPLICATION")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {"applied": self.applied, "mode": list(self.modes)}


@dataclass(frozen=True)
class ContextManifest:
    context_manifest_id: str
    project_id: str
    conversation_id: str
    task_id: str
    model_id: str
    token_budget: TokenBudget
    sections: tuple[ContextManifestSection, ...]
    compaction: CompactionState
    authority_fingerprint: str
    created_at: str = field(default_factory=_now)
    schema_version: str = CONTEXT_MANIFEST_SCHEMA

    def validate(self) -> "ContextManifest":
        _compact_id(self.context_manifest_id, "context_manifest_id")
        _compact_id(self.project_id, "project_id")
        _compact_id(self.conversation_id, "conversation_id")
        _compact_id(self.task_id, "task_id")
        _single_line(self.model_id, "model_id", max_len=256)
        if not isinstance(self.token_budget, TokenBudget):
            raise ContextManifestError("INVALID_TOKEN_BUDGET")
        self.token_budget.validate()
        if not isinstance(self.sections, tuple) or not self.sections:
            raise ContextManifestError("CONTEXT_SECTIONS_REQUIRED")
        for section in self.sections:
            if not isinstance(section, ContextManifestSection):
                raise ContextManifestError("INVALID_CONTEXT_SECTION")
            section.validate()
        if sum(section.token_count for section in self.sections) != self.token_budget.compiled_input:
            raise ContextManifestError("COMPILED_INPUT_TOKEN_MISMATCH")
        if not isinstance(self.compaction, CompactionState):
            raise ContextManifestError("INVALID_COMPACTION_STATE")
        self.compaction.validate()
        _sha256(self.authority_fingerprint, "authority_fingerprint")
        _timestamp(self.created_at, "created_at")
        if self.schema_version != CONTEXT_MANIFEST_SCHEMA:
            raise ContextManifestError("CONTEXT_MANIFEST_SCHEMA_VERSION_MISMATCH")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "context_manifest_id": self.context_manifest_id,
            "project_id": self.project_id,
            "conversation_id": self.conversation_id,
            "task_id": self.task_id,
            "model_id": self.model_id,
            "created_at": self.created_at,
            "token_budget": self.token_budget.canonical_dict(),
            "sections": [section.canonical_dict() for section in self.sections],
            "compaction": self.compaction.canonical_dict(),
            "authority_fingerprint": self.authority_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())


class ContextManifestBuilder:
    """Build audit-safe metadata without persisting prompt or source bodies."""

    @staticmethod
    def build(
        *,
        context_manifest_id: str,
        project_id: str,
        conversation_id: str,
        task_id: str,
        model_id: str,
        max_input: int,
        reserved_output: int,
        section_inputs: tuple[ContextSectionInput, ...],
        authority_fingerprint: str,
        compaction: CompactionState | None = None,
        created_at: str | None = None,
    ) -> ContextManifest:
        if not isinstance(section_inputs, tuple) or not section_inputs:
            raise ContextManifestError("CONTEXT_SECTION_INPUTS_REQUIRED")
        sections: list[ContextManifestSection] = []
        for section_input in section_inputs:
            if not isinstance(section_input, ContextSectionInput):
                raise ContextManifestError("INVALID_CONTEXT_SECTION_INPUT")
            section_input.validate()
            sections.append(
                ContextManifestSection(
                    section_type=section_input.section_type,
                    item_count=section_input.item_count,
                    token_count=section_input.token_count,
                    source_hash=section_input.source_hash,
                    source_ref_hashes=tuple(_hash_text(ref) for ref in section_input.source_refs),
                    critical=section_input.critical,
                )
            )
        compiled_input = sum(section.token_count for section in sections)
        manifest = ContextManifest(
            context_manifest_id=context_manifest_id,
            project_id=project_id,
            conversation_id=conversation_id,
            task_id=task_id,
            model_id=model_id,
            token_budget=TokenBudget(
                max_input=max_input,
                reserved_output=reserved_output,
                compiled_input=compiled_input,
            ),
            sections=tuple(sections),
            compaction=compaction or CompactionState(),
            authority_fingerprint=authority_fingerprint,
            created_at=created_at or _now(),
        )
        manifest.validate()
        return manifest


class ContextManifestStore:
    """Immutable, project-scoped audit metadata backed by the existing SQLite DB."""

    def __init__(self, task_store: TaskStore):
        if not isinstance(task_store, TaskStore):
            raise TypeError("task_store must be TaskStore")
        self.task_store = task_store
        self.initialize()

    def initialize(self) -> None:
        with self.task_store.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS harness_context_manifests (
                    context_manifest_id TEXT PRIMARY KEY,
                    schema_version TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    conversation_id TEXT NOT NULL,
                    task_id TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    manifest_json TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(task_id) REFERENCES tasks(task_id)
                );
                CREATE INDEX IF NOT EXISTS idx_harness_context_manifest_scope
                    ON harness_context_manifests(
                        project_id, conversation_id, task_id, created_at
                    );

                CREATE TRIGGER IF NOT EXISTS harness_context_manifests_no_update
                BEFORE UPDATE ON harness_context_manifests
                BEGIN
                    SELECT RAISE(ABORT, 'harness context manifests are immutable');
                END;
                CREATE TRIGGER IF NOT EXISTS harness_context_manifests_no_delete
                BEFORE DELETE ON harness_context_manifests
                BEGIN
                    SELECT RAISE(ABORT, 'harness context manifests are immutable');
                END;
                """
            )

    def _assert_task_exists(self, task_id: str) -> None:
        try:
            self.task_store.get_task(task_id)
        except KeyError as exc:
            raise ContextManifestError("CONTEXT_MANIFEST_TASK_SCOPE_UNKNOWN") from exc

    @staticmethod
    def _from_row(row: sqlite3.Row) -> ContextManifest:
        try:
            payload = json.loads(str(row["manifest_json"]))
        except (json.JSONDecodeError, TypeError) as exc:
            raise ContextManifestError("CONTEXT_MANIFEST_INTEGRITY_FAILED:JSON_INVALID") from exc
        if not isinstance(payload, dict):
            raise ContextManifestError("CONTEXT_MANIFEST_INTEGRITY_FAILED:NOT_OBJECT")

        def text(obj: dict[str, Any], key: str) -> str:
            value = obj.get(key)
            if not isinstance(value, str):
                raise ContextManifestError("CONTEXT_MANIFEST_INTEGRITY_FAILED:SHAPE_INVALID")
            return value

        token_payload = payload.get("token_budget")
        compaction_payload = payload.get("compaction")
        section_payloads = payload.get("sections")
        if (
            not isinstance(token_payload, dict)
            or not isinstance(compaction_payload, dict)
            or not isinstance(section_payloads, list)
        ):
            raise ContextManifestError("CONTEXT_MANIFEST_INTEGRITY_FAILED:SHAPE_INVALID")

        try:
            token_budget = TokenBudget(
                max_input=token_payload["max_input"],
                reserved_output=token_payload["reserved_output"],
                compiled_input=token_payload["compiled_input"],
            )
            modes = compaction_payload["mode"]
            if not isinstance(modes, list) or any(not isinstance(mode, str) for mode in modes):
                raise ContextManifestError("CONTEXT_MANIFEST_INTEGRITY_FAILED:SHAPE_INVALID")
            compaction = CompactionState(
                applied=compaction_payload["applied"],
                modes=tuple(modes),
            )
            sections: list[ContextManifestSection] = []
            for section_payload in section_payloads:
                if not isinstance(section_payload, dict):
                    raise ContextManifestError("CONTEXT_MANIFEST_INTEGRITY_FAILED:SHAPE_INVALID")
                ref_hashes = section_payload.get("source_ref_hashes")
                if not isinstance(ref_hashes, list) or any(
                    not isinstance(ref_hash, str) for ref_hash in ref_hashes
                ):
                    raise ContextManifestError("CONTEXT_MANIFEST_INTEGRITY_FAILED:SHAPE_INVALID")
                sections.append(
                    ContextManifestSection(
                        section_type=text(section_payload, "type"),
                        item_count=section_payload["item_count"],
                        token_count=section_payload["tokens"],
                        source_hash=text(section_payload, "source_hash"),
                        source_ref_hashes=tuple(ref_hashes),
                        critical=section_payload["critical"],
                    )
                )
            manifest = ContextManifest(
                context_manifest_id=text(payload, "context_manifest_id"),
                project_id=text(payload, "project_id"),
                conversation_id=text(payload, "conversation_id"),
                task_id=text(payload, "task_id"),
                model_id=text(payload, "model_id"),
                token_budget=token_budget,
                sections=tuple(sections),
                compaction=compaction,
                authority_fingerprint=text(payload, "authority_fingerprint"),
                created_at=text(payload, "created_at"),
                schema_version=text(payload, "schema_version"),
            )
        except (KeyError, TypeError) as exc:
            raise ContextManifestError("CONTEXT_MANIFEST_INTEGRITY_FAILED:SHAPE_INVALID") from exc

        try:
            manifest.validate()
        except ContextManifestError as exc:
            raise ContextManifestError("CONTEXT_MANIFEST_INTEGRITY_FAILED:RECORD_INVALID") from exc
        if (
            manifest.context_manifest_id != str(row["context_manifest_id"])
            or manifest.project_id != str(row["project_id"])
            or manifest.conversation_id != str(row["conversation_id"])
            or manifest.task_id != str(row["task_id"])
            or manifest.model_id != str(row["model_id"])
            or manifest.schema_version != str(row["schema_version"])
            or manifest.created_at != str(row["created_at"])
        ):
            raise ContextManifestError("CONTEXT_MANIFEST_INTEGRITY_FAILED:SCOPE_MISMATCH")
        if manifest.fingerprint != str(row["manifest_sha256"]):
            raise ContextManifestError("CONTEXT_MANIFEST_INTEGRITY_FAILED:SHA256_MISMATCH")
        return manifest

    def save(self, manifest: ContextManifest) -> str:
        manifest.validate()
        if _as_datetime(manifest.created_at) > datetime.now(timezone.utc) + timedelta(minutes=5):
            raise ContextManifestError("CONTEXT_MANIFEST_CREATED_AT_IN_FUTURE")
        self._assert_task_exists(manifest.task_id)
        payload = manifest.canonical_dict()
        fingerprint = manifest.fingerprint
        with self.task_store.connect() as conn:
            existing = conn.execute(
                "SELECT * FROM harness_context_manifests WHERE context_manifest_id = ?",
                (manifest.context_manifest_id,),
            ).fetchone()
            if existing is not None:
                stored = self._from_row(existing)
                if stored.fingerprint != fingerprint:
                    raise ContextManifestError("CONTEXT_MANIFEST_ID_CONFLICT")
                return fingerprint
            conn.execute(
                """
                INSERT INTO harness_context_manifests(
                    context_manifest_id,schema_version,project_id,conversation_id,
                    task_id,model_id,manifest_json,manifest_sha256,created_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    manifest.context_manifest_id,
                    manifest.schema_version,
                    manifest.project_id,
                    manifest.conversation_id,
                    manifest.task_id,
                    manifest.model_id,
                    _canonical_json(payload),
                    fingerprint,
                    manifest.created_at,
                ),
            )
        return fingerprint

    def get(self, *, context_manifest_id: str, project_id: str) -> ContextManifest:
        manifest_id = _compact_id(context_manifest_id, "context_manifest_id")
        project = _compact_id(project_id, "project_id")
        with self.task_store.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM harness_context_manifests
                WHERE context_manifest_id = ? AND project_id = ?
                """,
                (manifest_id, project),
            ).fetchone()
        if row is None:
            raise KeyError(f"Unknown context manifest in project {project}: {manifest_id}")
        return self._from_row(row)

    def list_manifests(
        self,
        *,
        project_id: str,
        conversation_id: str | None = None,
        task_id: str | None = None,
    ) -> tuple[ContextManifest, ...]:
        project = _compact_id(project_id, "project_id")
        clauses = ["project_id = ?"]
        params: list[str] = [project]
        if conversation_id is not None:
            clauses.append("conversation_id = ?")
            params.append(_compact_id(conversation_id, "conversation_id"))
        if task_id is not None:
            clauses.append("task_id = ?")
            params.append(_compact_id(task_id, "task_id"))
        query = (
            "SELECT * FROM harness_context_manifests WHERE "
            + " AND ".join(clauses)
            + " ORDER BY created_at, context_manifest_id"
        )
        with self.task_store.connect() as conn:
            rows = conn.execute(query, tuple(params)).fetchall()
        return tuple(self._from_row(row) for row in rows)
