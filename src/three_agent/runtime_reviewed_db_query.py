from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import re
import sqlite3
import stat
import time
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol
from urllib.parse import quote

from .capability_registry import CapabilityRegistry
from .inference_scope import current_capability_authority
from .resource_events import ResourceEventRecorder
from .runtime_capability_boundary import require_runtime_capability
from .runtime_execution_plan import ExecutionNode
from .runtime_invocation import RuntimeInvocationBundle
from .runtime_plan_compiler import CompiledRuntimePlan
from .runtime_readonly_query import RuntimeReadonlyQueryBundle, RuntimeReadonlyQueryError
from .runtime_source_authority import (
    RuntimeSourceAuthorityDenied,
    RuntimeSourceBindingBundle,
)
from .task_contract import TaskContract

RUNTIME_REVIEWED_DB_QUERY_SCHEMA = "workspace-runtime-reviewed-db-query/v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_EVIDENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_DEFAULT_MAX_ROWS = 100
_HARD_MAX_ROWS = 1000
_DEFAULT_MAX_RESULT_BYTES = 1024 * 1024
_HARD_MAX_RESULT_BYTES = 4 * 1024 * 1024
_HARD_MAX_COLUMNS = 128
_MAX_COLUMN_NAME_CHARS = 256
_MAX_SQL_CHARS = 16_384


class ReviewedDbQueryError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


class DatabaseQueryEvidenceSink(Protocol):
    """Persist bounded raw query rows and return compact evidence references."""

    def persist_db_query(
        self,
        *,
        task_id: str,
        node_id: str,
        source_class: str,
        resource_ref: str,
        query_ref: str,
        sql_sha256: str,
        parameters_sha256: str | None,
        result: bytes,
        result_sha256: str,
    ) -> tuple[str, ...]: ...


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _validate_refs(values: tuple[str, ...]) -> tuple[str, ...]:
    refs: list[str] = []
    for value in values:
        ref = str(value).strip()
        if not ref or not _EVIDENCE_RE.fullmatch(ref) or "://" in ref:
            raise ReviewedDbQueryError("DB_QUERY_EVIDENCE_REF_INVALID")
        if ref not in refs:
            refs.append(ref)
        if len(refs) > 32:
            raise ReviewedDbQueryError("DB_QUERY_EVIDENCE_REF_LIMIT_EXCEEDED")
    if not refs:
        raise ReviewedDbQueryError("DB_QUERY_EVIDENCE_REQUIRED")
    return tuple(refs)


def _safe_relative_parts(resource_ref: str) -> tuple[str, ...]:
    text = str(resource_ref or "").strip().replace("\\", "/")
    path = PurePosixPath(text)
    if not text or path.is_absolute() or not path.parts:
        raise RuntimeSourceAuthorityDenied("SOURCE_RESOURCE_PATH_INVALID")
    parts = tuple(path.parts)
    if any(part in {"", ".", ".."} for part in parts):
        raise RuntimeSourceAuthorityDenied("SOURCE_RESOURCE_PATH_ESCAPES_ROOT")
    return parts


def _resolve_regular_database(root: Path, resource_ref: str) -> tuple[Path, tuple[int, int]]:
    parts = _safe_relative_parts(resource_ref)
    current = root
    try:
        for component in parts[:-1]:
            current = current / component
            info = os.lstat(current)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise ReviewedDbQueryError("DB_QUERY_DATABASE_PATH_UNSAFE")
        target = current / parts[-1]
        info = os.lstat(target)
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise ReviewedDbQueryError("DB_QUERY_REGULAR_DATABASE_REQUIRED")
        resolved = target.resolve(strict=True)
        common = Path(os.path.commonpath((str(root), str(resolved))))
        if common != root:
            raise RuntimeSourceAuthorityDenied("SOURCE_RESOURCE_PATH_ESCAPES_ROOT")
        return resolved, (int(info.st_dev), int(info.st_ino))
    except (RuntimeSourceAuthorityDenied, ReviewedDbQueryError):
        raise
    except (OSError, ValueError) as exc:
        raise ReviewedDbQueryError("DB_QUERY_DATABASE_UNAVAILABLE") from exc


def _sqlite_readonly_uri(path: Path) -> str:
    text = path.as_posix()
    if os.name == "nt" and re.match(r"^[A-Za-z]:/", text):
        text = "/" + text
    return f"file:{quote(text, safe='/:')}?mode=ro"


def _authorizer():
    allowed = {
        sqlite3.SQLITE_SELECT,
        sqlite3.SQLITE_READ,
        sqlite3.SQLITE_FUNCTION,
    }
    recursive = getattr(sqlite3, "SQLITE_RECURSIVE", None)
    if isinstance(recursive, int):
        allowed.add(recursive)
    denied_function_names = {"load_extension", "writefile", "readfile"}
    denied: dict[str, object] = {}

    def callback(action_code, arg1, arg2, db_name, trigger_name):
        if action_code not in allowed:
            denied["action"] = action_code
            denied["arg1"] = arg1
            denied["arg2"] = arg2
            return sqlite3.SQLITE_DENY
        if action_code == sqlite3.SQLITE_FUNCTION:
            function_name = str(arg2 or arg1 or "").casefold()
            if function_name in denied_function_names:
                denied["action"] = action_code
                denied["function"] = function_name
                return sqlite3.SQLITE_DENY
        return sqlite3.SQLITE_OK

    return callback, denied


def _json_cell(value: object) -> object:
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ReviewedDbQueryError("DB_QUERY_RESULT_VALUE_INVALID")
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        raw = bytes(value)
        return {"type": "bytes", "base64": base64.b64encode(raw).decode("ascii")}
    raise ReviewedDbQueryError("DB_QUERY_RESULT_VALUE_TYPE_INVALID")


@dataclass(frozen=True)
class ReviewedDbQueryResult:
    query_ref: str
    sql_sha256: str
    parameters_sha256: str | None
    result_sha256: str
    result_bytes: int
    row_count: int
    column_count: int
    evidence_refs: tuple[str, ...]
    source_binding_fingerprint: str
    query_bundle_fingerprint: str
    schema_version: str = RUNTIME_REVIEWED_DB_QUERY_SCHEMA

    def validate(self) -> "ReviewedDbQueryResult":
        for digest in (
            self.sql_sha256,
            self.result_sha256,
            self.source_binding_fingerprint,
            self.query_bundle_fingerprint,
        ):
            if not _SHA256_RE.fullmatch(str(digest)):
                raise ReviewedDbQueryError("DB_QUERY_DIGEST_INVALID")
        if self.parameters_sha256 is not None and not _SHA256_RE.fullmatch(
            str(self.parameters_sha256)
        ):
            raise ReviewedDbQueryError("DB_QUERY_PARAMETER_DIGEST_INVALID")
        if (
            isinstance(self.result_bytes, bool)
            or not isinstance(self.result_bytes, int)
            or not 0 <= self.result_bytes <= _HARD_MAX_RESULT_BYTES
        ):
            raise ReviewedDbQueryError("DB_QUERY_RESULT_BYTES_INVALID")
        if (
            isinstance(self.row_count, bool)
            or not isinstance(self.row_count, int)
            or not 0 <= self.row_count <= _HARD_MAX_ROWS
        ):
            raise ReviewedDbQueryError("DB_QUERY_ROW_COUNT_INVALID")
        if (
            isinstance(self.column_count, bool)
            or not isinstance(self.column_count, int)
            or not 0 <= self.column_count <= _HARD_MAX_COLUMNS
        ):
            raise ReviewedDbQueryError("DB_QUERY_COLUMN_COUNT_INVALID")
        _validate_refs(tuple(self.evidence_refs))
        return self


class ReviewedReadonlyDatabaseQueryBoundary:
    """Fail-closed SQLite read boundary over immutable reviewed query semantics.

    Planner data supplies only opaque query/parameter references. Runtime-reviewed
    source authority owns the exact database root and resource path; reviewed query
    profiles own SQL and raw parameter values. Live capability authorization and
    tool-call accounting happen before database I/O. SQLite is opened in mode=ro,
    query_only is enabled, extensions are disabled, a fail-closed authorizer allows
    only SELECT/READ/FUNCTION operations, and a progress handler enforces deadline.
    Raw rows are sent only to the evidence sink; observations receive hashes/counts.
    """

    def __init__(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        invocation_bundle: RuntimeInvocationBundle,
        query_bundle: RuntimeReadonlyQueryBundle,
        source_binding_bundle: RuntimeSourceBindingBundle,
        evidence_sink: DatabaseQueryEvidenceSink,
        registry: CapabilityRegistry | None = None,
        recorder: ResourceEventRecorder | None = None,
        max_rows: int = _DEFAULT_MAX_ROWS,
        max_result_bytes: int = _DEFAULT_MAX_RESULT_BYTES,
    ):
        active_registry = registry or CapabilityRegistry.default()
        source_binding_bundle.validate(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
            registry=active_registry,
        )
        query_bundle.validate(
            compiled_plan=compiled_plan,
            invocation_bundle=invocation_bundle,
        )
        if evidence_sink is None or not callable(getattr(evidence_sink, "persist_db_query", None)):
            raise ReviewedDbQueryError("DB_QUERY_EVIDENCE_SINK_REQUIRED")
        if (
            isinstance(max_rows, bool)
            or not isinstance(max_rows, int)
            or not 1 <= max_rows <= _HARD_MAX_ROWS
        ):
            raise ReviewedDbQueryError("DB_QUERY_MAX_ROWS_INVALID")
        if (
            isinstance(max_result_bytes, bool)
            or not isinstance(max_result_bytes, int)
            or not 1024 <= max_result_bytes <= _HARD_MAX_RESULT_BYTES
        ):
            raise ReviewedDbQueryError("DB_QUERY_MAX_RESULT_BYTES_INVALID")

        query_nodes = [
            node for node in compiled_plan.plan.nodes if node.capability == "query_db_readonly"
        ]
        for node in query_nodes:
            binding = source_binding_bundle.for_node(node.node_id)
            if binding.local_root is None:
                raise ReviewedDbQueryError("DB_QUERY_TRUSTED_ROOT_REQUIRED")

        self.compiled_plan = compiled_plan
        self.task_contract = task_contract
        self.invocation_bundle = invocation_bundle
        self.query_bundle = query_bundle
        self.source_binding_bundle = source_binding_bundle
        self.evidence_sink = evidence_sink
        self.registry = active_registry
        self.recorder = recorder
        self.max_rows = max_rows
        self.max_result_bytes = max_result_bytes

    @staticmethod
    def _deadline(deadline: float) -> None:
        if time.monotonic() > deadline:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")

    def query(
        self,
        *,
        task_id: str,
        node: ExecutionNode,
        query_ref: str,
        parameters_ref: str | None,
        timeout_seconds: float,
    ) -> ReviewedDbQueryResult:
        if (
            node.capability != "query_db_readonly"
            or node.effect != "read"
            or node.resource_kind != "database"
        ):
            raise ReviewedDbQueryError("DB_QUERY_NODE_UNSUPPORTED")
        if task_id != self.task_contract.task_id:
            raise ReviewedDbQueryError("DB_QUERY_TASK_MISMATCH")
        if timeout_seconds <= 0:
            raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED")

        binding = self.source_binding_bundle.for_node(node.node_id)
        binding.validate(
            compiled_plan=self.compiled_plan,
            task_contract=self.task_contract,
            registry=self.registry,
        )
        if (
            binding.capability != node.capability
            or binding.resource_kind != node.resource_kind
            or binding.resource_ref != node.resource_ref
        ):
            raise RuntimeSourceAuthorityDenied("SOURCE_NODE_BINDING_MISMATCH")
        root = binding.local_root
        if root is None:
            raise ReviewedDbQueryError("DB_QUERY_TRUSTED_ROOT_REQUIRED")

        spec = self.invocation_bundle.for_node(node.node_id)
        if spec.capability != "query_db_readonly" or spec.operation != "query":
            raise ReviewedDbQueryError("DB_QUERY_INVOCATION_INVALID")
        args = spec.argument_map()
        if str(args.get("query_ref")) != str(query_ref):
            raise ReviewedDbQueryError("DB_QUERY_REF_MISMATCH")
        expected_parameters_ref = args.get("parameters_ref")
        if (
            None if expected_parameters_ref is None else str(expected_parameters_ref)
        ) != (None if parameters_ref is None else str(parameters_ref)):
            raise ReviewedDbQueryError("DB_QUERY_PARAMETERS_REF_MISMATCH")

        try:
            profile = self.query_bundle.profile(str(query_ref))
            parameter_set = (
                None
                if parameters_ref is None
                else self.query_bundle.parameter_set(str(parameters_ref))
            )
        except RuntimeReadonlyQueryError as exc:
            raise ReviewedDbQueryError(str(exc)) from exc
        values = {} if parameter_set is None else parameter_set.values
        if set(values) != set(profile.parameter_names):
            raise ReviewedDbQueryError("DB_QUERY_PARAMETER_KEYS_MISMATCH")

        authority = current_capability_authority()
        if authority is None:
            raise ReviewedDbQueryError("DB_QUERY_NODE_AUTHORITY_REQUIRED")
        if binding.source_class not in authority.allowed_sources:
            raise RuntimeSourceAuthorityDenied("SOURCE_CLASS_NOT_ALLOWED")
        if authority.network_scope != "deny" or authority.write_scope != "none":
            raise ReviewedDbQueryError("DB_QUERY_SCOPE_NOT_ISOLATED")

        require_runtime_capability(
            node.capability,
            task_id=task_id,
            resource_kind=node.resource_kind,
            resource_ref=node.resource_ref,
            effect=node.effect,
            recorder=self.recorder,
            actor_id="runtime_node",
            action="reviewed_db_query",
        )

        deadline = time.monotonic() + float(timeout_seconds)
        self._deadline(deadline)
        database_path, expected_identity = _resolve_regular_database(root, binding.resource_ref)
        self._deadline(deadline)
        uri = _sqlite_readonly_uri(database_path)
        connection: sqlite3.Connection | None = None
        timed_out = False
        denied_action: dict[str, object] = {}
        try:
            connection = sqlite3.connect(
                uri,
                uri=True,
                timeout=max(0.05, min(5.0, float(timeout_seconds))),
                isolation_level=None,
            )
            current = os.stat(database_path)
            if (int(current.st_dev), int(current.st_ino)) != expected_identity:
                raise ReviewedDbQueryError("DB_QUERY_DATABASE_IDENTITY_CHANGED")
            try:
                connection.enable_load_extension(False)
            except (AttributeError, sqlite3.DatabaseError):
                pass
            connection.execute("PRAGMA query_only=ON")
            row = connection.execute("PRAGMA query_only").fetchone()
            if not row or int(row[0]) != 1:
                raise ReviewedDbQueryError("DB_QUERY_QUERY_ONLY_UNAVAILABLE")
            connection.execute("PRAGMA temp_store=MEMORY")
            if hasattr(connection, "setlimit"):
                connection.setlimit(sqlite3.SQLITE_LIMIT_SQL_LENGTH, _MAX_SQL_CHARS)
                connection.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, _HARD_MAX_COLUMNS)
                connection.setlimit(
                    sqlite3.SQLITE_LIMIT_LENGTH,
                    min(self.max_result_bytes, _HARD_MAX_RESULT_BYTES),
                )

            authorizer_callback, denied_action = _authorizer()
            connection.set_authorizer(authorizer_callback)

            def progress() -> int:
                nonlocal timed_out
                if time.monotonic() > deadline:
                    timed_out = True
                    return 1
                return 0

            connection.set_progress_handler(progress, 1000)
            cursor = connection.execute(profile.sql, values)
            description = cursor.description or ()
            if len(description) > _HARD_MAX_COLUMNS:
                raise ReviewedDbQueryError("DB_QUERY_COLUMN_LIMIT_EXCEEDED")
            columns: list[str] = []
            for item in description:
                name = str(item[0] or "")
                if not name or len(name) > _MAX_COLUMN_NAME_CHARS or "\x00" in name:
                    raise ReviewedDbQueryError("DB_QUERY_COLUMN_NAME_INVALID")
                columns.append(name)

            rows: list[list[object]] = []
            estimated = 0
            while True:
                self._deadline(deadline)
                raw_row = cursor.fetchone()
                if raw_row is None:
                    break
                if len(rows) >= self.max_rows:
                    raise ReviewedDbQueryError("DB_QUERY_ROW_LIMIT_EXCEEDED")
                normalized = [_json_cell(value) for value in raw_row]
                encoded_row = json.dumps(
                    normalized,
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                ).encode("utf-8")
                estimated += len(encoded_row)
                if estimated > self.max_result_bytes:
                    raise ReviewedDbQueryError("DB_QUERY_RESULT_TOO_LARGE")
                rows.append(normalized)

            payload = {
                "schema_version": RUNTIME_REVIEWED_DB_QUERY_SCHEMA,
                "query_ref": profile.profile_id,
                "sql_sha256": profile.sql_sha256,
                "parameters_sha256": (
                    None if parameter_set is None else parameter_set.values_sha256
                ),
                "columns": columns,
                "rows": rows,
                "row_count": len(rows),
            }
            result_bytes = json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            if len(result_bytes) > self.max_result_bytes:
                raise ReviewedDbQueryError("DB_QUERY_RESULT_TOO_LARGE")
        except TimeoutError:
            raise
        except ReviewedDbQueryError:
            raise
        except sqlite3.DatabaseError as exc:
            if timed_out:
                raise TimeoutError("CAPABILITY_INVOCATION_DEADLINE_EXCEEDED") from exc
            if denied_action:
                raise ReviewedDbQueryError("DB_QUERY_SQLITE_AUTHORITY_DENIED") from exc
            raise ReviewedDbQueryError("DB_QUERY_BACKEND_FAILED") from exc
        except OSError as exc:
            raise ReviewedDbQueryError("DB_QUERY_DATABASE_UNAVAILABLE") from exc
        finally:
            if connection is not None:
                try:
                    connection.set_progress_handler(None, 0)
                except sqlite3.DatabaseError:
                    pass
                try:
                    connection.set_authorizer(None)
                except sqlite3.DatabaseError:
                    pass
                connection.close()

        self._deadline(deadline)
        result_sha = _sha256(result_bytes)
        parameters_sha = None if parameter_set is None else parameter_set.values_sha256
        refs = self.evidence_sink.persist_db_query(
            task_id=task_id,
            node_id=node.node_id,
            source_class=binding.source_class,
            resource_ref=binding.resource_ref,
            query_ref=profile.profile_id,
            sql_sha256=profile.sql_sha256,
            parameters_sha256=parameters_sha,
            result=result_bytes,
            result_sha256=result_sha,
        )
        return ReviewedDbQueryResult(
            query_ref=profile.profile_id,
            sql_sha256=profile.sql_sha256,
            parameters_sha256=parameters_sha,
            result_sha256=result_sha,
            result_bytes=len(result_bytes),
            row_count=len(rows),
            column_count=len(columns),
            evidence_refs=_validate_refs(tuple(refs)),
            source_binding_fingerprint=binding.fingerprint,
            query_bundle_fingerprint=self.query_bundle.fingerprint,
        ).validate()
