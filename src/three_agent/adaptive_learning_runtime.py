"""Trusted production bootstrap for Phase 4C adaptive-learning retrieval.

This module only opens an already-existing authenticated learning store for
read-only consumption. It never bootstraps, mutates, repairs, rebaselines,
rotates keys, stages, promotes, archives, or rolls back learning state.
"""
from __future__ import annotations

import os
import sqlite3
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, TYPE_CHECKING

from .adaptive_learning_checkpoint import (
    HmacCheckpointKeyring,
    LearningCheckpointAuthority,
)
from .adaptive_learning_contract import DOMAINS
from .adaptive_learning_retrieval import LearningRetrievalGateway
from .adaptive_learning_store import AdaptiveLearningStore

if TYPE_CHECKING:
    from .config import AppConfig


class AdaptiveLearningRuntimeError(ValueError):
    """Trusted runtime retrieval configuration or storage is invalid."""


class _ClosingReadOnlyConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class ReadOnlyAdaptiveLearningStore(AdaptiveLearningStore):
    """Existing Phase 3 store opened without initialization or write authority."""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        try:
            info = self.db_path.lstat()
        except OSError as exc:
            raise AdaptiveLearningRuntimeError("LEARNING_STORE_MISSING") from exc
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise AdaptiveLearningRuntimeError("LEARNING_STORE_PATH_INVALID")
        if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
            raise AdaptiveLearningRuntimeError("LEARNING_STORE_PERMISSIONS")
        try:
            resolved = self.db_path.resolve(strict=True)
        except OSError as exc:
            raise AdaptiveLearningRuntimeError("LEARNING_STORE_PATH_INVALID") from exc
        self._readonly_uri = resolved.as_uri() + "?mode=ro"

    def initialize(self) -> None:
        raise AdaptiveLearningRuntimeError("LEARNING_STORE_READ_ONLY")

    def connect(self) -> sqlite3.Connection:
        try:
            conn = sqlite3.connect(
                self._readonly_uri,
                uri=True,
                factory=_ClosingReadOnlyConnection,
            )
        except sqlite3.Error as exc:
            raise AdaptiveLearningRuntimeError("LEARNING_STORE_READ_FAILED") from exc
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn


@dataclass(frozen=True)
class RuntimeLearningBinding:
    gateway: LearningRetrievalGateway | None
    domain: str

    @property
    def enabled(self) -> bool:
        return self.gateway is not None


_ALLOWED_RUNTIME_FIELDS = {
    "enabled",
    "store_path",
    "checkpoint_journal_path",
    "trusted_head_witness_path",
    "store_id",
    "active_key_id",
    "key_files",
    "domain",
}


def _expand_path(value: Any, *, field: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise AdaptiveLearningRuntimeError(f"ADAPTIVE_RUNTIME_REQUIRED:{field}")
    return Path(os.path.expandvars(os.path.expanduser(value.strip())))


def _required_text(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AdaptiveLearningRuntimeError(f"ADAPTIVE_RUNTIME_REQUIRED:{field}")
    return value.strip()


def _runtime_config(raw: Mapping[str, Any]) -> Mapping[str, Any]:
    adaptive = raw.get("adaptive_learning")
    if adaptive is None:
        return {}
    if not isinstance(adaptive, Mapping):
        raise AdaptiveLearningRuntimeError("ADAPTIVE_LEARNING_CONFIG_INVALID")
    runtime = adaptive.get("runtime_retrieval")
    if runtime is None:
        return {}
    if not isinstance(runtime, Mapping):
        raise AdaptiveLearningRuntimeError("ADAPTIVE_RUNTIME_CONFIG_INVALID")
    unknown = set(runtime) - _ALLOWED_RUNTIME_FIELDS
    if unknown:
        raise AdaptiveLearningRuntimeError(
            "ADAPTIVE_RUNTIME_UNKNOWN_FIELDS:" + ",".join(sorted(str(x) for x in unknown))
        )
    return runtime


def build_runtime_learning_binding(config: "AppConfig") -> RuntimeLearningBinding:
    """Build the trusted read-only retrieval binding from local operator config.

    Disabled configuration is a strict no-op and does not touch adaptive-learning
    filesystem paths. Enabled configuration authenticates only an already-existing
    store/checkpoint/witness generation and fails closed on any mismatch.
    """

    runtime = _runtime_config(config.raw if isinstance(config.raw, Mapping) else {})
    if not runtime:
        return RuntimeLearningBinding(None, "analyst")

    enabled = runtime.get("enabled", False)
    if not isinstance(enabled, bool):
        raise AdaptiveLearningRuntimeError("ADAPTIVE_RUNTIME_ENABLED_MUST_BE_BOOLEAN")
    domain = str(runtime.get("domain", "analyst")).strip().lower()
    if not enabled:
        return RuntimeLearningBinding(None, domain if domain in DOMAINS else "analyst")

    if config.environment == "public-research-zone" or str(
        config.confidentiality_mode
    ).strip().lower() == "public-research":
        raise AdaptiveLearningRuntimeError("ADAPTIVE_RUNTIME_PUBLIC_RESEARCH_FORBIDDEN")
    if domain not in DOMAINS:
        raise AdaptiveLearningRuntimeError("ADAPTIVE_RUNTIME_DOMAIN_INVALID")

    store_path = _expand_path(runtime.get("store_path"), field="store_path")
    journal_path = _expand_path(
        runtime.get("checkpoint_journal_path"),
        field="checkpoint_journal_path",
    )
    witness_path = _expand_path(
        runtime.get("trusted_head_witness_path"),
        field="trusted_head_witness_path",
    )
    store_id = _required_text(runtime.get("store_id"), field="store_id")
    active_key_id = _required_text(
        runtime.get("active_key_id"), field="active_key_id"
    )
    raw_key_files = runtime.get("key_files")
    if not isinstance(raw_key_files, Mapping) or not raw_key_files:
        raise AdaptiveLearningRuntimeError("ADAPTIVE_RUNTIME_KEY_FILES_REQUIRED")
    if len(raw_key_files) > 8:
        raise AdaptiveLearningRuntimeError("ADAPTIVE_RUNTIME_TOO_MANY_KEYS")
    key_files: dict[str, Path] = {}
    for raw_key_id, raw_path in raw_key_files.items():
        key_id = _required_text(raw_key_id, field="key_id")
        key_files[key_id] = _expand_path(raw_path, field=f"key_files:{key_id}")

    # This Phase intentionally does not create the store. Requiring the exact
    # existing regular private DB before constructing the adapter prevents the
    # Phase 3 store constructor from initializing/rebaselining an empty database.
    store = ReadOnlyAdaptiveLearningStore(store_path)
    keyring = HmacCheckpointKeyring.from_files(
        key_files,
        active_key_id=active_key_id,
    )
    authority = LearningCheckpointAuthority(
        journal_path,
        witness_path,
        keyring,
        store_id=store_id,
    )
    gateway = LearningRetrievalGateway(store, authority)
    return RuntimeLearningBinding(gateway, domain)
