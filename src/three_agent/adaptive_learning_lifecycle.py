"""Explicit operator lifecycle for adaptive-learning bootstrap and verification.

Phase 4F is deliberately outside normal WorkSpace startup. It creates a fresh
local learning store only when every target is absent, reuses the existing
checkpoint authority for genesis signing, and exposes no repair/rebaseline path.
"""
from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .adaptive_learning_checkpoint import HmacCheckpointKeyring, LearningCheckpointAuthority
from .adaptive_learning_runtime import ReadOnlyAdaptiveLearningStore
from .adaptive_learning_store import AdaptiveLearningStore


BOOTSTRAP_RECEIPT_SCHEMA = "workspace-adaptive-learning-bootstrap/v1"
VERIFY_RECEIPT_SCHEMA = "workspace-adaptive-learning-bootstrap-verify/v1"
_MIN_KEY_BYTES = 32
_MAX_KEY_BYTES = 64


class AdaptiveLearningLifecycleError(ValueError):
    """Operator bootstrap/verification request is unsafe or incomplete."""


@dataclass(frozen=True)
class LearningLifecyclePaths:
    store: Path
    journal: Path
    witness: Path
    key: Path

    @classmethod
    def from_values(
        cls,
        *,
        store: str | Path,
        journal: str | Path,
        witness: str | Path,
        key: str | Path,
    ) -> "LearningLifecyclePaths":
        paths = cls(*(Path(value).expanduser() for value in (store, journal, witness, key)))
        resolved = [str(path.resolve(strict=False)) for path in paths.all()]
        if len(set(resolved)) != len(resolved):
            raise AdaptiveLearningLifecycleError("LEARNING_BOOTSTRAP_PATH_COLLISION")
        return paths

    def all(self) -> tuple[Path, Path, Path, Path]:
        return self.store, self.journal, self.witness, self.key


def _require_posix() -> None:
    if os.name != "posix":
        raise AdaptiveLearningLifecycleError("LEARNING_BOOTSTRAP_KEY_PROVIDER_POSIX_ONLY")


def _validate_identifier(value: str, *, field: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 128 or not all(ch.isalnum() or ch in "._:-" for ch in text):
        raise AdaptiveLearningLifecycleError(f"LEARNING_BOOTSTRAP_INVALID:{field}")
    if not text[0].isalnum():
        raise AdaptiveLearningLifecycleError(f"LEARNING_BOOTSTRAP_INVALID:{field}")
    return text


def _ensure_targets_absent(paths: LearningLifecyclePaths) -> None:
    for path in paths.all():
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise AdaptiveLearningLifecycleError("LEARNING_BOOTSTRAP_TARGET_CHECK_FAILED") from exc
        raise AdaptiveLearningLifecycleError("LEARNING_BOOTSTRAP_TARGET_EXISTS")


def _prepare_parent(path: Path) -> None:
    parent = path.parent
    existed = parent.exists()
    try:
        parent.mkdir(parents=True, exist_ok=True)
        info = parent.lstat()
    except OSError as exc:
        raise AdaptiveLearningLifecycleError("LEARNING_BOOTSTRAP_PARENT_INVALID") from exc
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        raise AdaptiveLearningLifecycleError("LEARNING_BOOTSTRAP_PARENT_INVALID")
    if not existed:
        try:
            parent.chmod(0o700)
        except OSError as exc:
            raise AdaptiveLearningLifecycleError("LEARNING_BOOTSTRAP_PARENT_PERMISSIONS") from exc


def _create_private_key(path: Path, *, key_bytes: int) -> None:
    if not _MIN_KEY_BYTES <= key_bytes <= _MAX_KEY_BYTES:
        raise AdaptiveLearningLifecycleError("LEARNING_BOOTSTRAP_KEY_SIZE_INVALID")
    _prepare_parent(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(secrets.token_bytes(key_bytes))
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(0o600)
    except Exception:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _cleanup_created(paths: Iterable[Path]) -> None:
    for path in reversed(tuple(paths)):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass


def _receipt(checkpoint: Any, *, schema_version: str) -> dict[str, Any]:
    return {
        "schema_version": schema_version,
        "store_id": checkpoint.store_id,
        "key_id": checkpoint.key_id,
        "checkpoint_sequence": checkpoint.sequence,
        "checkpoint_sha256": checkpoint.checkpoint_sha256,
        "state_sha256": checkpoint.state_sha256,
        "ledger_entry_count": checkpoint.ledger_entry_count,
        "version_count": checkpoint.version_count,
    }


def bootstrap_learning_store(
    *,
    store_path: str | Path,
    journal_path: str | Path,
    witness_path: str | Path,
    key_path: str | Path,
    store_id: str,
    key_id: str = "key:v1",
    key_bytes: int = 32,
) -> dict[str, Any]:
    """Create one fresh authenticated learning-store generation.

    Every target must be absent before the first mutation. Failure cleanup only
    removes target files created by this ceremony; pre-existing paths are never
    overwritten or deleted.
    """

    _require_posix()
    stable_store_id = _validate_identifier(store_id, field="store_id")
    stable_key_id = _validate_identifier(key_id, field="key_id")
    paths = LearningLifecyclePaths.from_values(
        store=store_path,
        journal=journal_path,
        witness=witness_path,
        key=key_path,
    )
    _ensure_targets_absent(paths)
    for target in paths.all():
        _prepare_parent(target)

    created: list[Path] = []
    try:
        _create_private_key(paths.key, key_bytes=key_bytes)
        created.append(paths.key)

        store = AdaptiveLearningStore(paths.store)
        created.append(paths.store)
        if os.name == "posix":
            paths.store.chmod(0o600)

        keyring = HmacCheckpointKeyring.from_files(
            {stable_key_id: paths.key},
            active_key_id=stable_key_id,
        )
        authority = LearningCheckpointAuthority(
            paths.journal,
            paths.witness,
            keyring,
            store_id=stable_store_id,
        )
        checkpoint = authority.bootstrap(store)
        created.extend([paths.journal, paths.witness])
        verified = authority.verify(store)
        if verified.checkpoint_sha256 != checkpoint.checkpoint_sha256:
            raise AdaptiveLearningLifecycleError("LEARNING_BOOTSTRAP_VERIFY_MISMATCH")
        return _receipt(verified, schema_version=BOOTSTRAP_RECEIPT_SCHEMA)
    except Exception:
        _cleanup_created(created + [paths.journal, paths.witness])
        raise


def verify_learning_store(
    *,
    store_path: str | Path,
    journal_path: str | Path,
    witness_path: str | Path,
    key_path: str | Path,
    store_id: str,
    key_id: str = "key:v1",
) -> dict[str, Any]:
    """Read-only verification of an existing authenticated generation."""

    _require_posix()
    stable_store_id = _validate_identifier(store_id, field="store_id")
    stable_key_id = _validate_identifier(key_id, field="key_id")
    paths = LearningLifecyclePaths.from_values(
        store=store_path,
        journal=journal_path,
        witness=witness_path,
        key=key_path,
    )
    store = ReadOnlyAdaptiveLearningStore(paths.store)
    keyring = HmacCheckpointKeyring.from_files(
        {stable_key_id: paths.key},
        active_key_id=stable_key_id,
    )
    authority = LearningCheckpointAuthority(
        paths.journal,
        paths.witness,
        keyring,
        store_id=stable_store_id,
    )
    checkpoint = authority.verify(store)
    return _receipt(checkpoint, schema_version=VERIFY_RECEIPT_SCHEMA)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="workspace-learning-admin")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("bootstrap", "verify"):
        command = sub.add_parser(name)
        command.add_argument("--store", required=True)
        command.add_argument("--journal", required=True)
        command.add_argument("--witness", required=True)
        command.add_argument("--key-file", required=True)
        command.add_argument("--store-id", required=True)
        command.add_argument("--key-id", default="key:v1")
    sub.choices["bootstrap"].add_argument("--key-bytes", type=int, default=32)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    common = {
        "store_path": args.store,
        "journal_path": args.journal,
        "witness_path": args.witness,
        "key_path": args.key_file,
        "store_id": args.store_id,
        "key_id": args.key_id,
    }
    if args.command == "bootstrap":
        result = bootstrap_learning_store(**common, key_bytes=args.key_bytes)
    else:
        result = verify_learning_store(**common)
    print(json.dumps(result, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
