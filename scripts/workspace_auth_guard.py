#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
from contextlib import closing
from pathlib import Path

PROTECTED_COLUMNS = (
    "user_id",
    "username",
    "role",
    "enabled",
    "bootstrap_admin",
    "password_salt",
    "password_hash",
)


def read_env_file(path: Path) -> dict[str, str]:
    env = dict(os.environ)
    if not path.is_file():
        return env
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key:
            env[key] = value.strip()
    return env


def resolve_database(root: Path, env_path: Path) -> Path:
    env = read_env_file(env_path)
    config_raw = env.get("WORKSPACE_CONFIG") or env.get("THREE_AGENT_CONFIG") or "config/workspace.secure.json"
    config_path = Path(os.path.expanduser(os.path.expandvars(config_raw)))
    if not config_path.is_absolute():
        config_path = root / config_path
    config_path = config_path.resolve()
    if not config_path.is_file():
        raise FileNotFoundError(f"WorkSpace config not found: {config_path}")
    data = json.loads(config_path.read_text(encoding="utf-8"))
    db_raw = os.path.expanduser(os.path.expandvars(str(data.get("database_path", "data/tasks.db"))))
    db_path = Path(db_raw)
    if not db_path.is_absolute():
        db_path = root / db_path
    return db_path.resolve()


def credential_fingerprint(db: Path) -> str:
    uri = f"file:{db.as_posix()}?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as conn:
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='workspace_users'"
        ).fetchone()
        if table is None:
            raise RuntimeError("workspace_users table is missing")
        columns = {
            str(row[1])
            for row in conn.execute("PRAGMA table_info(workspace_users)").fetchall()
        }
        missing = [name for name in PROTECTED_COLUMNS if name not in columns]
        if missing:
            raise RuntimeError("workspace_users protected columns missing")
        rows = conn.execute(
            "SELECT user_id,username,role,enabled,bootstrap_admin,password_salt,password_hash "
            "FROM workspace_users ORDER BY user_id"
        ).fetchall()
    canonical = json.dumps(rows, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def sqlite_backup(source: Path, backup: Path) -> None:
    backup.parent.mkdir(parents=True, exist_ok=True)
    if backup.exists():
        backup.unlink()
    source_uri = f"file:{source.as_posix()}?mode=ro"
    with closing(sqlite3.connect(source_uri, uri=True)) as src:
        with closing(sqlite3.connect(backup)) as dst:
            src.backup(dst)
            dst.commit()
    os.chmod(backup, 0o600)


def atomic_restore(backup: Path, destination: Path, mode: int) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{destination.name}.restore-", dir=destination.parent)
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        shutil.copyfile(backup, tmp)
        os.chmod(tmp, mode)
        os.replace(tmp, destination)
        for suffix in ("-wal", "-shm"):
            sidecar = Path(f"{destination}{suffix}")
            try:
                sidecar.unlink()
            except FileNotFoundError:
                pass
    finally:
        try:
            tmp.unlink()
        except FileNotFoundError:
            pass


def write_state(path: Path, payload: dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, sort_keys=True, indent=2) + "\n", encoding="utf-8")
    os.chmod(path, 0o600)


def snapshot(root: Path, env_path: Path, backup: Path, state: Path) -> int:
    try:
        db = resolve_database(root, env_path)
    except FileNotFoundError:
        write_state(state, {"schema_version": 1, "applicable": False, "reason": "config_missing"})
        return 0
    if not db.is_file():
        write_state(state, {"schema_version": 1, "applicable": False, "reason": "database_missing"})
        return 0
    try:
        fingerprint = credential_fingerprint(db)
    except RuntimeError as exc:
        write_state(state, {"schema_version": 1, "applicable": False, "reason": str(exc)})
        return 0
    mode = stat.S_IMODE(db.stat().st_mode)
    sqlite_backup(db, backup)
    write_state(
        state,
        {
            "schema_version": 1,
            "applicable": True,
            "database_path": str(db),
            "database_mode": mode,
            "credential_fingerprint": fingerprint,
        },
    )
    return 0


def verify(root: Path, env_path: Path, state: Path) -> int:
    payload = json.loads(state.read_text(encoding="utf-8"))
    if not payload.get("applicable"):
        return 0
    try:
        db = resolve_database(root, env_path)
        if str(db) != str(payload.get("database_path")):
            print("CREDENTIAL_INVARIANT_DATABASE_PATH_CHANGED")
            return 20
        current = credential_fingerprint(db)
    except (FileNotFoundError, RuntimeError, sqlite3.Error, json.JSONDecodeError):
        print("CREDENTIAL_INVARIANT_UNREADABLE")
        return 21
    if current != payload.get("credential_fingerprint"):
        print("CREDENTIAL_INVARIANT_MISMATCH")
        return 22
    print("CREDENTIAL_INVARIANT_OK")
    return 0


def restore(state: Path, backup: Path) -> int:
    payload = json.loads(state.read_text(encoding="utf-8"))
    if not payload.get("applicable"):
        return 0
    destination = Path(str(payload["database_path"]))
    if not backup.is_file():
        print("CREDENTIAL_BACKUP_MISSING")
        return 30
    atomic_restore(backup, destination, int(payload.get("database_mode", 0o600)))
    try:
        restored = credential_fingerprint(destination)
    except (RuntimeError, sqlite3.Error):
        print("CREDENTIAL_RESTORE_UNREADABLE")
        return 31
    if restored != payload.get("credential_fingerprint"):
        print("CREDENTIAL_RESTORE_MISMATCH")
        return 32
    print("CREDENTIAL_RESTORE_OK")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local WorkSpace auth-state transaction guard")
    sub = parser.add_subparsers(dest="command", required=True)

    snap = sub.add_parser("snapshot")
    snap.add_argument("--root", type=Path, required=True)
    snap.add_argument("--env", type=Path, required=True)
    snap.add_argument("--backup", type=Path, required=True)
    snap.add_argument("--state", type=Path, required=True)

    check = sub.add_parser("verify")
    check.add_argument("--root", type=Path, required=True)
    check.add_argument("--env", type=Path, required=True)
    check.add_argument("--state", type=Path, required=True)

    recover = sub.add_parser("restore")
    recover.add_argument("--state", type=Path, required=True)
    recover.add_argument("--backup", type=Path, required=True)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "snapshot":
        return snapshot(args.root.resolve(), args.env.expanduser(), args.backup.expanduser(), args.state.expanduser())
    if args.command == "verify":
        return verify(args.root.resolve(), args.env.expanduser(), args.state.expanduser())
    if args.command == "restore":
        return restore(args.state.expanduser(), args.backup.expanduser())
    raise AssertionError(args.command)


if __name__ == "__main__":
    raise SystemExit(main())
