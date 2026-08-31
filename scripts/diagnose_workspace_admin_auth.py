#!/usr/bin/env python3
from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import os
import sqlite3
import sys
import time
from pathlib import Path

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32


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
        raise RuntimeError(f"WorkSpace config not found: {config_path}")
    data = json.loads(config_path.read_text(encoding="utf-8"))
    db_raw = os.path.expanduser(os.path.expandvars(str(data.get("database_path", "data/tasks.db"))))
    db_path = Path(db_raw)
    if not db_path.is_absolute():
        db_path = root / db_path
    return db_path.resolve()


def matches(password: str, salt_hex: str, digest_hex: str) -> bool:
    try:
        actual = hashlib.scrypt(
            password.encode("utf-8"),
            salt=bytes.fromhex(salt_hex),
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
        )
        expected = bytes.fromhex(digest_hex)
    except (TypeError, ValueError):
        return False
    return hmac.compare_digest(actual, expected)


def main() -> int:
    root = Path(os.environ.get("THREE_AGENT_ROOT", str(Path.home() / "3agent"))).expanduser().resolve()
    env_path = Path(os.environ.get("WORKSPACE_CHAT_ENV", str(Path.home() / ".config/3agent/chat.env"))).expanduser()
    db = resolve_database(root, env_path)

    print("===== WorkSpace Admin Auth Diagnostic =====")
    print(f"database_exists: {'YES' if db.is_file() else 'NO'}")
    if not db.is_file():
        print("result: DATABASE_MISSING")
        return 2

    uri = f"file:{db.as_posix()}?mode=ro"
    with sqlite3.connect(uri, uri=True) as conn:
        conn.row_factory = sqlite3.Row
        table = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='workspace_users'"
        ).fetchone()
        if table is None:
            print("workspace_users_table: NO")
            print("result: AUTH_DATABASE_NOT_BOOTSTRAPPED")
            return 3
        row = conn.execute(
            """
            SELECT username,role,enabled,bootstrap_admin,failed_attempts,locked_until,
                   password_salt,password_hash
            FROM workspace_users
            WHERE role='admin'
            ORDER BY bootstrap_admin DESC, created_at, user_id
            LIMIT 1
            """
        ).fetchone()
        user_count = int(conn.execute("SELECT COUNT(*) FROM workspace_users").fetchone()[0])
        admin_count = int(
            conn.execute(
                "SELECT COUNT(*) FROM workspace_users WHERE role='admin' AND enabled=1"
            ).fetchone()[0]
        )

    print("workspace_users_table: YES")
    print(f"user_count: {user_count}")
    print(f"enabled_admin_count: {admin_count}")
    if row is None:
        print("result: NO_ADMIN_ACCOUNT")
        return 4

    remaining = max(0, int(float(row["locked_until"] or 0) - time.time()))
    print(f"admin_username: {row['username']}")
    print(f"admin_enabled: {'YES' if bool(row['enabled']) else 'NO'}")
    print(f"bootstrap_admin: {'YES' if bool(row['bootstrap_admin']) else 'NO'}")
    print(f"failed_attempts: {int(row['failed_attempts'] or 0)}")
    print(f"lock_remaining_seconds: {remaining}")

    if not sys.stdin.isatty():
        print("password_check: SKIPPED_NO_TTY")
        print("result: METADATA_ONLY")
        return 0

    password = getpass.getpass("Enter the OLD admin password to verify locally (hidden): ")
    ok = matches(password, str(row["password_salt"]), str(row["password_hash"]))
    del password
    print(f"password_matches_current_db: {'YES' if ok else 'NO'}")
    if ok and remaining > 0:
        print("result: PASSWORD_CORRECT_BUT_ACCOUNT_LOCKED")
    elif ok:
        print("result: PASSWORD_STILL_CORRECT")
    else:
        print("result: PASSWORD_DOES_NOT_MATCH_CURRENT_DB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
