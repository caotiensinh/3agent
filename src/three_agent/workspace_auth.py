from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

TZ = ZoneInfo("Asia/Tokyo")
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
USER_ID_RE = re.compile(r"^usr_[a-f0-9]{16}$")
VALID_ROLES = {"user", "admin"}
PASSWORD_MIN_CHARS = 16
SESSION_TTL_SECONDS = 12 * 60 * 60
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_DKLEN = 32
MAX_FAILED_ATTEMPTS = 5
LOCK_SECONDS = 5 * 60


class _ClosingConnection(sqlite3.Connection):
    def __exit__(self, exc_type, exc_value, traceback) -> bool:
        try:
            return super().__exit__(exc_type, exc_value, traceback)
        finally:
            self.close()


class WorkspaceAuthStore:
    """Local WorkSpace accounts, RBAC and IP-bound browser sessions."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, factory=_ClosingConnection)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(TZ).isoformat()

    @staticmethod
    def _username(value: str) -> str:
        value = str(value or "").strip()
        if not USERNAME_RE.fullmatch(value):
            raise ValueError(
                "Username must be 3-64 characters using letters, numbers, '.', '_' or '-'"
            )
        return value

    @staticmethod
    def _user_id(value: str) -> str:
        value = str(value or "").strip().lower()
        if not USER_ID_RE.fullmatch(value):
            raise ValueError("Invalid user_id")
        return value

    @staticmethod
    def _role(value: str) -> str:
        value = str(value or "").strip().lower()
        if value not in VALID_ROLES:
            raise ValueError("Role must be 'user' or 'admin'")
        return value

    @staticmethod
    def _password(value: str) -> str:
        value = str(value or "")
        if len(value) < PASSWORD_MIN_CHARS:
            raise ValueError(f"Password must contain at least {PASSWORD_MIN_CHARS} characters")
        if len(value) > 512:
            raise ValueError("Password is too long")
        return value

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=SCRYPT_N,
            r=SCRYPT_R,
            p=SCRYPT_P,
            dklen=SCRYPT_DKLEN,
        )

    @classmethod
    def _password_record(cls, password: str) -> tuple[str, str]:
        password = cls._password(password)
        salt = secrets.token_bytes(16)
        return salt.hex(), cls._derive(password, salt).hex()

    @classmethod
    def _matches(cls, password: str, salt_hex: str, digest_hex: str) -> bool:
        try:
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(digest_hex)
            actual = cls._derive(str(password or ""), salt)
        except (TypeError, ValueError):
            return False
        return hmac.compare_digest(actual, expected)

    @staticmethod
    def _session_hash(token: str) -> str:
        return hashlib.sha256(str(token or "").encode("utf-8")).hexdigest()

    @staticmethod
    def _ip_hash(client_ip: str) -> str:
        raw = "workspace-session-ip-v1:" + str(client_ip or "").strip()
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    @staticmethod
    def _initials(display_name: str, username: str) -> str:
        value = str(display_name or "").strip() or str(username or "").strip()
        parts = [part for part in value.split() if part]
        return ("".join(part[0].upper() for part in parts[:2]) or "W")[:2]

    def initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS workspace_users (
                    user_id TEXT PRIMARY KEY,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    display_name TEXT NOT NULL,
                    department TEXT NOT NULL DEFAULT '',
                    title TEXT NOT NULL DEFAULT '',
                    role TEXT NOT NULL CHECK(role IN ('user','admin')),
                    password_salt TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0,1)),
                    bootstrap_admin INTEGER NOT NULL DEFAULT 0 CHECK(bootstrap_admin IN (0,1)),
                    failed_attempts INTEGER NOT NULL DEFAULT 0,
                    locked_until REAL NOT NULL DEFAULT 0,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_workspace_users_role_enabled
                    ON workspace_users(role, enabled);
                CREATE TABLE IF NOT EXISTS workspace_auth_sessions (
                    session_hash TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    client_ip_hash TEXT NOT NULL,
                    created_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES workspace_users(user_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_workspace_sessions_user
                    ON workspace_auth_sessions(user_id, expires_at);
                """
            )

    def _public(self, row: sqlite3.Row) -> dict[str, Any]:
        username = str(row["username"])
        display_name = str(row["display_name"])
        return {
            "user_id": str(row["user_id"]),
            "username": username,
            "display_name": display_name,
            "department": str(row["department"]),
            "title": str(row["title"]),
            "role": str(row["role"]),
            "enabled": bool(row["enabled"]),
            "initials": self._initials(display_name, username),
        }

    def _existing_bootstrap_user(self, username: str) -> sqlite3.Row | None:
        with self.connect() as conn:
            count = int(conn.execute("SELECT COUNT(*) FROM workspace_users").fetchone()[0])
            if not count:
                return None
            row = conn.execute(
                "SELECT * FROM workspace_users WHERE username=? COLLATE NOCASE",
                (username,),
            ).fetchone()
            if row is None:
                row = conn.execute(
                    "SELECT * FROM workspace_users ORDER BY created_at,user_id LIMIT 1"
                ).fetchone()
            return row

    def bootstrap_admin(
        self,
        username: str,
        password: str,
        *,
        display_name: str = "WorkSpace Administrator",
        department: str = "",
        title: str = "Administrator",
    ) -> dict[str, Any]:
        username = self._username(username)
        existing = self._existing_bootstrap_user(username)
        if existing is not None:
            return self._public(existing)

        salt, digest = self._password_record(password)
        now = self._now()
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            count = int(conn.execute("SELECT COUNT(*) FROM workspace_users").fetchone()[0])
            if count:
                row = conn.execute(
                    "SELECT * FROM workspace_users WHERE username=? COLLATE NOCASE",
                    (username,),
                ).fetchone()
                if row is None:
                    row = conn.execute(
                        "SELECT * FROM workspace_users ORDER BY created_at,user_id LIMIT 1"
                    ).fetchone()
                if row is None:
                    raise RuntimeError("WorkSpace user table is unexpectedly empty")
                return self._public(row)
            user_id = "usr_" + uuid.uuid4().hex[:16]
            conn.execute(
                """
                INSERT INTO workspace_users(
                    user_id,username,display_name,department,title,role,
                    password_salt,password_hash,enabled,bootstrap_admin,
                    failed_attempts,locked_until,created_at,updated_at
                ) VALUES(?,?,?,?,?,'admin',?,?,1,1,0,0,?,?)
                """,
                (
                    user_id,
                    username,
                    str(display_name or "WorkSpace Administrator")[:120],
                    str(department or "")[:120],
                    str(title or "Administrator")[:120],
                    salt,
                    digest,
                    now,
                    now,
                ),
            )
            row = conn.execute(
                "SELECT * FROM workspace_users WHERE user_id=?", (user_id,)
            ).fetchone()
        if row is None:
            raise RuntimeError("Failed to create bootstrap administrator")
        return self._public(row)

    def _dummy_check(self, password: str) -> None:
        hmac.compare_digest(
            self._derive(str(password or ""), b"\0" * 16), b"\0" * SCRYPT_DKLEN
        )

    def login(
        self, username: str, password: str, client_ip: str
    ) -> tuple[str, dict[str, Any]] | None:
        try:
            username = self._username(username)
        except ValueError:
            self._dummy_check(password)
            return None
        now = time.time()
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM workspace_users WHERE username=? COLLATE NOCASE",
                (username,),
            ).fetchone()
        if (
            row is None
            or not bool(row["enabled"])
            or float(row["locked_until"] or 0) > now
        ):
            self._dummy_check(password)
            return None
        if not self._matches(
            password, str(row["password_salt"]), str(row["password_hash"])
        ):
            attempts = int(row["failed_attempts"] or 0) + 1
            locked = now + LOCK_SECONDS if attempts >= MAX_FAILED_ATTEMPTS else 0
            with self.connect() as conn:
                conn.execute(
                    "UPDATE workspace_users SET failed_attempts=?,locked_until=?,updated_at=? WHERE user_id=?",
                    (0 if locked else attempts, locked, self._now(), str(row["user_id"])),
                )
            return None
        token = secrets.token_urlsafe(32)
        expires = now + SESSION_TTL_SECONDS
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE workspace_users SET failed_attempts=0,locked_until=0,updated_at=? WHERE user_id=?",
                (self._now(), str(row["user_id"])),
            )
            conn.execute("DELETE FROM workspace_auth_sessions WHERE expires_at<?", (now,))
            conn.execute(
                "INSERT INTO workspace_auth_sessions(session_hash,user_id,client_ip_hash,created_at,expires_at) VALUES(?,?,?,?,?)",
                (
                    self._session_hash(token),
                    str(row["user_id"]),
                    self._ip_hash(client_ip),
                    now,
                    expires,
                ),
            )
            fresh = conn.execute(
                "SELECT * FROM workspace_users WHERE user_id=?", (str(row["user_id"]),)
            ).fetchone()
        return (token, self._public(fresh)) if fresh is not None else None

    def user_for_session(self, token: str, client_ip: str) -> dict[str, Any] | None:
        if not token:
            return None
        digest = self._session_hash(token)
        now = time.time()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT s.session_hash,s.client_ip_hash,s.expires_at,u.*
                FROM workspace_auth_sessions s JOIN workspace_users u ON u.user_id=s.user_id
                WHERE s.session_hash=?
                """,
                (digest,),
            ).fetchone()
            if row is None:
                return None
            valid_ip = hmac.compare_digest(
                str(row["client_ip_hash"]), self._ip_hash(client_ip)
            )
            if (
                float(row["expires_at"]) < now
                or not valid_ip
                or not bool(row["enabled"])
            ):
                conn.execute(
                    "DELETE FROM workspace_auth_sessions WHERE session_hash=?", (digest,)
                )
                return None
        return self._public(row)

    def valid(self, token: str, client_ip: str) -> bool:
        return self.user_for_session(token, client_ip) is not None

    def logout(self, token: str) -> None:
        if token:
            with self.connect() as conn:
                conn.execute(
                    "DELETE FROM workspace_auth_sessions WHERE session_hash=?",
                    (self._session_hash(token),),
                )

    def is_bootstrap_admin(self, user_id: str) -> bool:
        user_id = self._user_id(user_id)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT bootstrap_admin,role,enabled FROM workspace_users WHERE user_id=?",
                (user_id,),
            ).fetchone()
        return bool(
            row
            and row["bootstrap_admin"]
            and row["role"] == "admin"
            and row["enabled"]
        )

    def list_users(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM workspace_users ORDER BY CASE role WHEN 'admin' THEN 0 ELSE 1 END,username COLLATE NOCASE"
            ).fetchall()
        return [self._public(row) for row in rows]

    def create_user(
        self,
        *,
        username: str,
        password: str,
        display_name: str,
        department: str = "",
        title: str = "",
        role: str = "user",
    ) -> dict[str, Any]:
        username = self._username(username)
        role = self._role(role)
        salt, digest = self._password_record(password)
        user_id = "usr_" + uuid.uuid4().hex[:16]
        now = self._now()
        try:
            with self.connect() as conn:
                conn.execute(
                    """
                    INSERT INTO workspace_users(
                        user_id,username,display_name,department,title,role,
                        password_salt,password_hash,enabled,bootstrap_admin,
                        failed_attempts,locked_until,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,1,0,0,0,?,?)
                    """,
                    (
                        user_id,
                        username,
                        str(display_name or username)[:120],
                        str(department or "")[:120],
                        str(title or "")[:120],
                        role,
                        salt,
                        digest,
                        now,
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM workspace_users WHERE user_id=?", (user_id,)
                ).fetchone()
        except sqlite3.IntegrityError as exc:
            raise ValueError("Username already exists") from exc
        if row is None:
            raise RuntimeError("Failed to create WorkSpace user")
        return self._public(row)

    @staticmethod
    def _admin_count(conn: sqlite3.Connection) -> int:
        return int(
            conn.execute(
                "SELECT COUNT(*) FROM workspace_users WHERE role='admin' AND enabled=1"
            ).fetchone()[0]
        )

    def update_user(
        self,
        user_id: str,
        *,
        display_name: str | None = None,
        department: str | None = None,
        title: str | None = None,
        role: str | None = None,
        enabled: bool | None = None,
        new_password: str | None = None,
    ) -> dict[str, Any]:
        user_id = self._user_id(user_id)
        next_role = self._role(role) if role is not None else None
        password_record = self._password_record(new_password) if new_password else None
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            current = conn.execute(
                "SELECT * FROM workspace_users WHERE user_id=?", (user_id,)
            ).fetchone()
            if current is None:
                raise KeyError("User not found")
            resulting_role = next_role or str(current["role"])
            resulting_enabled = (
                bool(enabled) if enabled is not None else bool(current["enabled"])
            )
            if (
                str(current["role"]) == "admin"
                and bool(current["enabled"])
                and (resulting_role != "admin" or not resulting_enabled)
                and self._admin_count(conn) <= 1
            ):
                raise ValueError("Cannot disable or demote the last enabled administrator")
            updates: list[str] = []
            values: list[Any] = []
            for column, value in (
                ("display_name", display_name),
                ("department", department),
                ("title", title),
            ):
                if value is not None:
                    updates.append(f"{column}=?")
                    values.append(str(value)[:120])
            if next_role is not None:
                updates.append("role=?")
                values.append(next_role)
            if enabled is not None:
                updates.append("enabled=?")
                values.append(1 if enabled else 0)
            if password_record:
                updates += [
                    "password_salt=?",
                    "password_hash=?",
                    "failed_attempts=0",
                    "locked_until=0",
                ]
                values += list(password_record)
            updates.append("updated_at=?")
            values.append(self._now())
            values.append(user_id)
            conn.execute(
                f"UPDATE workspace_users SET {','.join(updates)} WHERE user_id=?",
                tuple(values),
            )
            if enabled is False or password_record:
                conn.execute(
                    "DELETE FROM workspace_auth_sessions WHERE user_id=?", (user_id,)
                )
            row = conn.execute(
                "SELECT * FROM workspace_users WHERE user_id=?", (user_id,)
            ).fetchone()
        if row is None:
            raise KeyError("User not found")
        return self._public(row)

    def change_password(
        self, user_id: str, current_password: str, new_password: str
    ) -> None:
        user_id = self._user_id(user_id)
        self._password(new_password)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM workspace_users WHERE user_id=?", (user_id,)
            ).fetchone()
        if row is None or not self._matches(
            current_password, str(row["password_salt"]), str(row["password_hash"])
        ):
            raise ValueError("Current password is incorrect")
        salt, digest = self._password_record(new_password)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                "UPDATE workspace_users SET password_salt=?,password_hash=?,failed_attempts=0,locked_until=0,updated_at=? WHERE user_id=?",
                (salt, digest, self._now(), user_id),
            )
            conn.execute(
                "DELETE FROM workspace_auth_sessions WHERE user_id=?", (user_id,)
            )
