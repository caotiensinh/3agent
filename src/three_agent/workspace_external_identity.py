from __future__ import annotations

import json
import os
import re
import secrets
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

from .workspace_auth import SESSION_TTL_SECONDS, WorkspaceAuthStore

VALID_EXTERNAL_PROVIDERS = {"google", "github", "line"}
IDENTITY_ID_RE = re.compile(r"^ext_[a-f0-9]{16}$")
EXTERNAL_KEY_RE = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class ExternalAuthSettings:
    browser_base_url: str
    providers: tuple[str, ...]
    redeem_url: str
    redeem_key: str

    @classmethod
    def from_env(cls) -> "ExternalAuthSettings":
        browser_base_url = os.getenv("WORKSPACE_EXTERNAL_AUTH_BROKER_URL", "").strip().rstrip("/")
        raw = os.getenv("WORKSPACE_EXTERNAL_AUTH_PROVIDERS", "")
        providers = tuple(
            item
            for item in (part.strip().lower() for part in raw.split(","))
            if item in VALID_EXTERNAL_PROVIDERS
        )
        redeem_url = os.getenv(
            "WORKSPACE_EXTERNAL_AUTH_REDEEM_URL", "http://127.0.0.1:8791/redeem"
        ).strip()
        redeem_key = os.getenv("WORKSPACE_EXTERNAL_AUTH_REDEEM_KEY", "")
        if providers:
            if not browser_base_url:
                raise ValueError("External auth providers require WORKSPACE_EXTERNAL_AUTH_BROKER_URL")
            parsed = urlparse(browser_base_url)
            if parsed.scheme != "https":
                raise ValueError("External auth browser URL must use HTTPS")
            redeem = urlparse(redeem_url)
            if redeem.scheme != "http" or redeem.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("External auth redemption must use loopback HTTP only")
            if len(redeem_key) < 32:
                raise ValueError("WORKSPACE_EXTERNAL_AUTH_REDEEM_KEY must contain at least 32 characters")
        return cls(browser_base_url, providers, redeem_url, redeem_key)

    @property
    def enabled(self) -> bool:
        return bool(self.providers)


class ExternalSessionAuthStore(WorkspaceAuthStore):
    """WorkspaceAuthStore extension for approved external-identity sessions."""

    def issue_session_for_user(self, user_id: str, client_ip: str) -> tuple[str, dict[str, Any]]:
        user_id = self._user_id(user_id)
        now = time.time()
        token = secrets.token_urlsafe(32)
        with self.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM workspace_users WHERE user_id=?", (user_id,)
            ).fetchone()
            if row is None or not bool(row["enabled"]):
                raise PermissionError("WorkSpace user is not enabled")
            conn.execute("DELETE FROM workspace_auth_sessions WHERE expires_at<?", (now,))
            conn.execute(
                "INSERT INTO workspace_auth_sessions(session_hash,user_id,client_ip_hash,created_at,expires_at) VALUES(?,?,?,?,?)",
                (
                    self._session_hash(token),
                    user_id,
                    self._ip_hash(client_ip),
                    now,
                    now + SESSION_TTL_SECONDS,
                ),
            )
        return token, self._public(row)


class ExternalIdentityStore:
    """Map provider identity fingerprints to operator-approved local accounts.

    The provider's raw subject/email/token is never stored here. The identity broker
    emits a stable HMAC-derived 64-hex external_key plus a display label only.
    """

    def __init__(self, auth: ExternalSessionAuthStore) -> None:
        self.auth = auth

    @staticmethod
    def _provider(value: str) -> str:
        provider = str(value or "").strip().lower()
        if provider not in VALID_EXTERNAL_PROVIDERS:
            raise ValueError("Unsupported external identity provider")
        return provider

    @staticmethod
    def _external_key(value: str) -> str:
        key = str(value or "").strip().lower()
        if not EXTERNAL_KEY_RE.fullmatch(key):
            raise ValueError("Invalid external identity key")
        return key

    @staticmethod
    def _identity_id(value: str) -> str:
        identity_id = str(value or "").strip().lower()
        if not IDENTITY_ID_RE.fullmatch(identity_id):
            raise ValueError("Invalid external identity id")
        return identity_id

    def initialize(self) -> None:
        with self.auth.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS workspace_external_identities (
                    identity_id TEXT PRIMARY KEY,
                    provider TEXT NOT NULL CHECK(provider IN ('google','github','line')),
                    external_key TEXT NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL CHECK(status IN ('pending','approved','rejected')),
                    user_id TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    last_seen_at TEXT NOT NULL,
                    UNIQUE(provider, external_key),
                    FOREIGN KEY(user_id) REFERENCES workspace_users(user_id) ON DELETE SET NULL
                );
                CREATE INDEX IF NOT EXISTS idx_workspace_external_identity_status
                ON workspace_external_identities(status, provider, updated_at DESC);
                """
            )

    @staticmethod
    def _public(row) -> dict[str, Any]:
        return {
            "identity_id": str(row["identity_id"]),
            "provider": str(row["provider"]),
            "display_name": str(row["display_name"]),
            "status": str(row["status"]),
            "user_id": str(row["user_id"] or ""),
            "created_at": str(row["created_at"]),
            "updated_at": str(row["updated_at"]),
            "last_seen_at": str(row["last_seen_at"]),
        }

    def record_assertion(self, provider: str, external_key: str, display_name: str) -> dict[str, Any]:
        provider = self._provider(provider)
        external_key = self._external_key(external_key)
        display_name = " ".join(str(display_name or "").split())[:120]
        now = self.auth._now()
        with self.auth.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT * FROM workspace_external_identities WHERE provider=? AND external_key=?",
                (provider, external_key),
            ).fetchone()
            if row is None:
                identity_id = "ext_" + uuid.uuid4().hex[:16]
                conn.execute(
                    """
                    INSERT INTO workspace_external_identities(
                        identity_id,provider,external_key,display_name,status,user_id,
                        created_at,updated_at,last_seen_at
                    ) VALUES(?,?,?,?, 'pending', NULL,?,?,?)
                    """,
                    (identity_id, provider, external_key, display_name, now, now, now),
                )
            else:
                conn.execute(
                    "UPDATE workspace_external_identities SET display_name=?,updated_at=?,last_seen_at=? WHERE identity_id=?",
                    (display_name, now, now, str(row["identity_id"])),
                )
            fresh = conn.execute(
                "SELECT * FROM workspace_external_identities WHERE provider=? AND external_key=?",
                (provider, external_key),
            ).fetchone()
        if fresh is None:
            raise RuntimeError("Failed to persist external identity assertion")
        return self._public(fresh)

    def list_identities(self) -> list[dict[str, Any]]:
        with self.auth.connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM workspace_external_identities
                ORDER BY CASE status WHEN 'pending' THEN 0 WHEN 'approved' THEN 1 ELSE 2 END,
                         updated_at DESC
                """
            ).fetchall()
        return [self._public(row) for row in rows]

    def approve(self, identity_id: str, user_id: str) -> dict[str, Any]:
        identity_id = self._identity_id(identity_id)
        user_id = self.auth._user_id(user_id)
        now = self.auth._now()
        with self.auth.connect() as conn:
            conn.execute("BEGIN IMMEDIATE")
            user = conn.execute(
                "SELECT user_id,enabled FROM workspace_users WHERE user_id=?", (user_id,)
            ).fetchone()
            if user is None or not bool(user["enabled"]):
                raise ValueError("External identity must bind to an enabled local WorkSpace user")
            changed = conn.execute(
                """
                UPDATE workspace_external_identities
                SET status='approved',user_id=?,updated_at=?
                WHERE identity_id=?
                """,
                (user_id, now, identity_id),
            ).rowcount
            if int(changed or 0) != 1:
                raise KeyError("External identity not found")
            row = conn.execute(
                "SELECT * FROM workspace_external_identities WHERE identity_id=?", (identity_id,)
            ).fetchone()
        if row is None:
            raise KeyError("External identity not found")
        return self._public(row)

    def reject(self, identity_id: str) -> dict[str, Any]:
        identity_id = self._identity_id(identity_id)
        now = self.auth._now()
        with self.auth.connect() as conn:
            changed = conn.execute(
                """
                UPDATE workspace_external_identities
                SET status='rejected',user_id=NULL,updated_at=?
                WHERE identity_id=?
                """,
                (now, identity_id),
            ).rowcount
            row = conn.execute(
                "SELECT * FROM workspace_external_identities WHERE identity_id=?", (identity_id,)
            ).fetchone()
        if int(changed or 0) != 1 or row is None:
            raise KeyError("External identity not found")
        return self._public(row)


class IdentityBrokerClient:
    """Redeem one-time opaque tickets over loopback only."""

    def __init__(self, settings: ExternalAuthSettings) -> None:
        self.settings = settings

    def redeem(self, ticket: str) -> dict[str, str]:
        ticket = str(ticket or "").strip()
        if len(ticket) < 32 or len(ticket) > 256:
            raise ValueError("Invalid external login ticket")
        payload = json.dumps({"ticket": ticket}, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            self.settings.redeem_url,
            data=payload,
            headers={
                "Content-Type": "application/json",
                "X-Workspace-Redeem-Key": self.settings.redeem_key,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                raw = response.read(16 * 1024)
        except (urllib.error.URLError, TimeoutError) as exc:
            raise RuntimeError("External identity broker is unavailable") from exc
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or not data.get("ok"):
            raise PermissionError("External login ticket was rejected")
        provider = str(data.get("provider") or "").lower()
        external_key = str(data.get("external_key") or "").lower()
        display_name = str(data.get("display_name") or "")
        if provider not in VALID_EXTERNAL_PROVIDERS or not EXTERNAL_KEY_RE.fullmatch(external_key):
            raise PermissionError("External identity assertion is invalid")
        return {
            "provider": provider,
            "external_key": external_key,
            "display_name": " ".join(display_name.split())[:120],
        }
