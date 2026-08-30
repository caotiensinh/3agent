from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

PROVIDERS = {"google", "github", "line"}
STATE_TTL_SECONDS = 5 * 60
TICKET_TTL_SECONDS = 60
MAX_RESPONSE_BYTES = 128 * 1024


@dataclass(frozen=True)
class ProviderConfig:
    name: str
    client_id: str
    client_secret: str


@dataclass
class PendingState:
    provider: str
    return_origin: str
    verifier: str
    nonce: str
    expires_at: float


@dataclass
class RedeemTicket:
    provider: str
    external_key: str
    display_name: str
    expires_at: float


class BrokerConfig:
    def __init__(self) -> None:
        self.public_base_url = os.getenv("WORKSPACE_IDENTITY_PUBLIC_BASE_URL", "").strip().rstrip("/")
        self.allowed_return_origins = {
            value.strip().rstrip("/")
            for value in os.getenv("WORKSPACE_IDENTITY_ALLOWED_RETURN_ORIGINS", "").split(",")
            if value.strip()
        }
        self.identity_key = os.getenv("WORKSPACE_IDENTITY_KEY", "")
        self.redeem_key = os.getenv("WORKSPACE_EXTERNAL_AUTH_REDEEM_KEY", "")
        self.host = os.getenv("WORKSPACE_IDENTITY_BROKER_HOST", "127.0.0.1")
        self.port = int(os.getenv("WORKSPACE_IDENTITY_BROKER_PORT", "8790"))
        self.redeem_host = "127.0.0.1"
        self.redeem_port = int(os.getenv("WORKSPACE_IDENTITY_REDEEM_PORT", "8791"))
        self.providers: dict[str, ProviderConfig] = {}
        google_id = os.getenv("WORKSPACE_GOOGLE_CLIENT_ID", "").strip()
        google_secret = os.getenv("WORKSPACE_GOOGLE_CLIENT_SECRET", "")
        github_id = os.getenv("WORKSPACE_GITHUB_CLIENT_ID", "").strip()
        github_secret = os.getenv("WORKSPACE_GITHUB_CLIENT_SECRET", "")
        line_id = os.getenv("WORKSPACE_LINE_CHANNEL_ID", "").strip()
        line_secret = os.getenv("WORKSPACE_LINE_CHANNEL_SECRET", "")
        if google_id and google_secret:
            self.providers["google"] = ProviderConfig("google", google_id, google_secret)
        if github_id and github_secret:
            self.providers["github"] = ProviderConfig("github", github_id, github_secret)
        if line_id and line_secret:
            self.providers["line"] = ProviderConfig("line", line_id, line_secret)
        self._validate()

    def _validate(self) -> None:
        if not self.providers:
            raise ValueError("No external identity provider credentials are configured")
        parsed = urlparse(self.public_base_url)
        if parsed.scheme != "https" or not parsed.netloc:
            raise ValueError("WORKSPACE_IDENTITY_PUBLIC_BASE_URL must be an HTTPS origin")
        if any(urlparse(origin).scheme not in {"http", "https"} for origin in self.allowed_return_origins):
            raise ValueError("Invalid allowed return origin")
        if not self.allowed_return_origins:
            raise ValueError("WORKSPACE_IDENTITY_ALLOWED_RETURN_ORIGINS is required")
        if len(self.identity_key) < 32:
            raise ValueError("WORKSPACE_IDENTITY_KEY must contain at least 32 characters")
        if len(self.redeem_key) < 32:
            raise ValueError("WORKSPACE_EXTERNAL_AUTH_REDEEM_KEY must contain at least 32 characters")


class BrokerState:
    def __init__(self, config: BrokerConfig) -> None:
        self.config = config
        self.pending: dict[str, PendingState] = {}
        self.tickets: dict[str, RedeemTicket] = {}
        self.lock = threading.Lock()

    def prune(self) -> None:
        now = time.monotonic()
        self.pending = {key: value for key, value in self.pending.items() if value.expires_at >= now}
        self.tickets = {key: value for key, value in self.tickets.items() if value.expires_at >= now}

    def external_key(self, provider: str, subject: str) -> str:
        message = (provider + "\0" + subject).encode("utf-8")
        return hmac.new(self.config.identity_key.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _pkce_pair() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _json_request(url: str, *, method: str = "GET", form: dict[str, str] | None = None, token: str = "") -> dict[str, Any]:
    if not url.startswith("https://"):
        raise ValueError("Identity provider endpoints must use HTTPS")
    data = urllib.parse.urlencode(form).encode("utf-8") if form is not None else None
    headers = {"Accept": "application/json", "User-Agent": "WorkSpace-Identity-Broker/1.0"}
    if form is not None:
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if token:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise PermissionError(f"Identity provider rejected request: HTTP {exc.code}") from exc
    if len(raw) > MAX_RESPONSE_BYTES:
        raise PermissionError("Identity provider response exceeded safety limit")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise PermissionError("Identity provider response was invalid")
    return payload


def _provider_authorize_url(config: BrokerConfig, provider: str, state: str, nonce: str, challenge: str) -> str:
    callback = f"{config.public_base_url}/auth/callback/{provider}"
    pc = config.providers[provider]
    if provider == "google":
        endpoint = "https://accounts.google.com/o/oauth2/v2/auth"
        params = {
            "client_id": pc.client_id,
            "redirect_uri": callback,
            "response_type": "code",
            "scope": "openid profile",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "prompt": "select_account",
        }
    elif provider == "github":
        endpoint = "https://github.com/login/oauth/authorize"
        params = {
            "client_id": pc.client_id,
            "redirect_uri": callback,
            "scope": "read:user",
            "state": state,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "allow_signup": "false",
        }
    else:
        endpoint = "https://access.line.me/oauth2/v2.1/authorize"
        params = {
            "response_type": "code",
            "client_id": pc.client_id,
            "redirect_uri": callback,
            "state": state,
            "scope": "openid profile",
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
    return endpoint + "?" + urllib.parse.urlencode(params)


def _exchange_identity(config: BrokerConfig, pending: PendingState, code: str) -> tuple[str, str]:
    provider = pending.provider
    pc = config.providers[provider]
    callback = f"{config.public_base_url}/auth/callback/{provider}"
    if provider == "google":
        token = _json_request(
            "https://oauth2.googleapis.com/token",
            method="POST",
            form={
                "client_id": pc.client_id,
                "client_secret": pc.client_secret,
                "code": code,
                "code_verifier": pending.verifier,
                "grant_type": "authorization_code",
                "redirect_uri": callback,
            },
        )
        scopes = set(str(token.get("scope") or "").split())
        if scopes and not scopes.issubset({"openid", "profile"}):
            raise PermissionError("Google returned permissions outside identity-only scope")
        access_token = str(token.get("access_token") or "")
        if not access_token:
            raise PermissionError("Google did not return an access token")
        profile = _json_request(
            "https://openidconnect.googleapis.com/v1/userinfo", token=access_token
        )
        subject = str(profile.get("sub") or "")
        display = str(profile.get("name") or "Google user")
    elif provider == "github":
        token = _json_request(
            "https://github.com/login/oauth/access_token",
            method="POST",
            form={
                "client_id": pc.client_id,
                "client_secret": pc.client_secret,
                "code": code,
                "redirect_uri": callback,
                "code_verifier": pending.verifier,
            },
        )
        scopes = {
            item.strip()
            for item in str(token.get("scope") or "").replace(" ", ",").split(",")
            if item.strip()
        }
        if not scopes.issubset({"read:user"}):
            raise PermissionError("GitHub returned permissions outside read:user")
        access_token = str(token.get("access_token") or "")
        if not access_token:
            raise PermissionError("GitHub did not return an access token")
        profile = _json_request("https://api.github.com/user", token=access_token)
        subject = str(profile.get("id") or "")
        display = str(profile.get("name") or profile.get("login") or "GitHub user")
    else:
        token = _json_request(
            "https://api.line.me/oauth2/v2.1/token",
            method="POST",
            form={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": callback,
                "client_id": pc.client_id,
                "client_secret": pc.client_secret,
                "code_verifier": pending.verifier,
            },
        )
        scopes = set(str(token.get("scope") or "").split())
        if scopes and not scopes.issubset({"openid", "profile"}):
            raise PermissionError("LINE returned permissions outside identity-only scope")
        id_token = str(token.get("id_token") or "")
        if not id_token:
            raise PermissionError("LINE did not return an OpenID ID token")
        profile = _json_request(
            "https://api.line.me/oauth2/v2.1/verify",
            method="POST",
            form={
                "id_token": id_token,
                "client_id": pc.client_id,
                "nonce": pending.nonce,
            },
        )
        subject = str(profile.get("sub") or "")
        display = str(profile.get("name") or "LINE user")
    if not subject or len(subject) > 512:
        raise PermissionError("Identity provider subject is missing or invalid")
    return subject, " ".join(display.split())[:120]


class PublicBrokerHandler(BaseHTTPRequestHandler):
    server_version = "WorkSpaceIdentityBroker/1.0"

    @property
    def state(self) -> BrokerState:
        return self.server.state  # type: ignore[attr-defined]

    def _text(self, status: int, body: str) -> None:
        raw = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        parts = [part for part in parsed.path.split("/") if part]
        if parsed.path == "/health":
            self._text(HTTPStatus.OK, "ok")
            return
        if len(parts) == 3 and parts[:2] == ["auth", "start"]:
            provider = parts[2]
            if provider not in self.state.config.providers:
                self._text(HTTPStatus.NOT_FOUND, "Provider not configured")
                return
            params = parse_qs(parsed.query)
            return_to = str(params.get("return_to", [""])[0]).rstrip("/")
            parsed_return = urlparse(return_to)
            return_origin = f"{parsed_return.scheme}://{parsed_return.netloc}" if parsed_return.scheme and parsed_return.netloc else ""
            if return_origin not in self.state.config.allowed_return_origins:
                self._text(HTTPStatus.BAD_REQUEST, "Return origin is not allowlisted")
                return
            verifier, challenge = _pkce_pair()
            state_token = secrets.token_urlsafe(32)
            nonce = secrets.token_urlsafe(24)
            with self.state.lock:
                self.state.prune()
                self.state.pending[state_token] = PendingState(
                    provider, return_origin, verifier, nonce, time.monotonic() + STATE_TTL_SECONDS
                )
            target = _provider_authorize_url(
                self.state.config, provider, state_token, nonce, challenge
            )
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", target)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        if len(parts) == 3 and parts[:2] == ["auth", "callback"]:
            provider = parts[2]
            params = parse_qs(parsed.query)
            state_token = str(params.get("state", [""])[0])
            code = str(params.get("code", [""])[0])
            if not state_token or not code:
                self._text(HTTPStatus.BAD_REQUEST, "OAuth callback is incomplete")
                return
            with self.state.lock:
                self.state.prune()
                pending = self.state.pending.pop(state_token, None)
            if pending is None or pending.provider != provider:
                self._text(HTTPStatus.BAD_REQUEST, "OAuth state is invalid or expired")
                return
            try:
                subject, display_name = _exchange_identity(self.state.config, pending, code)
            except Exception:
                self._text(HTTPStatus.BAD_GATEWAY, "Identity verification failed")
                return
            ticket = secrets.token_urlsafe(32)
            external_key = self.state.external_key(provider, subject)
            with self.state.lock:
                self.state.tickets[ticket] = RedeemTicket(
                    provider, external_key, display_name, time.monotonic() + TICKET_TTL_SECONDS
                )
            destination = pending.return_origin + "/#workspace_external_ticket=" + urllib.parse.quote(ticket)
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", destination)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            return
        self._text(HTTPStatus.NOT_FOUND, "Not found")

    def log_message(self, format: str, *args) -> None:
        del format, args


class RedeemHandler(BaseHTTPRequestHandler):
    server_version = "WorkSpaceIdentityRedeem/1.0"

    @property
    def state(self) -> BrokerState:
        return self.server.state  # type: ignore[attr-defined]

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

    def do_POST(self) -> None:
        if self.path != "/redeem":
            self._json(HTTPStatus.NOT_FOUND, {"ok": False})
            return
        supplied = self.headers.get("X-Workspace-Redeem-Key", "")
        if not hmac.compare_digest(supplied, self.state.config.redeem_key):
            self._json(HTTPStatus.FORBIDDEN, {"ok": False})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if length <= 0 or length > 4096:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False})
            return
        try:
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception:
            self._json(HTTPStatus.BAD_REQUEST, {"ok": False})
            return
        ticket_key = str(payload.get("ticket") or "") if isinstance(payload, dict) else ""
        with self.state.lock:
            self.state.prune()
            ticket = self.state.tickets.pop(ticket_key, None)
        if ticket is None:
            self._json(HTTPStatus.FORBIDDEN, {"ok": False})
            return
        self._json(
            HTTPStatus.OK,
            {
                "ok": True,
                "provider": ticket.provider,
                "external_key": ticket.external_key,
                "display_name": ticket.display_name,
            },
        )

    def log_message(self, format: str, *args) -> None:
        del format, args


def main() -> int:
    config = BrokerConfig()
    state = BrokerState(config)
    public = ThreadingHTTPServer((config.host, config.port), PublicBrokerHandler)
    redeem = ThreadingHTTPServer((config.redeem_host, config.redeem_port), RedeemHandler)
    public.state = state  # type: ignore[attr-defined]
    redeem.state = state  # type: ignore[attr-defined]
    thread = threading.Thread(target=redeem.serve_forever, name="workspace-identity-redeem", daemon=True)
    thread.start()
    print(
        "[WorkSpace-Identity] configured providers=" + ",".join(sorted(config.providers)),
        flush=True,
    )
    print(
        f"[WorkSpace-Identity] public listener={config.host}:{config.port}; redeem=127.0.0.1:{config.redeem_port}",
        flush=True,
    )
    try:
        public.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        public.server_close()
        redeem.shutdown()
        redeem.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
