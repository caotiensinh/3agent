from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import struct
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, unquote, urlencode, urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zoneinfo import ZoneInfo

from .config import GatewayConfig
from .privacy import OutboundDLPError, assert_public_egress_text, redact_sensitive_text

TZ = ZoneInfo("Asia/Tokyo")
_MAX_REDIRECTS = 5


class OutboundSecurityError(PermissionError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


@dataclass(frozen=True)
class _FetchGrant:
    url: str
    agent_id: str
    task_id: str | None
    expires_at: float


def _audit(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def _safe_audit_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or "<invalid-host>"
        port = f":{parsed.port}" if parsed.port else ""
        return f"{parsed.scheme.lower()}://{host}{port}{redact_sensitive_text(parsed.path or '/')}"
    except Exception:
        return "<invalid-url>"


def _validate_public_url(url: str, *, https_only: bool = True) -> None:
    parsed = urlsplit(url)
    allowed_schemes = {"https"} if https_only else {"http", "https"}
    if parsed.scheme.lower() not in allowed_schemes:
        raise OutboundSecurityError("Only HTTPS outbound URLs are permitted by WorkSpace secure mode")
    if parsed.username is not None or parsed.password is not None:
        raise OutboundSecurityError("Credentials in outbound URLs are prohibited")
    hostname = parsed.hostname
    if not hostname:
        raise OutboundSecurityError("Outbound URL must contain a hostname")
    if https_only and parsed.port not in {None, 443}:
        raise OutboundSecurityError("Only TCP/443 is permitted by WorkSpace secure mode")
    lowered = hostname.rstrip(".").casefold()
    if lowered == "localhost" or lowered.endswith(".localhost") or lowered.endswith(".local"):
        raise OutboundSecurityError("Local hostnames are prohibited for public-web egress")

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        literal = ipaddress.ip_address(hostname)
        addresses = {literal}
    except ValueError:
        try:
            resolved = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise OutboundSecurityError(f"DNS resolution failed for outbound host: {hostname}") from exc
        addresses = {ipaddress.ip_address(item[4][0]) for item in resolved}

    if not addresses:
        raise OutboundSecurityError("Outbound hostname resolved to no address")
    blocked = [str(address) for address in addresses if not address.is_global]
    if blocked:
        raise OutboundSecurityError(
            "Outbound destination resolved to a non-public address: " + ", ".join(sorted(blocked))
        )


class InternetGateway:
    """The only application-level public Internet boundary for WorkSpace.

    Secure mode is capability based:
    - arbitrary GET/POST is denied;
    - public search must use search_get() and pass DLP;
    - content fetches require a short-lived one-time grant derived from a search result;
    - request bodies, auth headers, cookies and caller-controlled headers are never accepted.

    Production deployments must pair this with OS/container egress isolation so
    WorkSpace Core cannot bypass the application boundary.
    """

    def __init__(self, config: GatewayConfig, test_mode_full_access: bool):
        self.config = config
        self.test_mode_full_access = test_mode_full_access
        self._opener = build_opener(_NoRedirect())
        self._grants: dict[str, _FetchGrant] = {}
        self._search_result_grants: dict[tuple[str, str | None, str], float] = {}

    @property
    def secure_mode(self) -> bool:
        return self.config.mode == "strict"

    @property
    def broker_active(self) -> bool:
        return bool(
            self.secure_mode
            and self.config.broker_socket is not None
            and not self.config.direct_egress
        )

    @staticmethod
    def _recv_exact(sock: socket.socket, size: int) -> bytes:
        chunks: list[bytes] = []
        remaining = size
        while remaining:
            chunk = sock.recv(remaining)
            if not chunk:
                raise OutboundSecurityError("Egress broker closed the connection")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _broker_request(self, action: str, payload: dict, *, timeout: int) -> bytes:
        socket_path = self.config.broker_socket
        if socket_path is None:
            raise OutboundSecurityError("Egress broker socket is not configured")
        request_payload = {"action": action, **payload}
        encoded = json.dumps(request_payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if len(encoded) > 16 * 1024:
            raise OutboundSecurityError("Egress broker request exceeds 16 KiB")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(min(timeout, self.config.broker_timeout_seconds))
            sock.connect(str(socket_path))
            sock.sendall(struct.pack("!I", len(encoded)) + encoded)
            response_size = struct.unpack("!I", self._recv_exact(sock, 4))[0]
            max_wire = (self.config.max_response_bytes * 2) + 65536
            if response_size <= 0 or response_size > max_wire:
                raise OutboundSecurityError("Invalid egress broker response size")
            response = json.loads(self._recv_exact(sock, response_size).decode("utf-8"))
        if not isinstance(response, dict) or not response.get("ok"):
            reason = response.get("error", "broker_denied") if isinstance(response, dict) else "broker_invalid_response"
            raise OutboundSecurityError(f"Egress broker denied request: {reason}")
        body = response.get("body_b64", "")
        if not isinstance(body, str):
            raise OutboundSecurityError("Egress broker response body is invalid")
        data = base64.b64decode(body.encode("ascii"), validate=True)
        if len(data) > self.config.max_response_bytes:
            raise OutboundSecurityError("Egress broker response exceeds configured safety limit")
        return data

    def _record(
        self,
        agent_id: str,
        task_id: str | None,
        url: str,
        allowed: bool,
        reason: str = "",
        action: str = "http_get",
        extra: dict | None = None,
    ) -> None:
        record = {
            "timestamp": datetime.now(TZ).isoformat(),
            "agent_id": agent_id,
            "task_id": task_id,
            "action": action,
            "url": _safe_audit_url(url),
            "allowed": allowed,
            "reason": redact_sensitive_text(reason)[:500],
        }
        if extra:
            record.update(extra)
        _audit(self.config.audit_log, record)

    def _legacy_allowed(self) -> bool:
        return (
            self.config.enabled
            and self.config.allow_all
            and self.test_mode_full_access
            and not self.secure_mode
        )

    def _read_https(
        self,
        agent_id: str,
        task_id: str | None,
        url: str,
        *,
        timeout: int,
        action: str,
    ) -> bytes:
        current = url
        for redirect_count in range(_MAX_REDIRECTS + 1):
            try:
                _validate_public_url(current, https_only=self.secure_mode)
            except Exception as exc:
                self._record(agent_id, task_id, current, False, str(exc), action)
                raise

            req = Request(
                current,
                headers={
                    "User-Agent": "WorkSpace-Egress/1.0",
                    "Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.1",
                    "Cache-Control": "no-store",
                },
                method="GET",
            )
            try:
                response = self._opener.open(req, timeout=timeout)
            except HTTPError as exc:
                if 300 <= exc.code < 400 and exc.headers.get("Location"):
                    if redirect_count >= _MAX_REDIRECTS:
                        self._record(agent_id, task_id, current, False, "redirect_limit_exceeded", action)
                        raise OutboundSecurityError("Outbound redirect limit exceeded") from exc
                    next_url = urljoin(current, exc.headers["Location"])
                    try:
                        _validate_public_url(next_url, https_only=self.secure_mode)
                    except Exception as redirect_exc:
                        self._record(
                            agent_id,
                            task_id,
                            current,
                            False,
                            f"redirect_target_rejected:{redirect_exc}",
                            action,
                        )
                        exc.close()
                        raise
                    self._record(agent_id, task_id, current, True, f"redirect_{exc.code}", action)
                    exc.close()
                    current = next_url
                    continue
                self._record(agent_id, task_id, current, True, f"http_error_{exc.code}", action)
                raise

            with response:
                data = response.read(self.config.max_response_bytes + 1)
            if len(data) > self.config.max_response_bytes:
                self._record(agent_id, task_id, current, False, "response_too_large", action)
                raise OutboundSecurityError("Outbound response exceeds configured safety limit")
            self._record(agent_id, task_id, current, True, action=action)
            return data
        raise OutboundSecurityError("Outbound redirect processing failed closed")

    def _learn_search_result_urls(
        self, agent_id: str, task_id: str | None, data: bytes
    ) -> None:
        """Create short-lived exact-URL grants from search-engine response bytes."""
        text = data.decode("utf-8", errors="replace")[: self.config.max_response_bytes]
        candidates = set(re.findall(r"https://[^\s\"'<>]+", text, flags=re.IGNORECASE))
        # Search pages are untrusted. Bound candidate processing so an attacker cannot
        # turn one response into an unbounded DNS/validation workload.
        candidates = set(sorted(candidates)[:64])
        for raw in list(candidates):
            try:
                parsed = urlsplit(raw.replace("&amp;", "&"))
                uddg = parse_qs(parsed.query).get("uddg", [])
                if uddg:
                    candidates.add(unquote(uddg[0]))
            except Exception:
                continue
        expiry = time.monotonic() + self.config.grant_ttl_seconds
        for candidate in sorted(candidates)[:64]:
            try:
                _validate_public_url(candidate)
            except Exception:
                continue
            self._search_result_grants[(agent_id, task_id, candidate)] = expiry

    def _consume_search_result_grant(
        self, agent_id: str, task_id: str | None, url: str
    ) -> bool:
        expiry = self._search_result_grants.pop((agent_id, task_id, url), None)
        return expiry is not None and expiry >= time.monotonic()

    def search_get(
        self,
        agent_id: str,
        task_id: str | None,
        endpoint: str,
        params: dict[str, str | int],
        *,
        timeout: int = 30,
    ) -> bytes:
        if self.broker_active:
            query = params.get("q", "")
            assert_public_egress_text(str(query), max_chars=self.config.max_query_chars)
            return self._broker_request(
                "search",
                {
                    "agent_id": agent_id,
                    "task_id": task_id,
                    "endpoint": endpoint,
                    "params": params,
                },
                timeout=timeout,
            )
        if not self.config.enabled or not self.secure_mode or not self.config.public_search_enabled:
            self._record(agent_id, task_id, endpoint, False, "public_search_disabled", "public_search")
            raise OutboundSecurityError("Public search is disabled by WorkSpace confidentiality policy")

        parsed = urlsplit(endpoint)
        host = (parsed.hostname or "").rstrip(".").casefold()
        if host not in self.config.allowed_search_hosts:
            self._record(agent_id, task_id, endpoint, False, "search_host_not_allowlisted", "public_search")
            raise OutboundSecurityError("Search host is not allowlisted")
        _validate_public_url(endpoint)

        permitted_keys = {"q", "count"}
        if not params or any(str(key) not in permitted_keys for key in params):
            raise OutboundSecurityError("Search parameters contain a non-allowlisted key")
        if "q" not in params:
            raise OutboundSecurityError("Search query parameter q is required")

        safe_params: dict[str, str] = {}
        for key, value in params.items():
            if key == "q":
                try:
                    safe_params[key] = assert_public_egress_text(
                        str(value), max_chars=self.config.max_query_chars
                    )
                except OutboundDLPError as exc:
                    self._record(agent_id, task_id, endpoint, False, str(exc), "public_search")
                    raise
            else:
                numeric = str(value)
                if not numeric.isdigit() or int(numeric) > 20:
                    raise OutboundSecurityError("Search count must be an integer <= 20")
                safe_params[key] = numeric

        url = endpoint.rstrip("?") + "?" + urlencode(safe_params)
        query_digest = hashlib.sha256(safe_params["q"].encode("utf-8")).hexdigest()
        self._record(
            agent_id,
            task_id,
            endpoint,
            True,
            "search_authorized",
            "public_search_authorized",
            {"query_sha256": query_digest, "query_chars": len(safe_params["q"])},
        )
        data = self._read_https(agent_id, task_id, url, timeout=timeout, action="public_search_fetch")
        self._learn_search_result_urls(agent_id, task_id, data)
        return data

    def grant_public_fetch(self, agent_id: str, task_id: str | None, url: str) -> str:
        if not self.config.enabled or not self.secure_mode or not self.config.public_search_enabled:
            raise OutboundSecurityError("Public fetch grants are disabled")
        _validate_public_url(url)
        parsed = urlsplit(url)
        host = (parsed.hostname or "").rstrip(".").casefold()
        if self.config.allowed_content_hosts and host not in self.config.allowed_content_hosts:
            raise OutboundSecurityError("Content host is not allowlisted")
        token = secrets.token_urlsafe(24)
        self._grants[token] = _FetchGrant(
            url=url,
            agent_id=agent_id,
            task_id=task_id,
            expires_at=time.monotonic() + self.config.grant_ttl_seconds,
        )
        self._record(agent_id, task_id, url, True, "one_time_fetch_grant", "public_fetch_grant")
        return token

    def fetch_granted(
        self,
        agent_id: str,
        task_id: str | None,
        grant_token: str,
        *,
        timeout: int = 30,
    ) -> bytes:
        grant = self._grants.pop(grant_token, None)
        if grant is None:
            raise OutboundSecurityError("Unknown or already-consumed public fetch grant")
        if grant.expires_at < time.monotonic():
            raise OutboundSecurityError("Public fetch grant expired")
        if grant.agent_id != agent_id or grant.task_id != task_id:
            raise OutboundSecurityError("Public fetch grant scope mismatch")
        return self._read_https(agent_id, task_id, grant.url, timeout=timeout, action="public_result_fetch")

    def get(self, agent_id: str, task_id: str | None, url: str, timeout: int = 30) -> bytes:
        if self.secure_mode:
            parsed = urlsplit(url)
            host = (parsed.hostname or "").rstrip(".").casefold()
            if host in self.config.allowed_search_hosts:
                params = parse_qs(parsed.query)
                flattened = {key: values[0] for key, values in params.items() if values}
                return self.search_get(
                    agent_id,
                    task_id,
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    flattened,
                    timeout=timeout,
                )
            if self.broker_active:
                return self._broker_request(
                    "fetch_result",
                    {"agent_id": agent_id, "task_id": task_id, "url": url},
                    timeout=timeout,
                )
            if self._consume_search_result_grant(agent_id, task_id, url):
                return self._read_https(
                    agent_id, task_id, url, timeout=timeout, action="public_result_fetch"
                )
            self._record(agent_id, task_id, url, False, "arbitrary_get_denied", "http_get")
            raise OutboundSecurityError(
                "Arbitrary Internet GET is disabled. URL must come from an allowlisted public search result."
            )
        if not self._legacy_allowed():
            self._record(agent_id, task_id, url, False, "gateway_policy_denied", "http_get")
            raise PermissionError("Outbound Internet is not permitted by current gateway policy")
        return self._read_https(agent_id, task_id, url, timeout=timeout, action="http_get")

    def post_json(
        self,
        agent_id: str,
        task_id: str | None,
        url: str,
        payload: dict,
        timeout: int = 30,
    ) -> bytes:
        del payload, timeout
        self._record(agent_id, task_id, url, False, "outbound_body_denied", "http_post")
        raise OutboundSecurityError(
            "WorkSpace Internet Gateway never permits arbitrary outbound POST bodies"
        )


class ExecutionGateway:
    def __init__(self, config: GatewayConfig, test_mode_full_access: bool):
        self.config = config
        self.test_mode_full_access = test_mode_full_access

    def run(
        self,
        agent_id: str,
        task_id: str | None,
        argv: list[str],
        cwd: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        allowed = self.config.enabled and self.test_mode_full_access and self.config.allow_all
        _audit(
            self.config.audit_log,
            {
                "timestamp": datetime.now(TZ).isoformat(),
                "agent_id": agent_id,
                "task_id": task_id,
                "action": "command",
                "argv": [redact_sensitive_text(item) for item in argv],
                "cwd": redact_sensitive_text(cwd) if cwd else None,
                "allowed": allowed,
            },
        )
        if not allowed:
            raise PermissionError("Command execution is not permitted by current gateway policy")
        return subprocess.run(argv, cwd=cwd, text=True, capture_output=True, check=False)
