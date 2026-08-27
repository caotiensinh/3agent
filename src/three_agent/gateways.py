from __future__ import annotations

import ipaddress
import json
import socket
import subprocess
from datetime import datetime
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import urljoin, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
from zoneinfo import ZoneInfo

from .config import GatewayConfig
from .privacy import redact_sensitive_text

TZ = ZoneInfo("Asia/Tokyo")
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024
_MAX_REDIRECTS = 5


class OutboundSecurityError(PermissionError):
    pass


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def _audit(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False) + "\n")


def _safe_audit_url(url: str) -> str:
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or "<invalid-host>"
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        path = redact_sensitive_text(parsed.path or "/")
        return f"{parsed.scheme.lower()}://{host}{port}{path}"
    except Exception:
        return "<invalid-url>"


def _validate_public_url(url: str) -> None:
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in {"http", "https"}:
        raise OutboundSecurityError("Only http/https outbound URLs are permitted")
    if parsed.username is not None or parsed.password is not None:
        raise OutboundSecurityError("Credentials in outbound URLs are prohibited")
    hostname = parsed.hostname
    if not hostname:
        raise OutboundSecurityError("Outbound URL must contain a hostname")
    lowered = hostname.rstrip(".").casefold()
    if lowered == "localhost" or lowered.endswith(".localhost") or lowered.endswith(".local"):
        raise OutboundSecurityError("Local hostnames are prohibited for public-web research")

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
    def __init__(self, config: GatewayConfig, test_mode_full_access: bool):
        self.config = config
        self.test_mode_full_access = test_mode_full_access
        self._opener = build_opener(_NoRedirect())

    def _record(
        self,
        agent_id: str,
        task_id: str | None,
        url: str,
        allowed: bool,
        reason: str = "",
        action: str = "http_get",
    ) -> None:
        _audit(
            self.config.audit_log,
            {
                "timestamp": datetime.now(TZ).isoformat(),
                "agent_id": agent_id,
                "task_id": task_id,
                "action": action,
                "url": _safe_audit_url(url),
                "allowed": allowed,
                "reason": redact_sensitive_text(reason)[:500],
            },
        )

    def _request(
        self,
        agent_id: str,
        task_id: str | None,
        url: str,
        *,
        timeout: int,
        method: str,
        body: bytes | None,
        headers: dict[str, str] | None,
        action: str,
    ) -> bytes:
        policy_allowed = self.config.enabled and self.test_mode_full_access and self.config.allow_all
        if not policy_allowed:
            self._record(agent_id, task_id, url, False, "gateway_policy_denied", action)
            raise PermissionError("Outbound Internet is not permitted by current gateway policy")

        current = url
        for redirect_count in range(_MAX_REDIRECTS + 1):
            try:
                _validate_public_url(current)
            except Exception as exc:
                self._record(agent_id, task_id, current, False, str(exc), action)
                raise

            req_headers = {"User-Agent": "3Agent-TestHarness/0.3"}
            req_headers.update(headers or {})
            req = Request(current, data=body, headers=req_headers, method=method)
            try:
                response = self._opener.open(req, timeout=timeout)
            except HTTPError as exc:
                if 300 <= exc.code < 400 and exc.headers.get("Location"):
                    if redirect_count >= _MAX_REDIRECTS:
                        self._record(agent_id, task_id, current, False, "redirect_limit_exceeded", action)
                        raise OutboundSecurityError("Outbound redirect limit exceeded") from exc
                    next_url = urljoin(current, exc.headers["Location"])
                    self._record(agent_id, task_id, current, True, f"redirect_{exc.code}", action)
                    exc.close()
                    current = next_url
                    continue
                self._record(agent_id, task_id, current, True, f"http_error_{exc.code}", action)
                raise

            with response:
                data = response.read(_MAX_RESPONSE_BYTES + 1)
            if len(data) > _MAX_RESPONSE_BYTES:
                self._record(agent_id, task_id, current, False, "response_too_large", action)
                raise OutboundSecurityError("Outbound response exceeds 8 MiB safety limit")
            self._record(agent_id, task_id, current, True, action=action)
            return data

        raise OutboundSecurityError("Outbound redirect processing failed closed")

    def get(self, agent_id: str, task_id: str | None, url: str, timeout: int = 30) -> bytes:
        return self._request(
            agent_id,
            task_id,
            url,
            timeout=timeout,
            method="GET",
            body=None,
            headers=None,
            action="http_get",
        )

    def post_json(
        self,
        agent_id: str,
        task_id: str | None,
        url: str,
        payload: dict,
        timeout: int = 30,
    ) -> bytes:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return self._request(
            agent_id,
            task_id,
            url,
            timeout=timeout,
            method="POST",
            body=body,
            headers={"Content-Type": "application/json; charset=utf-8"},
            action="http_post",
        )


class ExecutionGateway:
    def __init__(self, config: GatewayConfig, test_mode_full_access: bool):
        self.config = config
        self.test_mode_full_access = test_mode_full_access

    def run(self, agent_id: str, task_id: str | None, argv: list[str], cwd: str | None = None) -> subprocess.CompletedProcess[str]:
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
