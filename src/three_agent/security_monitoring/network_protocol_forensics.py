from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Mapping

from .contracts import CanonicalEvent, MonitoringContractError, sha256_fingerprint

NETWORK_PROTOCOL_FORENSICS_SCHEMA = "workspace-security-forensics/network-protocol-v1"
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HTTP_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "CONNECT", "TRACE"})
_TLS_CATEGORIES = frozenset({"suricata.tls", "zeek.ssl"})
_HTTP_CATEGORIES = frozenset({"suricata.http", "zeek.http"})
_TLS_KEYS = frozenset({"server_name", "tls_version", "certificate_sha256", "ja3"})
_HTTP_KEYS = frozenset({"method", "host", "uri", "user_agent", "status_code"})


def _privacy_hash(kind: str, value: object) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    if not text or len(text) > 4096 or any(ord(ch) < 32 for ch in text):
        raise MonitoringContractError(f"{kind} projection is invalid")
    return sha256_fingerprint({"kind": kind, "value": text})


def _optional_sha(value: object, field_name: str) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip().lower()
    if re.fullmatch(r"[0-9a-f]{64}", text):
        return "sha256:" + text
    if _SHA256_RE.fullmatch(text):
        return text
    raise MonitoringContractError(f"{field_name} must be SHA-256")


@dataclass(frozen=True)
class NetworkProtocolForensicMetadata:
    event_id: str
    evidence_ref: str
    source_type: str
    protocol: str
    server_name_sha256: str | None = None
    tls_version: str | None = None
    certificate_sha256: str | None = None
    ja3_sha256: str | None = None
    http_method: str | None = None
    http_status_code: int | None = None
    http_host_sha256: str | None = None
    http_uri_sha256: str | None = None
    http_user_agent_sha256: str | None = None
    authority: str = "advisory"
    schema_version: str = NETWORK_PROTOCOL_FORENSICS_SCHEMA

    def validate(self) -> "NetworkProtocolForensicMetadata":
        if not self.event_id or not self.evidence_ref:
            raise MonitoringContractError("network protocol forensic metadata requires event/evidence refs")
        if self.protocol not in {"tls", "http"}:
            raise MonitoringContractError("unsupported forensic network protocol")
        for field_name in (
            "server_name_sha256",
            "certificate_sha256",
            "ja3_sha256",
            "http_host_sha256",
            "http_uri_sha256",
            "http_user_agent_sha256",
        ):
            value = getattr(self, field_name)
            if value is not None and not _SHA256_RE.fullmatch(value):
                raise MonitoringContractError(f"{field_name} must be SHA-256")
        if self.protocol == "tls":
            if any(
                value is not None
                for value in (
                    self.http_method,
                    self.http_status_code,
                    self.http_host_sha256,
                    self.http_uri_sha256,
                    self.http_user_agent_sha256,
                )
            ):
                raise MonitoringContractError("TLS forensic metadata cannot carry HTTP fields")
            if self.tls_version is not None:
                version = str(self.tls_version).strip()
                if not version or len(version) > 32 or any(ch.isspace() for ch in version):
                    raise MonitoringContractError("tls_version is invalid")
                object.__setattr__(self, "tls_version", version)
        else:
            if any(value is not None for value in (self.server_name_sha256, self.tls_version, self.certificate_sha256, self.ja3_sha256)):
                raise MonitoringContractError("HTTP forensic metadata cannot carry TLS fields")
            if self.http_method not in _HTTP_METHODS:
                raise MonitoringContractError("unsupported HTTP method")
            if self.http_status_code is not None and not 100 <= self.http_status_code <= 599:
                raise MonitoringContractError("HTTP status code is out of range")
        if self.authority != "advisory":
            raise MonitoringContractError("network protocol forensic metadata must remain advisory")
        if self.schema_version != NETWORK_PROTOCOL_FORENSICS_SCHEMA:
            raise MonitoringContractError("unsupported network protocol forensic schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "event_id": self.event_id,
            "evidence_ref": self.evidence_ref,
            "source_type": self.source_type,
            "protocol": self.protocol,
            "server_name_sha256": self.server_name_sha256,
            "tls_version": self.tls_version,
            "certificate_sha256": self.certificate_sha256,
            "ja3_sha256": self.ja3_sha256,
            "http_method": self.http_method,
            "http_status_code": self.http_status_code,
            "http_host_sha256": self.http_host_sha256,
            "http_uri_sha256": self.http_uri_sha256,
            "http_user_agent_sha256": self.http_user_agent_sha256,
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def build_network_protocol_forensics(
    event: CanonicalEvent,
    projection: Mapping[str, object],
) -> NetworkProtocolForensicMetadata:
    """Create privacy-preserving TLS/HTTP metadata from an existing sensor event.

    The caller supplies a bounded projection extracted from already-ingested Zeek or
    Suricata telemetry. This function does not decode packets, open files, access the
    network or retain raw host/SNI/URI/User-Agent values.
    """

    if not isinstance(event, CanonicalEvent):
        raise MonitoringContractError("network protocol forensics requires CanonicalEvent")
    event.validate()
    if event.evidence_ref is None:
        raise MonitoringContractError("network protocol forensics requires evidence_ref")
    if not isinstance(projection, Mapping):
        raise MonitoringContractError("network protocol projection must be a mapping")

    if event.category in _TLS_CATEGORIES:
        if set(projection) - _TLS_KEYS:
            raise MonitoringContractError("TLS projection contains unsupported fields")
        return NetworkProtocolForensicMetadata(
            event_id=event.event_id,
            evidence_ref=event.evidence_ref,
            source_type=event.source_type,
            protocol="tls",
            server_name_sha256=_privacy_hash("tls_server_name", projection.get("server_name")),
            tls_version=None if projection.get("tls_version") in (None, "") else str(projection.get("tls_version")).strip(),
            certificate_sha256=_optional_sha(projection.get("certificate_sha256"), "certificate_sha256"),
            ja3_sha256=_privacy_hash("ja3", projection.get("ja3")),
        ).validate()

    if event.category in _HTTP_CATEGORIES:
        if set(projection) - _HTTP_KEYS:
            raise MonitoringContractError("HTTP projection contains unsupported fields")
        method = str(projection.get("method") or "").strip().upper()
        status_raw = projection.get("status_code")
        status = None
        if status_raw not in (None, ""):
            if isinstance(status_raw, bool):
                raise MonitoringContractError("HTTP status code is invalid")
            try:
                status = int(status_raw)
            except (TypeError, ValueError) as exc:
                raise MonitoringContractError("HTTP status code is invalid") from exc
        return NetworkProtocolForensicMetadata(
            event_id=event.event_id,
            evidence_ref=event.evidence_ref,
            source_type=event.source_type,
            protocol="http",
            http_method=method,
            http_status_code=status,
            http_host_sha256=_privacy_hash("http_host", projection.get("host")),
            http_uri_sha256=_privacy_hash("http_uri", projection.get("uri")),
            http_user_agent_sha256=_privacy_hash("http_user_agent", projection.get("user_agent")),
        ).validate()

    raise MonitoringContractError("event category is not a supported TLS/HTTP telemetry event")
