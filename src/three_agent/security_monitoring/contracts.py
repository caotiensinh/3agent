from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any

APPROVED_DATA_CLASSES = {"public", "internal", "confidential", "restricted", "secret"}
COLLECTOR_CAPABILITIES = {
    "icmp_echo",
    "tcp_connect",
    "snmpv3_read",
    "local_net_read",
    "fixed_readonly_adapter",
}
FINDING_STATUSES = {"open", "correlated", "investigating", "resolved", "reopened"}
SEVERITIES = {"info", "low", "medium", "high", "critical"}
RUN_STATUSES = {
    "scheduled",
    "acquiring_lock",
    "collecting",
    "normalizing",
    "analyzing_deterministically",
    "committing",
    "completed",
    "partial",
    "blocked_by_policy",
    "data_gap",
    "collector_timeout",
    "storage_failed",
    "pending_nas",
    "failed",
}
OBSERVATION_STATUSES = {"ok", "unreachable", "timeout", "unsupported", "discontinuity", "error"}
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,255}$")
_HOST_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$", re.ASCII)


class MonitoringContractError(ValueError):
    """Monitoring data is invalid or would broaden authority."""


def _compact(value: str, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _COMPACT_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a compact identifier")
    if "://" in text:
        raise MonitoringContractError(f"{field_name} must not contain a URL")
    return text


def validate_management_host(value: str) -> str:
    host = str(value or "").strip()
    if not host or len(host) > 253:
        raise MonitoringContractError("management_host is required")
    if any(ch.isspace() for ch in host) or any(ch in host for ch in "/\\;|&`$<>\"'"):
        raise MonitoringContractError("management_host contains unsafe characters")
    if "://" in host:
        raise MonitoringContractError("management_host must be a host, not a URL")
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        if not _HOST_RE.fullmatch(host):
            raise MonitoringContractError("management_host is not a valid IP/hostname")
        return host.lower()


def canonical_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def sha256_fingerprint(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()


def _iso_timestamp(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return text


@dataclass(frozen=True)
class SecretReference:
    """Opaque reference only. WorkSpace monitoring contracts never contain raw secrets."""

    handle: str

    def validate(self) -> "SecretReference":
        handle = str(self.handle or "").strip()
        if not handle.startswith("secret-ref:"):
            raise MonitoringContractError("secret handle must start with secret-ref:")
        suffix = handle.removeprefix("secret-ref:")
        _compact(suffix, "secret_handle", max_len=160)
        object.__setattr__(self, "handle", "secret-ref:" + suffix)
        return self


@dataclass(frozen=True)
class AssetInventoryRecord:
    asset_id: str
    role: str
    management_host: str
    collector_capabilities: tuple[str, ...]
    allowed_tcp_ports: tuple[int, ...] = field(default_factory=tuple)
    data_class: str = "confidential"
    enabled: bool = True
    credential_ref: SecretReference | None = None
    schema_version: str = "workspace-security-monitoring/asset-v1"

    def validate(self) -> "AssetInventoryRecord":
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id", max_len=128))
        object.__setattr__(self, "role", _compact(self.role, "role", max_len=64))
        object.__setattr__(self, "management_host", validate_management_host(self.management_host))
        caps = tuple(dict.fromkeys(str(v).strip() for v in self.collector_capabilities if str(v).strip()))
        unknown = set(caps) - COLLECTOR_CAPABILITIES
        if unknown:
            raise MonitoringContractError(f"unknown collector capabilities: {sorted(unknown)}")
        object.__setattr__(self, "collector_capabilities", caps)
        ports = tuple(dict.fromkeys(int(v) for v in self.allowed_tcp_ports))
        if any(port < 1 or port > 65535 for port in ports):
            raise MonitoringContractError("allowed_tcp_ports must be within 1..65535")
        object.__setattr__(self, "allowed_tcp_ports", ports)
        if self.data_class not in APPROVED_DATA_CLASSES:
            raise MonitoringContractError(f"unsupported data_class: {self.data_class}")
        if self.credential_ref is not None:
            self.credential_ref.validate()
        if "tcp_connect" in caps and not ports:
            raise MonitoringContractError("tcp_connect assets require explicit allowed_tcp_ports")
        if "snmpv3_read" in caps and self.credential_ref is None:
            raise MonitoringContractError("snmpv3_read requires an opaque credential_ref")
        return self

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["collector_capabilities"] = list(self.collector_capabilities)
        payload["allowed_tcp_ports"] = list(self.allowed_tcp_ports)
        if self.credential_ref is not None:
            payload["credential_ref"] = {"handle": self.credential_ref.handle}
        return payload

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class ObservationRecord:
    run_id: str
    asset_id: str
    collector: str
    observed_at: str
    metric: str
    status: str
    value: int | float | str | bool | None = None
    unit: str | None = None
    evidence_ref: str | None = None
    schema_version: str = "workspace-security-monitoring/observation-v1"

    def validate(self) -> "ObservationRecord":
        object.__setattr__(self, "run_id", _compact(self.run_id, "run_id", max_len=128))
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id", max_len=128))
        if self.collector not in COLLECTOR_CAPABILITIES:
            raise MonitoringContractError(f"unsupported collector: {self.collector}")
        object.__setattr__(self, "observed_at", _iso_timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "metric", _compact(self.metric, "metric", max_len=128))
        if self.status not in OBSERVATION_STATUSES:
            raise MonitoringContractError(f"unsupported observation status: {self.status}")
        if self.unit is not None:
            object.__setattr__(self, "unit", _compact(self.unit, "unit", max_len=32))
        if self.evidence_ref is not None:
            object.__setattr__(self, "evidence_ref", _compact(self.evidence_ref, "evidence_ref"))
        return self


@dataclass(frozen=True)
class CanonicalEvent:
    event_id: str
    source_id: str
    source_type: str
    observed_at: str
    category: str
    severity: str
    message_sha256: str
    parser_version: str
    evidence_ref: str | None = None
    schema_version: str = "workspace-security-monitoring/event-v1"

    def validate(self) -> "CanonicalEvent":
        object.__setattr__(self, "event_id", _compact(self.event_id, "event_id", max_len=128))
        object.__setattr__(self, "source_id", _compact(self.source_id, "source_id", max_len=128))
        object.__setattr__(self, "source_type", _compact(self.source_type, "source_type", max_len=64))
        object.__setattr__(self, "observed_at", _iso_timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "category", _compact(self.category, "category", max_len=96))
        if self.severity not in SEVERITIES:
            raise MonitoringContractError(f"unsupported severity: {self.severity}")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", self.message_sha256):
            raise MonitoringContractError("message_sha256 must be a SHA-256 fingerprint")
        object.__setattr__(self, "parser_version", _compact(self.parser_version, "parser_version", max_len=96))
        if self.evidence_ref is not None:
            object.__setattr__(self, "evidence_ref", _compact(self.evidence_ref, "evidence_ref"))
        return self


@dataclass(frozen=True)
class FindingRecord:
    finding_id: str
    category: str
    severity: str
    status: str
    first_seen: str
    last_seen: str
    asset_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    correlation_key: str
    rule_id: str
    schema_version: str = "workspace-security-monitoring/finding-v1"

    def validate(self) -> "FindingRecord":
        object.__setattr__(self, "finding_id", _compact(self.finding_id, "finding_id", max_len=128))
        object.__setattr__(self, "category", _compact(self.category, "category", max_len=96))
        if self.severity not in SEVERITIES:
            raise MonitoringContractError(f"unsupported severity: {self.severity}")
        if self.status not in FINDING_STATUSES:
            raise MonitoringContractError(f"unsupported finding status: {self.status}")
        object.__setattr__(self, "first_seen", _iso_timestamp(self.first_seen, "first_seen"))
        object.__setattr__(self, "last_seen", _iso_timestamp(self.last_seen, "last_seen"))
        assets = tuple(_compact(v, "asset_ref", max_len=128) for v in self.asset_refs)
        evidence = tuple(_compact(v, "evidence_ref") for v in self.evidence_refs)
        if not assets or not evidence:
            raise MonitoringContractError("findings require asset_refs and evidence_refs")
        object.__setattr__(self, "asset_refs", assets)
        object.__setattr__(self, "evidence_refs", evidence)
        object.__setattr__(self, "correlation_key", _compact(self.correlation_key, "correlation_key"))
        object.__setattr__(self, "rule_id", _compact(self.rule_id, "rule_id", max_len=128))
        return self


@dataclass(frozen=True)
class HourlyRunReceipt:
    run_id: str
    slot_key: str
    attempt: int
    scheduled_at: str
    started_at: str
    completed_at: str | None
    status: str
    inventory_fingerprint: str
    policy_fingerprint: str
    expected_assets: int
    observed_assets: int
    coverage_pct: float
    failure_codes: tuple[str, ...] = field(default_factory=tuple)
    schema_version: str = "workspace-security-monitoring/hourly-receipt-v1"

    def validate(self) -> "HourlyRunReceipt":
        object.__setattr__(self, "run_id", _compact(self.run_id, "run_id", max_len=128))
        object.__setattr__(self, "slot_key", _compact(self.slot_key, "slot_key", max_len=160))
        if self.attempt < 1:
            raise MonitoringContractError("attempt must be >= 1")
        object.__setattr__(self, "scheduled_at", _iso_timestamp(self.scheduled_at, "scheduled_at"))
        object.__setattr__(self, "started_at", _iso_timestamp(self.started_at, "started_at"))
        if self.completed_at is not None:
            object.__setattr__(self, "completed_at", _iso_timestamp(self.completed_at, "completed_at"))
        if self.status not in RUN_STATUSES:
            raise MonitoringContractError(f"unsupported run status: {self.status}")
        for name, fingerprint in (("inventory_fingerprint", self.inventory_fingerprint), ("policy_fingerprint", self.policy_fingerprint)):
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", fingerprint):
                raise MonitoringContractError(f"{name} must be a SHA-256 fingerprint")
        if self.expected_assets < 0 or self.observed_assets < 0 or self.observed_assets > self.expected_assets:
            raise MonitoringContractError("invalid asset coverage counts")
        if not 0.0 <= self.coverage_pct <= 100.0:
            raise MonitoringContractError("coverage_pct must be within [0,100]")
        failures = tuple(_compact(v, "failure_code", max_len=96) for v in self.failure_codes)
        object.__setattr__(self, "failure_codes", failures)
        return self
