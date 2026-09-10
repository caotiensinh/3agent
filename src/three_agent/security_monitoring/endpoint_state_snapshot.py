from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

ENDPOINT_STATE_SCHEMA = "workspace-security-monitoring/endpoint-state-snapshot-v1"
MAX_COMPONENTS = 128
MAX_ITEMS = 1_000_000
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SNAPSHOT_ID_RE = re.compile(r"^endpoint-state:[0-9a-f]{24}$")
ALLOWED_COMPONENTS = frozenset({"services", "packages", "processes", "network_interfaces", "mounts", "users", "security_controls"})


def _sha(value: str, field: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise MonitoringContractError(f"{field} must be SHA-256")
    return text


def _compact(value: str, field: str, max_len: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or "://" in text or any(ch.isspace() for ch in text):
        raise MonitoringContractError(f"{field} must be a bounded compact identifier")
    return text


def _timestamp(value: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError("captured_at must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError("captured_at must include timezone")
    return parsed.isoformat()


@dataclass(frozen=True)
class EndpointStateComponent:
    component: str
    content_sha256: str
    item_count: int

    def validate(self) -> "EndpointStateComponent":
        name = str(self.component or "").strip()
        if name not in ALLOWED_COMPONENTS:
            raise MonitoringContractError("unsupported endpoint state component")
        object.__setattr__(self, "component", name)
        object.__setattr__(self, "content_sha256", _sha(self.content_sha256, "content_sha256"))
        if isinstance(self.item_count, bool) or not isinstance(self.item_count, int) or not 0 <= self.item_count <= MAX_ITEMS:
            raise MonitoringContractError("item_count is out of bounds")
        return self


@dataclass(frozen=True)
class EndpointStateSnapshot:
    snapshot_id: str
    asset_id: str
    captured_at: str
    producer: str
    task_ref_sha256: str
    authorization_ref_sha256: str
    source_record_sha256: str
    components: tuple[EndpointStateComponent, ...]
    authority: str = "evidence_only"
    remote_execution_performed: bool = False
    raw_output_retained: bool = False
    schema_version: str = ENDPOINT_STATE_SCHEMA

    @classmethod
    def build(cls, *, asset_id: str, captured_at: str, producer: str, task_ref_sha256: str,
              authorization_ref_sha256: str, source_record_sha256: str,
              components: Iterable[EndpointStateComponent]) -> "EndpointStateSnapshot":
        provisional = cls("endpoint-state:" + "0" * 24, asset_id, captured_at, producer,
                          task_ref_sha256, authorization_ref_sha256, source_record_sha256,
                          tuple(components))
        provisional._validate(check_id=False)
        result = cls(**{**provisional.__dict__, "snapshot_id": "endpoint-state:" + provisional.identity_sha256.split(":", 1)[1][:24]})
        return result.validate()

    def _validate(self, *, check_id: bool) -> "EndpointStateSnapshot":
        if self.schema_version != ENDPOINT_STATE_SCHEMA:
            raise MonitoringContractError("unsupported endpoint state schema")
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id"))
        object.__setattr__(self, "producer", _compact(self.producer, "producer", 96))
        object.__setattr__(self, "captured_at", _timestamp(self.captured_at))
        object.__setattr__(self, "task_ref_sha256", _sha(self.task_ref_sha256, "task_ref_sha256"))
        object.__setattr__(self, "authorization_ref_sha256", _sha(self.authorization_ref_sha256, "authorization_ref_sha256"))
        object.__setattr__(self, "source_record_sha256", _sha(self.source_record_sha256, "source_record_sha256"))
        rows = tuple(sorted((item.validate() for item in self.components), key=lambda item: item.component))
        if not rows or len(rows) > MAX_COMPONENTS:
            raise MonitoringContractError("endpoint state component bound violated")
        names = tuple(item.component for item in rows)
        if len(set(names)) != len(names):
            raise MonitoringContractError("endpoint state component names must be unique")
        object.__setattr__(self, "components", rows)
        if self.authority != "evidence_only" or self.remote_execution_performed or self.raw_output_retained:
            raise MonitoringContractError("endpoint state snapshot cannot broaden execution or retention authority")
        if check_id:
            if not _SNAPSHOT_ID_RE.fullmatch(str(self.snapshot_id or "")):
                raise MonitoringContractError("snapshot_id is invalid")
            expected = "endpoint-state:" + self.identity_sha256.split(":", 1)[1][:24]
            if self.snapshot_id != expected:
                raise MonitoringContractError("snapshot_id does not match canonical identity")
        return self

    def validate(self) -> "EndpointStateSnapshot":
        return self._validate(check_id=True)

    def identity_dict(self) -> dict[str, object]:
        self._validate(check_id=False)
        return {
            "schema_version": self.schema_version, "asset_id": self.asset_id,
            "captured_at": self.captured_at, "producer": self.producer,
            "task_ref_sha256": self.task_ref_sha256,
            "authorization_ref_sha256": self.authorization_ref_sha256,
            "source_record_sha256": self.source_record_sha256,
            "components": [asdict(item) for item in self.components],
            "authority": self.authority, "remote_execution_performed": self.remote_execution_performed,
            "raw_output_retained": self.raw_output_retained,
        }

    @property
    def identity_sha256(self) -> str:
        return sha256_fingerprint(self.identity_dict())
