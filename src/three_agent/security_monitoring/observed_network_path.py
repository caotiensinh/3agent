from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

OBSERVED_PATH_SCHEMA = "workspace-security-monitoring/observed-network-path-v1"
MAX_HOPS = 64
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_PATH_ID_RE = re.compile(r"^observed-path:[0-9a-f]{24}$")


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
class ObservedPathHop:
    ordinal: int
    responder_sha256: str
    latency_ms: float | None = None

    def validate(self) -> "ObservedPathHop":
        if isinstance(self.ordinal, bool) or not isinstance(self.ordinal, int) or self.ordinal < 1:
            raise MonitoringContractError("hop ordinal must be a positive integer")
        object.__setattr__(self, "responder_sha256", _sha(self.responder_sha256, "responder_sha256"))
        if self.latency_ms is not None:
            if isinstance(self.latency_ms, bool) or not isinstance(self.latency_ms, (int, float)):
                raise MonitoringContractError("latency_ms must be numeric")
            value = float(self.latency_ms)
            if not 0.0 <= value <= 120_000.0:
                raise MonitoringContractError("latency_ms is out of bounds")
            object.__setattr__(self, "latency_ms", value)
        return self


@dataclass(frozen=True)
class ObservedNetworkPath:
    observation_id: str
    asset_id: str
    destination_ref: str
    captured_at: str
    producer: str
    task_ref_sha256: str
    authorization_ref_sha256: str
    source_record_sha256: str
    hops: tuple[ObservedPathHop, ...]
    authority: str = "evidence_only"
    acquisition_performed: bool = False
    raw_output_retained: bool = False
    schema_version: str = OBSERVED_PATH_SCHEMA

    @classmethod
    def build(cls, *, asset_id: str, destination_ref: str, captured_at: str, producer: str,
              task_ref_sha256: str, authorization_ref_sha256: str, source_record_sha256: str,
              hops: Iterable[ObservedPathHop]) -> "ObservedNetworkPath":
        provisional = cls("observed-path:" + "0" * 24, asset_id, destination_ref, captured_at,
                          producer, task_ref_sha256, authorization_ref_sha256,
                          source_record_sha256, tuple(hops))
        provisional._validate(check_id=False)
        result = cls(**{**provisional.__dict__, "observation_id": "observed-path:" + provisional.identity_sha256.split(":", 1)[1][:24]})
        return result.validate()

    def _validate(self, *, check_id: bool) -> "ObservedNetworkPath":
        if self.schema_version != OBSERVED_PATH_SCHEMA:
            raise MonitoringContractError("unsupported observed network path schema")
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id"))
        object.__setattr__(self, "destination_ref", _compact(self.destination_ref, "destination_ref"))
        object.__setattr__(self, "producer", _compact(self.producer, "producer", 96))
        object.__setattr__(self, "captured_at", _timestamp(self.captured_at))
        object.__setattr__(self, "task_ref_sha256", _sha(self.task_ref_sha256, "task_ref_sha256"))
        object.__setattr__(self, "authorization_ref_sha256", _sha(self.authorization_ref_sha256, "authorization_ref_sha256"))
        object.__setattr__(self, "source_record_sha256", _sha(self.source_record_sha256, "source_record_sha256"))
        rows = tuple(hop.validate() for hop in self.hops)
        if not rows or len(rows) > MAX_HOPS:
            raise MonitoringContractError("observed path hop bound violated")
        if tuple(hop.ordinal for hop in rows) != tuple(range(1, len(rows) + 1)):
            raise MonitoringContractError("hop ordinals must be contiguous from one")
        object.__setattr__(self, "hops", rows)
        if self.authority != "evidence_only" or self.acquisition_performed or self.raw_output_retained:
            raise MonitoringContractError("observed path contract cannot broaden acquisition or retention authority")
        if check_id:
            if not _PATH_ID_RE.fullmatch(str(self.observation_id or "")):
                raise MonitoringContractError("observation_id is invalid")
            expected = "observed-path:" + self.identity_sha256.split(":", 1)[1][:24]
            if self.observation_id != expected:
                raise MonitoringContractError("observation_id does not match canonical identity")
        return self

    def validate(self) -> "ObservedNetworkPath":
        return self._validate(check_id=True)

    def identity_dict(self) -> dict[str, object]:
        self._validate(check_id=False)
        return {
            "schema_version": self.schema_version, "asset_id": self.asset_id,
            "destination_ref": self.destination_ref, "captured_at": self.captured_at,
            "producer": self.producer, "task_ref_sha256": self.task_ref_sha256,
            "authorization_ref_sha256": self.authorization_ref_sha256,
            "source_record_sha256": self.source_record_sha256,
            "hops": [asdict(row) for row in self.hops], "authority": self.authority,
            "acquisition_performed": self.acquisition_performed,
            "raw_output_retained": self.raw_output_retained,
        }

    @property
    def identity_sha256(self) -> str:
        return sha256_fingerprint(self.identity_dict())
