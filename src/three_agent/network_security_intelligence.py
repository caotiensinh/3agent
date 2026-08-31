from __future__ import annotations

import hashlib
import json
import math
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable

from .network_corpus_adapter import EvidenceRecord

SIGNAL_SCHEMA = "workspace-network-security-signal/v1"
ANALYZER_VERSION = "workspace-network-security-intelligence/0.1"
SEVERITIES = {"LOW", "MEDIUM", "HIGH"}


class NetworkSecurityIntelligenceError(ValueError):
    """Input evidence violates the bounded deterministic analysis contract."""


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _parse_timestamp(value: str | None) -> datetime:
    if not value:
        raise NetworkSecurityIntelligenceError("flow evidence requires timestamp")
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise NetworkSecurityIntelligenceError("flow evidence timestamp must be ISO-8601") from exc


def _stable_epoch_seconds(value: datetime) -> float:
    # Naive dataset timestamps intentionally retain unknown timezone. Treat their
    # calendar values as a timezone-neutral axis instead of consulting host TZ.
    if value.tzinfo is None:
        return (value - datetime(1970, 1, 1)).total_seconds()
    return (value.astimezone(timezone.utc) - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds()


def _text(fields: dict[str, Any], key: str) -> str | None:
    value = fields.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _number(fields: dict[str, Any], key: str) -> float | None:
    value = fields.get(key)
    if value is None or isinstance(value, bool):
        return None
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


@dataclass(frozen=True)
class FlowView:
    evidence_id: str
    timestamp: datetime
    source_address: str
    destination_address: str
    source_port: str | None
    destination_port: str | None
    protocol: str | None
    total_bytes: float | None
    source_bytes: float | None

    @classmethod
    def from_evidence(cls, record: EvidenceRecord) -> "FlowView | None":
        if record.event_family != "network_flow":
            return None
        fields = record.observation_fields
        src = _text(fields, "source_address")
        dst = _text(fields, "destination_address")
        if not src or not dst:
            return None
        return cls(
            evidence_id=record.evidence_id,
            timestamp=_parse_timestamp(record.timestamp),
            source_address=src,
            destination_address=dst,
            source_port=_text(fields, "source_port"),
            destination_port=_text(fields, "destination_port"),
            protocol=_text(fields, "protocol"),
            total_bytes=_number(fields, "total_bytes"),
            source_bytes=_number(fields, "source_bytes"),
        )


@dataclass(frozen=True)
class NetworkSecuritySignal:
    signal_id: str
    signal_type: str
    severity: str
    subject: str
    window_start: str
    window_end: str
    evidence_ids: tuple[str, ...]
    evidence_count: int
    metrics: dict[str, Any]
    rationale: str
    authority: str = "advisory"
    ground_truth_used: bool = False
    analyzer_version: str = ANALYZER_VERSION
    schema_version: str = SIGNAL_SCHEMA

    @classmethod
    def build(
        cls,
        *,
        signal_type: str,
        severity: str,
        subject: str,
        window_start: datetime,
        window_end: datetime,
        evidence_ids: Iterable[str],
        evidence_count: int,
        metrics: dict[str, Any],
        rationale: str,
    ) -> "NetworkSecuritySignal":
        if severity not in SEVERITIES:
            raise NetworkSecurityIntelligenceError("invalid severity")
        ids = tuple(dict.fromkeys(str(item) for item in evidence_ids))
        if not ids or len(ids) > 64:
            raise NetworkSecurityIntelligenceError("signal evidence_ids must contain 1..64 unique ids")
        if evidence_count < len(ids):
            raise NetworkSecurityIntelligenceError("evidence_count cannot be smaller than retained evidence ids")
        identity = {
            "schema_version": SIGNAL_SCHEMA,
            "analyzer_version": ANALYZER_VERSION,
            "signal_type": signal_type,
            "severity": severity,
            "subject": subject,
            "window_start": window_start.isoformat(),
            "window_end": window_end.isoformat(),
            "evidence_ids": list(ids),
            "evidence_count": evidence_count,
            "metrics": metrics,
            "rationale": rationale,
            "authority": "advisory",
            "ground_truth_used": False,
        }
        return cls(
            signal_id="nsi_" + _canonical_sha256(identity)[7:31],
            signal_type=signal_type,
            severity=severity,
            subject=subject,
            window_start=window_start.isoformat(),
            window_end=window_end.isoformat(),
            evidence_ids=ids,
            evidence_count=evidence_count,
            metrics=dict(metrics),
            rationale=rationale,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "signal_id": self.signal_id,
            "signal_type": self.signal_type,
            "severity": self.severity,
            "subject": self.subject,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "evidence_ids": list(self.evidence_ids),
            "evidence_count": self.evidence_count,
            "metrics": self.metrics,
            "rationale": self.rationale,
            "authority": self.authority,
            "ground_truth_used": self.ground_truth_used,
            "analyzer_version": self.analyzer_version,
        }


@dataclass(frozen=True)
class NetworkSecurityIntelligenceConfig:
    max_records: int = 50_000
    window_seconds: int = 60
    port_scan_distinct_ports: int = 12
    host_fanout_distinct_destinations: int = 16
    burst_flow_count: int = 100
    beacon_min_samples: int = 6
    beacon_min_period_seconds: float = 5.0
    beacon_max_period_seconds: float = 3600.0
    beacon_max_cv: float = 0.15
    large_outbound_bytes: int = 50 * 1024 * 1024
    large_outbound_source_ratio: float = 0.85

    def __post_init__(self) -> None:
        positive_ints = (
            self.max_records,
            self.window_seconds,
            self.port_scan_distinct_ports,
            self.host_fanout_distinct_destinations,
            self.burst_flow_count,
            self.beacon_min_samples,
            self.large_outbound_bytes,
        )
        if any(isinstance(value, bool) or value <= 0 for value in positive_ints):
            raise NetworkSecurityIntelligenceError("integer analysis bounds must be positive")
        if self.max_records > 250_000:
            raise NetworkSecurityIntelligenceError("max_records may not exceed 250000")
        if not 0.0 <= self.beacon_max_cv <= 1.0:
            raise NetworkSecurityIntelligenceError("beacon_max_cv must be 0..1")
        if not 0.0 < self.large_outbound_source_ratio <= 1.0:
            raise NetworkSecurityIntelligenceError("large_outbound_source_ratio must be 0..1")
        if self.beacon_min_period_seconds <= 0:
            raise NetworkSecurityIntelligenceError("beacon_min_period_seconds must be > 0")
        if self.beacon_max_period_seconds < self.beacon_min_period_seconds:
            raise NetworkSecurityIntelligenceError("beacon period bounds are invalid")


class NetworkSecurityIntelligenceAnalyzer:
    """Truth-free deterministic deep-flow signal extraction.

    Inputs are visible EvidenceRecord objects only. Signals are evidence-backed
    advisory observations, not attack verdicts and never remediation authority.
    """

    def __init__(self, config: NetworkSecurityIntelligenceConfig | None = None):
        self.config = config or NetworkSecurityIntelligenceConfig()

    def _views(self, records: Iterable[EvidenceRecord]) -> list[FlowView]:
        views: list[FlowView] = []
        for record in records:
            view = FlowView.from_evidence(record)
            if view is None:
                continue
            if len(views) >= self.config.max_records:
                raise NetworkSecurityIntelligenceError("analysis record budget exceeded")
            views.append(view)
        views.sort(key=lambda item: (item.timestamp, item.evidence_id))
        return views

    def analyze(self, records: Iterable[EvidenceRecord]) -> tuple[NetworkSecuritySignal, ...]:
        views = self._views(records)
        if not views:
            return ()
        signals: list[NetworkSecuritySignal] = []
        signals.extend(self._large_outbound(views))
        signals.extend(self._windowed_behavior(views))
        signals.extend(self._beaconing(views))
        signals.sort(key=lambda item: (item.window_start, item.signal_type, item.subject, item.signal_id))
        return tuple(signals)

    def _large_outbound(self, views: list[FlowView]) -> list[NetworkSecuritySignal]:
        result: list[NetworkSecuritySignal] = []
        for item in views:
            if item.total_bytes is None or item.source_bytes is None or item.total_bytes <= 0:
                continue
            ratio = item.source_bytes / item.total_bytes
            if item.source_bytes < self.config.large_outbound_bytes or ratio < self.config.large_outbound_source_ratio:
                continue
            result.append(
                NetworkSecuritySignal.build(
                    signal_type="LARGE_OUTBOUND_TRANSFER",
                    severity="MEDIUM",
                    subject=item.source_address,
                    window_start=item.timestamp,
                    window_end=item.timestamp,
                    evidence_ids=[item.evidence_id],
                    evidence_count=1,
                    metrics={
                        "source_bytes": int(item.source_bytes),
                        "total_bytes": int(item.total_bytes),
                        "source_byte_ratio": round(ratio, 6),
                        "destination_address": item.destination_address,
                        "destination_port": item.destination_port,
                    },
                    rationale=(
                        "A single flow exceeded the configured outbound byte and source-byte-ratio thresholds. "
                        "This is a transfer signal, not a confirmed exfiltration verdict."
                    ),
                )
            )
        return result

    def _windowed_behavior(self, views: list[FlowView]) -> list[NetworkSecuritySignal]:
        buckets: dict[tuple[str, int], list[FlowView]] = defaultdict(list)
        for item in views:
            bucket_id = int(_stable_epoch_seconds(item.timestamp)) // self.config.window_seconds
            buckets[(item.source_address, bucket_id)].append(item)

        result: list[NetworkSecuritySignal] = []
        for (source, _bucket_id), items in sorted(buckets.items()):
            start = items[0].timestamp
            end = items[-1].timestamp
            sample_ids = [item.evidence_id for item in items[:64]]
            if len(items) >= self.config.burst_flow_count:
                result.append(
                    NetworkSecuritySignal.build(
                        signal_type="FLOW_BURST",
                        severity="MEDIUM",
                        subject=source,
                        window_start=start,
                        window_end=end,
                        evidence_ids=sample_ids,
                        evidence_count=len(items),
                        metrics={"flow_count": len(items), "window_seconds": self.config.window_seconds},
                        rationale="The source emitted an unusually dense flow burst under the configured deterministic threshold.",
                    )
                )

            per_dst_ports: dict[str, set[str]] = defaultdict(set)
            per_port_dsts: dict[str, set[str]] = defaultdict(set)
            per_dst_ids: dict[str, list[str]] = defaultdict(list)
            per_port_ids: dict[str, list[str]] = defaultdict(list)
            for item in items:
                if not item.destination_port:
                    continue
                per_dst_ports[item.destination_address].add(item.destination_port)
                if len(per_dst_ids[item.destination_address]) < 64:
                    per_dst_ids[item.destination_address].append(item.evidence_id)
                per_port_dsts[item.destination_port].add(item.destination_address)
                if len(per_port_ids[item.destination_port]) < 64:
                    per_port_ids[item.destination_port].append(item.evidence_id)

            for destination, ports in sorted(per_dst_ports.items()):
                if len(ports) >= self.config.port_scan_distinct_ports:
                    result.append(
                        NetworkSecuritySignal.build(
                            signal_type="VERTICAL_PORT_FANOUT",
                            severity="HIGH",
                            subject=source,
                            window_start=start,
                            window_end=end,
                            evidence_ids=per_dst_ids[destination],
                            evidence_count=sum(1 for item in items if item.destination_address == destination),
                            metrics={
                                "destination_address": destination,
                                "distinct_destination_ports": len(ports),
                                "window_seconds": self.config.window_seconds,
                            },
                            rationale=(
                                "The source contacted many distinct destination ports on one host inside a bounded window. "
                                "Treat as scan-like behavior pending corroboration."
                            ),
                        )
                    )

            for destination_port, destinations in sorted(per_port_dsts.items()):
                if len(destinations) >= self.config.host_fanout_distinct_destinations:
                    result.append(
                        NetworkSecuritySignal.build(
                            signal_type="HORIZONTAL_HOST_FANOUT",
                            severity="HIGH",
                            subject=source,
                            window_start=start,
                            window_end=end,
                            evidence_ids=per_port_ids[destination_port],
                            evidence_count=sum(1 for item in items if item.destination_port == destination_port),
                            metrics={
                                "destination_port": destination_port,
                                "distinct_destinations": len(destinations),
                                "window_seconds": self.config.window_seconds,
                            },
                            rationale=(
                                "The source contacted the same destination port across many hosts inside a bounded window. "
                                "Treat as host-discovery/scan-like behavior pending corroboration."
                            ),
                        )
                    )
        return result

    def _beaconing(self, views: list[FlowView]) -> list[NetworkSecuritySignal]:
        groups: dict[tuple[str, str, str | None, str | None], list[FlowView]] = defaultdict(list)
        for item in views:
            groups[(item.source_address, item.destination_address, item.destination_port, item.protocol)].append(item)

        result: list[NetworkSecuritySignal] = []
        for key, items in sorted(groups.items(), key=lambda pair: tuple(str(x) for x in pair[0])):
            if len(items) < self.config.beacon_min_samples:
                continue
            intervals = [
                (right.timestamp - left.timestamp).total_seconds()
                for left, right in zip(items, items[1:])
            ]
            if not intervals or any(value <= 0 for value in intervals):
                continue
            mean = sum(intervals) / len(intervals)
            if not self.config.beacon_min_period_seconds <= mean <= self.config.beacon_max_period_seconds:
                continue
            variance = sum((value - mean) ** 2 for value in intervals) / len(intervals)
            cv = math.sqrt(variance) / mean
            if cv > self.config.beacon_max_cv:
                continue
            source, destination, destination_port, protocol = key
            result.append(
                NetworkSecuritySignal.build(
                    signal_type="PERIODIC_FLOW_PATTERN",
                    severity="MEDIUM",
                    subject=source,
                    window_start=items[0].timestamp,
                    window_end=items[-1].timestamp,
                    evidence_ids=[item.evidence_id for item in items[:64]],
                    evidence_count=len(items),
                    metrics={
                        "destination_address": destination,
                        "destination_port": destination_port,
                        "protocol": protocol,
                        "samples": len(items),
                        "mean_period_seconds": round(mean, 6),
                        "period_cv": round(cv, 6),
                    },
                    rationale=(
                        "Repeated flows to the same peer have low timing variance under the configured thresholds. "
                        "This is beacon-like periodicity, not proof of command-and-control activity."
                    ),
                )
            )
        return result
