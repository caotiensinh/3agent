from __future__ import annotations

import hashlib
import ipaddress
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .contracts import CanonicalEvent, MonitoringContractError, _compact, sha256_fingerprint
from .log_pipeline import EvidencePartitionReceipt, EvidencePartitionWriter
from .parsers import QuarantinedRecord, parse_syslog_line
from .storage import MonitoringStore


@dataclass(frozen=True)
class SourceMapping:
    source_id: str
    source_type: str
    sender_address: str
    expected_interval_seconds: int = 300

    def validate(self) -> "SourceMapping":
        object.__setattr__(self, "source_id", _compact(self.source_id, "source_id", max_len=128))
        if self.source_type not in {"syslog", "suricata_eve", "zeek_json", "workspace_audit"}:
            raise MonitoringContractError("unsupported source_type")
        try:
            normalized = str(ipaddress.ip_address(self.sender_address))
        except ValueError as exc:
            raise MonitoringContractError("sender_address must be an exact IP address") from exc
        object.__setattr__(self, "sender_address", normalized)
        if not 1 <= self.expected_interval_seconds <= 86400:
            raise MonitoringContractError("expected_interval_seconds out of range")
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(
            {
                "source_id": self.source_id,
                "source_type": self.source_type,
                "sender_address": self.sender_address,
                "expected_interval_seconds": self.expected_interval_seconds,
            }
        )


class TrustedSourceRegistry:
    """Exact sender-IP mapping. Discovery/model inference never creates trusted sources."""

    def __init__(self, mappings: tuple[SourceMapping, ...]):
        validated = tuple(mapping.validate() for mapping in mappings)
        sender_keys = [(m.source_type, m.sender_address) for m in validated]
        ids = [m.source_id for m in validated]
        if len(sender_keys) != len(set(sender_keys)) or len(ids) != len(set(ids)):
            raise MonitoringContractError("duplicate trusted source mapping")
        self.mappings = validated
        self._by_sender = {(m.source_type, m.sender_address): m for m in validated}

    def resolve(self, *, source_type: str, sender_address: str) -> SourceMapping:
        try:
            sender = str(ipaddress.ip_address(sender_address))
        except ValueError as exc:
            raise PermissionError("SOURCE_SENDER_INVALID") from exc
        mapping = self._by_sender.get((source_type, sender))
        if mapping is None:
            raise PermissionError("SOURCE_NOT_APPROVED")
        return mapping


@dataclass(frozen=True)
class IngestReceipt:
    source_id: str
    source_mapping_fingerprint: str
    input_sha256: str
    input_bytes: int
    lines_seen: int
    events_accepted: int
    records_quarantined: int
    partition: EvidencePartitionReceipt | None
    status: str


class RsyslogSpoolIngestor:
    """Consume one root-owned/local rsyslog file with hard input bounds."""

    def __init__(
        self,
        *,
        store: MonitoringStore,
        partition_writer: EvidencePartitionWriter,
        max_input_bytes: int = 8 * 1024 * 1024,
        max_lines: int = 50000,
    ):
        if not 4096 <= max_input_bytes <= 128 * 1024 * 1024:
            raise ValueError("max_input_bytes out of range")
        if not 1 <= max_lines <= 200000:
            raise ValueError("max_lines out of range")
        self.store = store
        self.partition_writer = partition_writer
        self.max_input_bytes = max_input_bytes
        self.max_lines = max_lines

    def ingest_file(
        self,
        *,
        path: str | Path,
        source: SourceMapping,
        partition_id: str,
        remove_on_success: bool = False,
    ) -> IngestReceipt:
        source.validate()
        if source.source_type != "syslog":
            raise MonitoringContractError("RsyslogSpoolIngestor requires source_type=syslog")
        input_path = Path(path)
        if input_path.is_symlink() or not input_path.is_file():
            raise MonitoringContractError("spool input must be a regular non-symlink file")
        size = input_path.stat().st_size
        if size > self.max_input_bytes:
            raise MonitoringContractError("spool input byte bound exceeded")
        raw = input_path.read_bytes()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        lines = raw.decode("utf-8", errors="replace").splitlines()
        if len(lines) > self.max_lines:
            raise MonitoringContractError("spool input line bound exceeded")

        events: list[CanonicalEvent] = []
        quarantined = 0
        self.store.initialize()
        for line in lines:
            record = parse_syslog_line(source_id=source.source_id, line=line)
            if isinstance(record, QuarantinedRecord):
                self.store.add_quarantine(record)
                quarantined += 1
            else:
                self.store.add_event(record)
                events.append(record)

        partition = self.partition_writer.write_events(partition_id=partition_id, events=events) if events else None
        if remove_on_success:
            input_path.unlink()
        status = "completed" if quarantined == 0 else "partial"
        return IngestReceipt(
            source_id=source.source_id,
            source_mapping_fingerprint=source.fingerprint,
            input_sha256=digest,
            input_bytes=size,
            lines_seen=len(lines),
            events_accepted=len(events),
            records_quarantined=quarantined,
            partition=partition,
            status=status,
        )
