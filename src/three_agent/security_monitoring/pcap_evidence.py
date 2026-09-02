from __future__ import annotations

import hashlib
import os
import re
import struct
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Iterable

from .contracts import canonical_json, sha256_fingerprint

PCAP_RESOURCE_SCHEMA = "workspace-security-monitoring/pcap-resource-v1"
PCAP_PACKET_EVIDENCE_SCHEMA = "workspace-security-monitoring/pcap-packet-evidence-v1"
PCAP_CAPTURE_EVIDENCE_SCHEMA = "workspace-security-monitoring/pcap-capture-evidence-v1"

DEFAULT_MAX_PCAP_BYTES = 32 * 1024 * 1024
DEFAULT_MAX_PCAP_PACKETS = 4096
DEFAULT_MAX_PACKET_BYTES = 1024 * 1024
MAX_RESOURCE_REF_LENGTH = 128
MAX_RELATIVE_PATH_LENGTH = 240

_RESOURCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# Classic libpcap magic values. pcapng is intentionally not admitted in v0.7.
_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("little", "microsecond", "<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": ("big", "microsecond", ">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("little", "nanosecond", "<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": ("big", "nanosecond", ">", 1_000_000_000),
}


class PCAPEvidenceError(ValueError):
    """A trusted PCAP resource or classic-PCAP structure is invalid."""


class PCAPEvidenceDenied(PermissionError):
    """The requested resource is not admitted by the trusted PCAP registry."""

    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _resource_ref(value: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > MAX_RESOURCE_REF_LENGTH or not _RESOURCE_RE.fullmatch(text):
        raise PCAPEvidenceError("pcap resource_ref must be a compact identifier")
    if "://" in text or ".." in PurePosixPath(text).parts:
        raise PCAPEvidenceError("pcap resource_ref must not escape its trust domain")
    return text


def _relative_path(value: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    if not text or len(text) > MAX_RELATIVE_PATH_LENGTH:
        raise PCAPEvidenceError("pcap relative_path is invalid")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts or path.as_posix() in {"", "."}:
        raise PCAPEvidenceError("pcap relative_path must be safe and relative")
    if any(part in {"", "."} for part in path.parts):
        raise PCAPEvidenceError("pcap relative_path contains an invalid segment")
    return path.as_posix()


def _bounded_int(value: int, field_name: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PCAPEvidenceError(f"{field_name} must be within {minimum}..{maximum}")
    return value


@dataclass(frozen=True)
class PCAPResource:
    resource_ref: str
    relative_path: str
    max_file_bytes: int = DEFAULT_MAX_PCAP_BYTES
    max_packets: int = DEFAULT_MAX_PCAP_PACKETS
    max_packet_bytes: int = DEFAULT_MAX_PACKET_BYTES
    schema_version: str = PCAP_RESOURCE_SCHEMA

    def validate(self) -> "PCAPResource":
        object.__setattr__(self, "resource_ref", _resource_ref(self.resource_ref))
        object.__setattr__(self, "relative_path", _relative_path(self.relative_path))
        object.__setattr__(
            self,
            "max_file_bytes",
            _bounded_int(self.max_file_bytes, "max_file_bytes", 24, 256 * 1024 * 1024),
        )
        object.__setattr__(self, "max_packets", _bounded_int(self.max_packets, "max_packets", 1, 100_000))
        object.__setattr__(
            self,
            "max_packet_bytes",
            _bounded_int(self.max_packet_bytes, "max_packet_bytes", 64, 16 * 1024 * 1024),
        )
        if self.max_packet_bytes > self.max_file_bytes:
            raise PCAPEvidenceError("max_packet_bytes cannot exceed max_file_bytes")
        if self.schema_version != PCAP_RESOURCE_SCHEMA:
            raise PCAPEvidenceError("unsupported PCAP resource schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        # The relative path is trusted runtime configuration and is intentionally not
        # exposed through request/receipt/audit surfaces. Only its digest is exported.
        return {
            "schema_version": self.schema_version,
            "resource_ref": self.resource_ref,
            "relative_path_sha256": "sha256:" + hashlib.sha256(self.relative_path.encode("utf-8")).hexdigest(),
            "max_file_bytes": self.max_file_bytes,
            "max_packets": self.max_packets,
            "max_packet_bytes": self.max_packet_bytes,
        }


class PCAPResourceRegistry:
    """Trusted resource-id -> bounded local file mapping under one immutable root."""

    def __init__(self, trusted_root: str | Path, resources: Iterable[PCAPResource]) -> None:
        root = Path(trusted_root)
        if not root.is_absolute():
            raise PCAPEvidenceError("trusted_root must be absolute")
        if root.exists() and root.is_symlink():
            raise PCAPEvidenceError("trusted_root symlink is denied")
        self.trusted_root = root
        rows = tuple(resource.validate() for resource in resources)
        refs = [row.resource_ref for row in rows]
        if not rows:
            raise PCAPEvidenceError("PCAP registry requires at least one trusted resource")
        if len(refs) != len(set(refs)):
            raise PCAPEvidenceError("duplicate PCAP resource_ref")
        paths = [row.relative_path for row in rows]
        if len(paths) != len(set(paths)):
            raise PCAPEvidenceError("duplicate PCAP relative_path")
        self._resources = {row.resource_ref: row for row in rows}

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(
            {
                "trusted_root_sha256": "sha256:"
                + hashlib.sha256(str(self.trusted_root).encode("utf-8")).hexdigest(),
                "resources": [self._resources[key].public_dict() for key in sorted(self._resources)],
            }
        )

    def resolve(self, resource_ref: str) -> tuple[PCAPResource, Path]:
        ref = _resource_ref(resource_ref)
        resource = self._resources.get(ref)
        if resource is None:
            raise PCAPEvidenceDenied("PCAP_RESOURCE_NOT_TRUSTED")
        root = self.trusted_root
        if not root.exists() or not root.is_dir() or root.is_symlink():
            raise PCAPEvidenceDenied("PCAP_TRUSTED_ROOT_UNAVAILABLE")
        path = root.joinpath(*PurePosixPath(resource.relative_path).parts)
        self._deny_symlink_components(root, path)
        if not path.exists():
            raise PCAPEvidenceDenied("PCAP_RESOURCE_MISSING")
        if path.is_symlink():
            raise PCAPEvidenceDenied("PCAP_RESOURCE_SYMLINK_DENIED")
        if not path.is_file():
            raise PCAPEvidenceDenied("PCAP_RESOURCE_NOT_REGULAR_FILE")
        resolved_root = root.resolve(strict=True)
        resolved_path = path.resolve(strict=True)
        try:
            resolved_path.relative_to(resolved_root)
        except ValueError as exc:
            raise PCAPEvidenceDenied("PCAP_RESOURCE_OUTSIDE_TRUSTED_ROOT") from exc
        return resource, resolved_path

    @staticmethod
    def _deny_symlink_components(root: Path, path: Path) -> None:
        current = root
        relative = path.relative_to(root)
        for part in relative.parts:
            current = current / part
            if current.is_symlink():
                raise PCAPEvidenceDenied("PCAP_RESOURCE_SYMLINK_DENIED")


@dataclass(frozen=True)
class PCAPPacketEvidence:
    packet_index: int
    timestamp_epoch_ns: int
    captured_length: int
    original_length: int
    payload_sha256: str
    schema_version: str = PCAP_PACKET_EVIDENCE_SCHEMA

    def validate(self) -> "PCAPPacketEvidence":
        _bounded_int(self.packet_index, "packet_index", 1, 100_000)
        if isinstance(self.timestamp_epoch_ns, bool) or not isinstance(self.timestamp_epoch_ns, int) or self.timestamp_epoch_ns < 0:
            raise PCAPEvidenceError("timestamp_epoch_ns must be a non-negative integer")
        _bounded_int(self.captured_length, "captured_length", 0, 16 * 1024 * 1024)
        _bounded_int(self.original_length, "original_length", 0, 64 * 1024 * 1024)
        if self.original_length < self.captured_length:
            raise PCAPEvidenceError("original_length cannot be smaller than captured_length")
        if not _SHA256_RE.fullmatch(self.payload_sha256):
            raise PCAPEvidenceError("packet payload_sha256 is invalid")
        if self.schema_version != PCAP_PACKET_EVIDENCE_SCHEMA:
            raise PCAPEvidenceError("unsupported packet evidence schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class PCAPCaptureEvidence:
    resource_ref: str
    mode: str
    file_sha256: str
    file_size_bytes: int
    byte_order: str
    timestamp_resolution: str
    version_major: int
    version_minor: int
    snaplen: int
    linktype: int
    packet_count: int
    total_captured_bytes: int
    total_original_bytes: int
    first_timestamp_epoch_ns: int | None
    last_timestamp_epoch_ns: int | None
    packets: tuple[PCAPPacketEvidence, ...]
    bounded_complete: bool = True
    schema_version: str = PCAP_CAPTURE_EVIDENCE_SCHEMA

    def validate(self) -> "PCAPCaptureEvidence":
        object.__setattr__(self, "resource_ref", _resource_ref(self.resource_ref))
        if self.mode not in {"capture", "metadata"}:
            raise PCAPEvidenceError("unsupported PCAP evidence mode")
        if not _SHA256_RE.fullmatch(self.file_sha256):
            raise PCAPEvidenceError("file_sha256 is invalid")
        _bounded_int(self.file_size_bytes, "file_size_bytes", 24, 256 * 1024 * 1024)
        if self.byte_order not in {"little", "big"}:
            raise PCAPEvidenceError("unsupported PCAP byte_order")
        if self.timestamp_resolution not in {"microsecond", "nanosecond"}:
            raise PCAPEvidenceError("unsupported PCAP timestamp_resolution")
        if (self.version_major, self.version_minor) != (2, 4):
            raise PCAPEvidenceError("only classic PCAP version 2.4 is admitted")
        _bounded_int(self.snaplen, "snaplen", 1, 16 * 1024 * 1024)
        _bounded_int(self.linktype, "linktype", 0, 0xFFFFFFFF)
        _bounded_int(self.packet_count, "packet_count", 0, 100_000)
        if isinstance(self.total_captured_bytes, bool) or not isinstance(self.total_captured_bytes, int) or self.total_captured_bytes < 0:
            raise PCAPEvidenceError("total_captured_bytes is invalid")
        if isinstance(self.total_original_bytes, bool) or not isinstance(self.total_original_bytes, int) or self.total_original_bytes < self.total_captured_bytes:
            raise PCAPEvidenceError("total_original_bytes is invalid")
        if self.packet_count == 0:
            if self.first_timestamp_epoch_ns is not None or self.last_timestamp_epoch_ns is not None:
                raise PCAPEvidenceError("empty PCAP cannot expose packet timestamps")
        else:
            if self.first_timestamp_epoch_ns is None or self.last_timestamp_epoch_ns is None:
                raise PCAPEvidenceError("non-empty PCAP requires first/last timestamps")
            if self.first_timestamp_epoch_ns > self.last_timestamp_epoch_ns:
                raise PCAPEvidenceError("PCAP timestamps are not monotonic at summary boundary")
        if self.mode == "metadata" and self.packets:
            raise PCAPEvidenceError("metadata mode cannot expose packet records")
        if self.mode == "capture" and len(self.packets) != self.packet_count:
            raise PCAPEvidenceError("capture mode packet records must match packet_count")
        if any(packet.packet_index != index for index, packet in enumerate(self.packets, 1)):
            raise PCAPEvidenceError("packet evidence indices must be contiguous")
        for packet in self.packets:
            packet.validate()
        if not self.bounded_complete:
            raise PCAPEvidenceError("v0.7 never returns partial PCAP evidence as complete")
        if self.schema_version != PCAP_CAPTURE_EVIDENCE_SCHEMA:
            raise PCAPEvidenceError("unsupported PCAP capture evidence schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "resource_ref": self.resource_ref,
            "mode": self.mode,
            "file_sha256": self.file_sha256,
            "file_size_bytes": self.file_size_bytes,
            "byte_order": self.byte_order,
            "timestamp_resolution": self.timestamp_resolution,
            "version_major": self.version_major,
            "version_minor": self.version_minor,
            "snaplen": self.snaplen,
            "linktype": self.linktype,
            "packet_count": self.packet_count,
            "total_captured_bytes": self.total_captured_bytes,
            "total_original_bytes": self.total_original_bytes,
            "first_timestamp_epoch_ns": self.first_timestamp_epoch_ns,
            "last_timestamp_epoch_ns": self.last_timestamp_epoch_ns,
            "packets": [packet.public_dict() for packet in self.packets],
            "bounded_complete": self.bounded_complete,
        }

    def to_json(self) -> str:
        return canonical_json(self.public_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


class BoundedPCAPEvidenceReader:
    """Pure classic-PCAP reader: no subprocess, packet capture, network or mutation."""

    def __init__(self, registry: PCAPResourceRegistry) -> None:
        if not isinstance(registry, PCAPResourceRegistry):
            raise PCAPEvidenceError("PCAP reader requires PCAPResourceRegistry")
        self.registry = registry

    def read_capture(self, resource_ref: str) -> PCAPCaptureEvidence:
        return self._read(resource_ref, mode="capture")

    def read_metadata(self, resource_ref: str) -> PCAPCaptureEvidence:
        return self._read(resource_ref, mode="metadata")

    def _read(self, resource_ref: str, *, mode: str) -> PCAPCaptureEvidence:
        resource, path = self.registry.resolve(resource_ref)
        stat = path.stat()
        if stat.st_size < 24:
            raise PCAPEvidenceError("PCAP_FILE_TOO_SMALL")
        if stat.st_size > resource.max_file_bytes:
            raise PCAPEvidenceError("PCAP_FILE_BOUND_EXCEEDED")
        # Re-check immediately before open to reduce path-replacement races. O_NOFOLLOW
        # prevents the final component from becoming a symlink between validation/open.
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags)
        try:
            opened = os.fstat(fd)
            if opened.st_size != stat.st_size or opened.st_ino != stat.st_ino or opened.st_dev != stat.st_dev:
                raise PCAPEvidenceDenied("PCAP_RESOURCE_CHANGED_BEFORE_READ")
            if opened.st_size > resource.max_file_bytes:
                raise PCAPEvidenceError("PCAP_FILE_BOUND_EXCEEDED")
            data = b""
            remaining = opened.st_size
            while remaining:
                chunk = os.read(fd, min(1024 * 1024, remaining))
                if not chunk:
                    raise PCAPEvidenceError("PCAP_FILE_TRUNCATED_DURING_READ")
                data += chunk
                remaining -= len(chunk)
        finally:
            os.close(fd)
        if len(data) != stat.st_size:
            raise PCAPEvidenceError("PCAP_FILE_SIZE_CHANGED_DURING_READ")
        return self._parse(resource, data, mode=mode)

    @staticmethod
    def _parse(resource: PCAPResource, data: bytes, *, mode: str) -> PCAPCaptureEvidence:
        magic = data[:4]
        descriptor = _MAGIC.get(magic)
        if descriptor is None:
            raise PCAPEvidenceError("PCAP_MAGIC_UNSUPPORTED")
        byte_order, resolution, endian, fraction_base = descriptor
        if len(data) < 24:
            raise PCAPEvidenceError("PCAP_GLOBAL_HEADER_TRUNCATED")
        version_major, version_minor, _thiszone, _sigfigs, snaplen, linktype = struct.unpack(
            endian + "HHiIII", data[4:24]
        )
        if (version_major, version_minor) != (2, 4):
            raise PCAPEvidenceError("PCAP_VERSION_UNSUPPORTED")
        if not 1 <= snaplen <= resource.max_packet_bytes:
            raise PCAPEvidenceError("PCAP_SNAPLEN_BOUND_EXCEEDED")

        offset = 24
        packet_index = 0
        packet_records: list[PCAPPacketEvidence] = []
        total_captured = 0
        total_original = 0
        first_timestamp: int | None = None
        last_timestamp: int | None = None
        while offset < len(data):
            if len(data) - offset < 16:
                raise PCAPEvidenceError("PCAP_PACKET_HEADER_TRUNCATED")
            ts_sec, ts_fraction, captured_len, original_len = struct.unpack(
                endian + "IIII", data[offset : offset + 16]
            )
            offset += 16
            packet_index += 1
            if packet_index > resource.max_packets:
                raise PCAPEvidenceError("PCAP_PACKET_COUNT_BOUND_EXCEEDED")
            if ts_fraction >= fraction_base:
                raise PCAPEvidenceError("PCAP_TIMESTAMP_FRACTION_INVALID")
            if captured_len > snaplen or captured_len > resource.max_packet_bytes:
                raise PCAPEvidenceError("PCAP_PACKET_LENGTH_BOUND_EXCEEDED")
            if original_len < captured_len:
                raise PCAPEvidenceError("PCAP_ORIGINAL_LENGTH_INVALID")
            if len(data) - offset < captured_len:
                raise PCAPEvidenceError("PCAP_PACKET_PAYLOAD_TRUNCATED")
            payload = data[offset : offset + captured_len]
            offset += captured_len
            timestamp_ns = ts_sec * 1_000_000_000 + (
                ts_fraction * 1_000 if resolution == "microsecond" else ts_fraction
            )
            if last_timestamp is not None and timestamp_ns < last_timestamp:
                raise PCAPEvidenceError("PCAP_PACKET_TIMESTAMP_ORDER_INVALID")
            if first_timestamp is None:
                first_timestamp = timestamp_ns
            last_timestamp = timestamp_ns
            total_captured += captured_len
            total_original += original_len
            if mode == "capture":
                packet_records.append(
                    PCAPPacketEvidence(
                        packet_index=packet_index,
                        timestamp_epoch_ns=timestamp_ns,
                        captured_length=captured_len,
                        original_length=original_len,
                        payload_sha256="sha256:" + hashlib.sha256(payload).hexdigest(),
                    ).validate()
                )
        if offset != len(data):
            raise PCAPEvidenceError("PCAP_TRAILING_STRUCTURE_INVALID")
        return PCAPCaptureEvidence(
            resource_ref=resource.resource_ref,
            mode=mode,
            file_sha256="sha256:" + hashlib.sha256(data).hexdigest(),
            file_size_bytes=len(data),
            byte_order=byte_order,
            timestamp_resolution=resolution,
            version_major=version_major,
            version_minor=version_minor,
            snaplen=snaplen,
            linktype=linktype,
            packet_count=packet_index,
            total_captured_bytes=total_captured,
            total_original_bytes=total_original,
            first_timestamp_epoch_ns=first_timestamp,
            last_timestamp_epoch_ns=last_timestamp,
            packets=tuple(packet_records),
        ).validate()
