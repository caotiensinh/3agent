from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, _compact, sha256_fingerprint

DEVICE_CONFIG_SECTION_SCHEMA = "workspace-security-monitoring/device-config-section-digest-v1"
DEVICE_CONFIG_SNAPSHOT_SCHEMA = "workspace-security-monitoring/device-config-snapshot-v1"
DEVICE_CONFIG_DIFF_SCHEMA = "workspace-security-monitoring/device-config-diff-v1"
DEVICE_CONFIG_HISTORY_SCHEMA = "workspace-security-monitoring/device-config-history-v1"

MAX_CONFIG_SECTIONS = 128
MAX_CONFIG_HISTORY_SNAPSHOTS = 256
MAX_SECTION_ITEM_COUNT = 1_000_000

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_SNAPSHOT_ID_RE = re.compile(r"^config-snapshot:[0-9a-f]{24}$")
_DIFF_ID_RE = re.compile(r"^config-diff:[0-9a-f]{24}$")


def _sha256(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be SHA-256")
    return text


def _timestamp(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed.isoformat()


def _instant(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


@dataclass(frozen=True)
class DeviceConfigSectionDigest:
    """Metadata-only digest for one reviewed device configuration section."""

    section: str
    content_sha256: str
    item_count: int
    schema_version: str = DEVICE_CONFIG_SECTION_SCHEMA

    def validate(self) -> "DeviceConfigSectionDigest":
        object.__setattr__(self, "section", _compact(self.section, "section", max_len=96))
        object.__setattr__(self, "content_sha256", _sha256(self.content_sha256, "content_sha256"))
        if (
            isinstance(self.item_count, bool)
            or not isinstance(self.item_count, int)
            or not 0 <= self.item_count <= MAX_SECTION_ITEM_COUNT
        ):
            raise MonitoringContractError("item_count is out of bounds")
        if self.schema_version != DEVICE_CONFIG_SECTION_SCHEMA:
            raise MonitoringContractError("unsupported device configuration section schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class DeviceConfigSnapshot:
    """Immutable, evidence-bound identity for one approved device configuration.

    This contract deliberately cannot carry raw configuration text, command output,
    credentials, host targets, or acquisition instructions. A separately authorized
    trusted producer hashes reviewed sections and submits only bounded metadata.
    """

    snapshot_id: str
    asset_id: str
    captured_at: str
    source_type: str
    producer: str
    task_ref_sha256: str
    authorization_ref_sha256: str
    source_record_sha256: str
    sections: tuple[DeviceConfigSectionDigest, ...]
    authority: str = "evidence_only"
    raw_config_retained: bool = False
    schema_version: str = DEVICE_CONFIG_SNAPSHOT_SCHEMA

    @classmethod
    def build(
        cls,
        *,
        asset_id: str,
        captured_at: str,
        source_type: str,
        producer: str,
        task_ref_sha256: str,
        authorization_ref_sha256: str,
        source_record_sha256: str,
        sections: Iterable[DeviceConfigSectionDigest],
    ) -> "DeviceConfigSnapshot":
        provisional = cls(
            snapshot_id="config-snapshot:" + "0" * 24,
            asset_id=asset_id,
            captured_at=captured_at,
            source_type=source_type,
            producer=producer,
            task_ref_sha256=task_ref_sha256,
            authorization_ref_sha256=authorization_ref_sha256,
            source_record_sha256=source_record_sha256,
            sections=tuple(sections),
        )
        provisional._validate_fields(check_id=False)
        snapshot_id = "config-snapshot:" + provisional.identity_sha256.split(":", 1)[1][:24]
        return cls(**{**provisional.__dict__, "snapshot_id": snapshot_id}).validate()

    def _validate_fields(self, *, check_id: bool) -> "DeviceConfigSnapshot":
        if self.schema_version != DEVICE_CONFIG_SNAPSHOT_SCHEMA:
            raise MonitoringContractError("unsupported device configuration snapshot schema")
        if self.authority != "evidence_only":
            raise MonitoringContractError("device configuration snapshot must remain evidence_only")
        if self.raw_config_retained is not False:
            raise MonitoringContractError("raw device configuration retention is forbidden")
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id", max_len=128))
        object.__setattr__(self, "captured_at", _timestamp(self.captured_at, "captured_at"))
        object.__setattr__(self, "source_type", _compact(self.source_type, "source_type", max_len=64))
        object.__setattr__(self, "producer", _compact(self.producer, "producer", max_len=96))
        object.__setattr__(self, "task_ref_sha256", _sha256(self.task_ref_sha256, "task_ref_sha256"))
        object.__setattr__(
            self,
            "authorization_ref_sha256",
            _sha256(self.authorization_ref_sha256, "authorization_ref_sha256"),
        )
        object.__setattr__(
            self,
            "source_record_sha256",
            _sha256(self.source_record_sha256, "source_record_sha256"),
        )
        sections = tuple(section.validate() for section in self.sections)
        if not sections:
            raise MonitoringContractError("device configuration snapshot requires section digests")
        if len(sections) > MAX_CONFIG_SECTIONS:
            raise MonitoringContractError("device configuration section bound exceeded")
        names = [section.section for section in sections]
        if len(names) != len(set(names)):
            raise MonitoringContractError("device configuration section names must be unique")
        object.__setattr__(self, "sections", tuple(sorted(sections, key=lambda row: row.section)))
        if check_id:
            if not _SNAPSHOT_ID_RE.fullmatch(str(self.snapshot_id or "")):
                raise MonitoringContractError("snapshot_id is invalid")
            expected = "config-snapshot:" + self.identity_sha256.split(":", 1)[1][:24]
            if self.snapshot_id != expected:
                raise MonitoringContractError("snapshot_id does not match snapshot content")
        return self

    def validate(self) -> "DeviceConfigSnapshot":
        return self._validate_fields(check_id=True)

    def identity_dict(self) -> dict[str, object]:
        self._validate_fields(check_id=False)
        return {
            "schema_version": self.schema_version,
            "asset_id": self.asset_id,
            "captured_at": self.captured_at,
            "source_type": self.source_type,
            "producer": self.producer,
            "task_ref_sha256": self.task_ref_sha256,
            "authorization_ref_sha256": self.authorization_ref_sha256,
            "source_record_sha256": self.source_record_sha256,
            "sections": [section.public_dict() for section in self.sections],
            "authority": self.authority,
            "raw_config_retained": self.raw_config_retained,
        }

    @property
    def identity_sha256(self) -> str:
        return sha256_fingerprint(self.identity_dict())

    @property
    def section_set_sha256(self) -> str:
        self._validate_fields(check_id=False)
        return sha256_fingerprint(
            {
                "asset_id": self.asset_id,
                "sections": [section.public_dict() for section in self.sections],
            }
        )

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {"snapshot_id": self.snapshot_id, **self.identity_dict()}


@dataclass(frozen=True)
class DeviceConfigDiff:
    """Deterministic metadata-only drift assessment between two snapshots."""

    diff_id: str
    asset_id: str
    base_snapshot_id: str
    target_snapshot_id: str
    base_captured_at: str
    target_captured_at: str
    added_sections: tuple[str, ...]
    removed_sections: tuple[str, ...]
    changed_sections: tuple[str, ...]
    unchanged_sections: tuple[str, ...]
    drift_detected: bool
    authority: str = "advisory"
    schema_version: str = DEVICE_CONFIG_DIFF_SCHEMA

    @classmethod
    def between(cls, base: DeviceConfigSnapshot, target: DeviceConfigSnapshot) -> "DeviceConfigDiff":
        base.validate()
        target.validate()
        if base.asset_id != target.asset_id:
            raise MonitoringContractError("device configuration diff requires the same asset")
        if _instant(target.captured_at) < _instant(base.captured_at):
            raise MonitoringContractError("target snapshot cannot precede base snapshot")

        base_sections = {row.section: row.content_sha256 for row in base.sections}
        target_sections = {row.section: row.content_sha256 for row in target.sections}
        base_names = set(base_sections)
        target_names = set(target_sections)
        shared = base_names & target_names
        added = tuple(sorted(target_names - base_names))
        removed = tuple(sorted(base_names - target_names))
        changed = tuple(sorted(name for name in shared if base_sections[name] != target_sections[name]))
        unchanged = tuple(sorted(name for name in shared if base_sections[name] == target_sections[name]))
        drift = bool(added or removed or changed)

        provisional = cls(
            diff_id="config-diff:" + "0" * 24,
            asset_id=base.asset_id,
            base_snapshot_id=base.snapshot_id,
            target_snapshot_id=target.snapshot_id,
            base_captured_at=base.captured_at,
            target_captured_at=target.captured_at,
            added_sections=added,
            removed_sections=removed,
            changed_sections=changed,
            unchanged_sections=unchanged,
            drift_detected=drift,
        )
        provisional._validate_fields(check_id=False)
        diff_id = "config-diff:" + provisional.identity_sha256.split(":", 1)[1][:24]
        return cls(**{**provisional.__dict__, "diff_id": diff_id}).validate()

    def _validate_fields(self, *, check_id: bool) -> "DeviceConfigDiff":
        if self.schema_version != DEVICE_CONFIG_DIFF_SCHEMA:
            raise MonitoringContractError("unsupported device configuration diff schema")
        if self.authority != "advisory":
            raise MonitoringContractError("device configuration diff must remain advisory")
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id", max_len=128))
        if not _SNAPSHOT_ID_RE.fullmatch(str(self.base_snapshot_id or "")):
            raise MonitoringContractError("base_snapshot_id is invalid")
        if not _SNAPSHOT_ID_RE.fullmatch(str(self.target_snapshot_id or "")):
            raise MonitoringContractError("target_snapshot_id is invalid")
        object.__setattr__(self, "base_captured_at", _timestamp(self.base_captured_at, "base_captured_at"))
        object.__setattr__(self, "target_captured_at", _timestamp(self.target_captured_at, "target_captured_at"))
        if _instant(self.target_captured_at) < _instant(self.base_captured_at):
            raise MonitoringContractError("target snapshot cannot precede base snapshot")
        groups: list[set[str]] = []
        for field_name in (
            "added_sections",
            "removed_sections",
            "changed_sections",
            "unchanged_sections",
        ):
            values = tuple(_compact(value, field_name, max_len=96) for value in getattr(self, field_name))
            if len(values) != len(set(values)) or values != tuple(sorted(values)):
                raise MonitoringContractError(f"{field_name} must be sorted and unique")
            object.__setattr__(self, field_name, values)
            groups.append(set(values))
        for index, left in enumerate(groups):
            for right in groups[index + 1 :]:
                if left & right:
                    raise MonitoringContractError("device configuration diff section groups must be disjoint")
        expected_drift = bool(self.added_sections or self.removed_sections or self.changed_sections)
        if not isinstance(self.drift_detected, bool) or self.drift_detected != expected_drift:
            raise MonitoringContractError("drift_detected does not match section changes")
        if check_id:
            if not _DIFF_ID_RE.fullmatch(str(self.diff_id or "")):
                raise MonitoringContractError("diff_id is invalid")
            expected = "config-diff:" + self.identity_sha256.split(":", 1)[1][:24]
            if self.diff_id != expected:
                raise MonitoringContractError("diff_id does not match diff content")
        return self

    def validate(self) -> "DeviceConfigDiff":
        return self._validate_fields(check_id=True)

    def identity_dict(self) -> dict[str, object]:
        self._validate_fields(check_id=False)
        return {
            "schema_version": self.schema_version,
            "asset_id": self.asset_id,
            "base_snapshot_id": self.base_snapshot_id,
            "target_snapshot_id": self.target_snapshot_id,
            "base_captured_at": self.base_captured_at,
            "target_captured_at": self.target_captured_at,
            "added_sections": list(self.added_sections),
            "removed_sections": list(self.removed_sections),
            "changed_sections": list(self.changed_sections),
            "unchanged_sections": list(self.unchanged_sections),
            "drift_detected": self.drift_detected,
            "authority": self.authority,
        }

    @property
    def identity_sha256(self) -> str:
        return sha256_fingerprint(self.identity_dict())

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {"diff_id": self.diff_id, **self.identity_dict()}


@dataclass(frozen=True)
class DeviceConfigHistory:
    """Bounded chronological history derived only from validated snapshots."""

    asset_id: str
    snapshots: tuple[DeviceConfigSnapshot, ...]
    diffs: tuple[DeviceConfigDiff, ...]
    authority: str = "evidence_only"
    schema_version: str = DEVICE_CONFIG_HISTORY_SCHEMA

    @classmethod
    def build(cls, snapshots: Iterable[DeviceConfigSnapshot]) -> "DeviceConfigHistory":
        unique: dict[str, DeviceConfigSnapshot] = {}
        for raw in snapshots:
            snapshot = raw.validate()
            previous = unique.get(snapshot.snapshot_id)
            if previous is not None and previous.public_dict() != snapshot.public_dict():
                raise MonitoringContractError("duplicate snapshot_id has conflicting content")
            unique[snapshot.snapshot_id] = snapshot
            if len(unique) > MAX_CONFIG_HISTORY_SNAPSHOTS:
                raise MonitoringContractError("device configuration history bound exceeded")
        if not unique:
            raise MonitoringContractError("device configuration history requires snapshots")
        ordered = tuple(sorted(unique.values(), key=lambda row: (_instant(row.captured_at), row.snapshot_id)))
        asset_ids = {row.asset_id for row in ordered}
        if len(asset_ids) != 1:
            raise MonitoringContractError("device configuration history must contain one asset")
        diffs = tuple(DeviceConfigDiff.between(left, right) for left, right in zip(ordered, ordered[1:]))
        return cls(asset_id=ordered[0].asset_id, snapshots=ordered, diffs=diffs).validate()

    def validate(self) -> "DeviceConfigHistory":
        if self.schema_version != DEVICE_CONFIG_HISTORY_SCHEMA:
            raise MonitoringContractError("unsupported device configuration history schema")
        if self.authority != "evidence_only":
            raise MonitoringContractError("device configuration history must remain evidence_only")
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id", max_len=128))
        if not 1 <= len(self.snapshots) <= MAX_CONFIG_HISTORY_SNAPSHOTS:
            raise MonitoringContractError("device configuration history snapshot count is out of bounds")
        snapshots = tuple(snapshot.validate() for snapshot in self.snapshots)
        if any(snapshot.asset_id != self.asset_id for snapshot in snapshots):
            raise MonitoringContractError("device configuration history asset mismatch")
        expected_order = tuple(sorted(snapshots, key=lambda row: (_instant(row.captured_at), row.snapshot_id)))
        if snapshots != expected_order:
            raise MonitoringContractError("device configuration history snapshots must be chronological")
        expected_diffs = tuple(DeviceConfigDiff.between(left, right) for left, right in zip(snapshots, snapshots[1:]))
        if self.diffs != expected_diffs:
            raise MonitoringContractError("device configuration history diffs do not match snapshots")
        object.__setattr__(self, "snapshots", snapshots)
        object.__setattr__(self, "diffs", expected_diffs)
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "asset_id": self.asset_id,
            "snapshots": [snapshot.public_dict() for snapshot in self.snapshots],
            "diffs": [diff.public_dict() for diff in self.diffs],
            "authority": self.authority,
            "raw_config_retained": False,
        }

    @property
    def fingerprint(self) -> str:
        self.validate()
        return sha256_fingerprint(self.public_dict())
