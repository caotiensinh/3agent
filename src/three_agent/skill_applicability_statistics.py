"""Deterministic metadata-only vendor/version applicability statistics for approved skills.

M-06 projects only reviewed applicability declarations already admitted by the
canonical ``ApprovedSkillLoader`` and exposed by ``ApprovedSkillCatalog``. It
never reads reference bodies, never infers observed field/device identity, and
grants no model, filesystem, network, credential, tool, promotion, or mutation
authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .skill_catalog import ApprovedSkillCatalog
from .skills import ApprovedSkillLoader, SkillSecurityError

SKILL_APPLICABILITY_STATISTICS_SCHEMA = "workspace-approved-skill-applicability-statistics/v1"
MAX_APPLICABILITY_SKILLS_PER_PROJECTION = 16
_MAX_APPLICABILITY_VALUE_CHARS = 160
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")


def _canonical(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _safe_value(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SkillSecurityError(f"Skill applicability {field} must be a string")
    if any(ord(char) < 32 for char in value):
        raise SkillSecurityError(f"Skill applicability {field} is invalid")
    text = " ".join(value.split()).strip()
    if not text or len(text) > _MAX_APPLICABILITY_VALUE_CHARS:
        raise SkillSecurityError(f"Skill applicability {field} is invalid")
    return text


@dataclass(frozen=True)
class SkillApplicabilityBucket:
    """Count of reviewed references declaring one exact applicability pair."""

    vendor_family: str | None
    version: str | None
    reference_count: int

    def validate(self) -> "SkillApplicabilityBucket":
        vendor = _safe_value(self.vendor_family, field="vendor_family")
        version = _safe_value(self.version, field="version")
        if vendor != self.vendor_family or version != self.version:
            raise SkillSecurityError("Skill applicability bucket metadata is not canonical")
        if (
            not isinstance(self.reference_count, int)
            or isinstance(self.reference_count, bool)
            or self.reference_count < 1
        ):
            raise SkillSecurityError("Skill applicability bucket count is invalid")
        return self

    def to_payload(self) -> dict[str, object]:
        self.validate()
        return {
            "vendor_family": self.vendor_family,
            "version": self.version,
            "reference_count": self.reference_count,
        }


@dataclass(frozen=True)
class SkillApplicabilityStatistics:
    """Metadata-only applicability coverage for one exact approved skill version."""

    skill_name: str
    production_sha256: str
    total_references: int
    vendor_scoped_references: int
    version_scoped_references: int
    fully_scoped_references: int
    unscoped_references: int
    buckets: tuple[SkillApplicabilityBucket, ...]
    schema_version: str = SKILL_APPLICABILITY_STATISTICS_SCHEMA

    def _base_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "skill_name": self.skill_name,
            "production_sha256": self.production_sha256,
            "total_references": self.total_references,
            "vendor_scoped_references": self.vendor_scoped_references,
            "version_scoped_references": self.version_scoped_references,
            "fully_scoped_references": self.fully_scoped_references,
            "unscoped_references": self.unscoped_references,
            "buckets": [bucket.to_payload() for bucket in self.buckets],
        }

    def validate(self) -> "SkillApplicabilityStatistics":
        if self.schema_version != SKILL_APPLICABILITY_STATISTICS_SCHEMA:
            raise SkillSecurityError("Skill applicability statistics schema mismatch")
        if not self.skill_name or len(self.skill_name) > 128 or any(
            char in self.skill_name for char in "\r\n\x00"
        ):
            raise SkillSecurityError("Skill applicability skill_name is invalid")
        if not _SHA256_HEX.fullmatch(self.production_sha256):
            raise SkillSecurityError("Skill applicability production SHA-256 is invalid")
        counts = (
            self.total_references,
            self.vendor_scoped_references,
            self.version_scoped_references,
            self.fully_scoped_references,
            self.unscoped_references,
        )
        if any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in counts
        ):
            raise SkillSecurityError("Skill applicability statistics count is invalid")

        expected_order = tuple(
            sorted(
                self.buckets,
                key=lambda row: (row.vendor_family or "", row.version or ""),
            )
        )
        if expected_order != self.buckets:
            raise SkillSecurityError("Skill applicability buckets must be deterministic")
        seen: set[tuple[str | None, str | None]] = set()
        bucket_total = 0
        expected_vendor = 0
        expected_version = 0
        expected_fully = 0
        expected_unscoped = 0
        for bucket in self.buckets:
            bucket.validate()
            key = (bucket.vendor_family, bucket.version)
            if key in seen:
                raise SkillSecurityError("Duplicate skill applicability bucket")
            seen.add(key)
            bucket_total += bucket.reference_count
            if bucket.vendor_family is not None:
                expected_vendor += bucket.reference_count
            if bucket.version is not None:
                expected_version += bucket.reference_count
            if bucket.vendor_family is not None and bucket.version is not None:
                expected_fully += bucket.reference_count
            if bucket.vendor_family is None and bucket.version is None:
                expected_unscoped += bucket.reference_count

        if bucket_total != self.total_references:
            raise SkillSecurityError("Skill applicability bucket total mismatch")
        if self.vendor_scoped_references != expected_vendor:
            raise SkillSecurityError("Vendor-scoped reference count mismatch")
        if self.version_scoped_references != expected_version:
            raise SkillSecurityError("Version-scoped reference count mismatch")
        if self.fully_scoped_references != expected_fully:
            raise SkillSecurityError("Fully-scoped reference count mismatch")
        if self.unscoped_references != expected_unscoped:
            raise SkillSecurityError("Unscoped reference count mismatch")
        return self

    @property
    def projection_sha256(self) -> str:
        self.validate()
        return "sha256:" + hashlib.sha256(
            _canonical(self._base_payload()).encode("utf-8")
        ).hexdigest()

    def to_payload(self) -> dict[str, object]:
        return {**self._base_payload(), "projection_sha256": self.projection_sha256}


class ApprovedSkillApplicabilityProjector:
    """Read-only M-06 projection over canonical approved skill/reference metadata."""

    def __init__(self, root: Path | ApprovedSkillLoader | ApprovedSkillCatalog):
        if isinstance(root, ApprovedSkillCatalog):
            self.catalog = root
        else:
            self.catalog = ApprovedSkillCatalog(root)

    def project_for_agent(self, agent_id: str, skill_name: str) -> SkillApplicabilityStatistics:
        """Project reviewed vendor/version declaration coverage for one skill.

        ``list_for_agent`` audits the complete enabled registry first. The exact
        skill reference list then reuses canonical per-skill admission and
        integrity validation. No reference body is disclosed to this projector.
        """

        name = str(skill_name or "").strip()
        summaries = {row.name: row for row in self.catalog.list_for_agent(agent_id)}
        summary = summaries.get(name)
        if summary is None:
            raise SkillSecurityError(f"Skill is not available for applicability projection: {name}")

        references = self.catalog.list_references_for_agent(agent_id, name)
        counts: dict[tuple[str | None, str | None], int] = {}
        vendor_scoped = 0
        version_scoped = 0
        fully_scoped = 0
        unscoped = 0

        for reference in references:
            vendor = _safe_value(reference.vendor_family, field="vendor_family")
            version = _safe_value(reference.version, field="version")
            if vendor is not None:
                vendor_scoped += 1
            if version is not None:
                version_scoped += 1
            if vendor is not None and version is not None:
                fully_scoped += 1
            if vendor is None and version is None:
                unscoped += 1
            key = (vendor, version)
            counts[key] = counts.get(key, 0) + 1

        buckets = tuple(
            SkillApplicabilityBucket(vendor, version, count)
            for (vendor, version), count in sorted(
                counts.items(), key=lambda row: (row[0][0] or "", row[0][1] or "")
            )
        )
        return SkillApplicabilityStatistics(
            skill_name=summary.name,
            production_sha256=summary.sha256,
            total_references=len(references),
            vendor_scoped_references=vendor_scoped,
            version_scoped_references=version_scoped,
            fully_scoped_references=fully_scoped,
            unscoped_references=unscoped,
            buckets=buckets,
        ).validate()

    def project_many_for_agent(
        self,
        agent_id: str,
        skill_names: Iterable[str],
    ) -> tuple[SkillApplicabilityStatistics, ...]:
        """Project an explicit bounded set without turning this into registry discovery."""

        if isinstance(skill_names, (str, bytes)):
            raise SkillSecurityError("Skill applicability names must be a sequence")
        try:
            names = tuple(dict.fromkeys(str(name or "").strip() for name in skill_names))
        except TypeError as exc:
            raise SkillSecurityError("Skill applicability names must be a sequence") from exc
        if not names or any(not name for name in names):
            raise SkillSecurityError("Skill applicability names must be non-empty")
        if len(names) > MAX_APPLICABILITY_SKILLS_PER_PROJECTION:
            raise SkillSecurityError(
                "Skill applicability projection exceeds bounded skill count"
            )
        return tuple(
            sorted(
                (self.project_for_agent(agent_id, name) for name in names),
                key=lambda row: row.skill_name,
            )
        )
