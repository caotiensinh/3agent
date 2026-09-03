from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

ALLOWED_STATUSES = {"approved", "quarantined", "disabled"}
ALLOWED_NETWORK = {"none", "loopback", "allowlist"}
ALLOWED_SUBPROCESS = {"none", "allowlist"}


class SkillRegistryError(ValueError):
    pass


class MissingSkillError(LookupError):
    def __init__(self, capability: str, artifact_type: str = "") -> None:
        self.capability = capability
        self.artifact_type = artifact_type
        suffix = f" for {artifact_type}" if artifact_type else ""
        super().__init__(f"missing_skill: {capability}{suffix}")


@dataclass(frozen=True)
class SkillPermissions:
    network: str
    subprocess: str
    filesystem: str
    gpu: bool


@dataclass(frozen=True)
class SkillRecord:
    skill_id: str
    version: str
    status: str
    capabilities: tuple[str, ...]
    extensions: tuple[str, ...]
    mime_types: tuple[str, ...]
    permissions: SkillPermissions
    provenance: dict[str, str]
    priority: int = 100

    def supports(self, capability: str, artifact_type: str = "") -> bool:
        if capability not in self.capabilities:
            return False
        if not artifact_type:
            return True
        kind = artifact_type.casefold().strip()
        if kind.startswith("."):
            return kind in self.extensions
        if "/" in kind:
            return kind in self.mime_types
        return f".{kind}" in self.extensions


class SkillRegistry:
    """Read-only, deterministic, local-only registry for curated WorkSpace skills."""

    def __init__(self, records: Iterable[SkillRecord], *, schema_version: int = 1) -> None:
        self.schema_version = schema_version
        self._records = tuple(records)

    @classmethod
    def load(cls, path: str | Path) -> "SkillRegistry":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1:
            raise SkillRegistryError("unsupported skill registry schema")
        raw_skills = payload.get("skills")
        if not isinstance(raw_skills, list):
            raise SkillRegistryError("skills must be an array")
        records: list[SkillRecord] = []
        seen: set[str] = set()
        for raw in raw_skills:
            if not isinstance(raw, dict):
                raise SkillRegistryError("skill entry must be an object")
            skill_id = str(raw.get("id") or "").strip()
            version = str(raw.get("version") or "").strip()
            status = str(raw.get("status") or "").strip()
            if not skill_id or not version:
                raise SkillRegistryError("skill id and version are required")
            if skill_id in seen:
                raise SkillRegistryError(f"duplicate skill id: {skill_id}")
            seen.add(skill_id)
            if status not in ALLOWED_STATUSES:
                raise SkillRegistryError(f"invalid status for {skill_id}: {status}")
            permissions = raw.get("permissions") or {}
            if not isinstance(permissions, dict):
                raise SkillRegistryError(f"permissions must be an object: {skill_id}")
            network = str(permissions.get("network") or "none")
            subprocess = str(permissions.get("subprocess") or "none")
            filesystem = str(permissions.get("filesystem") or "job_sandbox")
            if network not in ALLOWED_NETWORK:
                raise SkillRegistryError(f"invalid network permission: {skill_id}")
            if subprocess not in ALLOWED_SUBPROCESS:
                raise SkillRegistryError(f"invalid subprocess permission: {skill_id}")
            provenance = raw.get("provenance") or {}
            if not isinstance(provenance, dict):
                raise SkillRegistryError(f"provenance must be an object: {skill_id}")
            if not str(provenance.get("origin") or "").strip():
                raise SkillRegistryError(f"provenance origin required: {skill_id}")
            records.append(
                SkillRecord(
                    skill_id=skill_id,
                    version=version,
                    status=status,
                    capabilities=tuple(sorted({str(x).strip() for x in raw.get("capabilities", []) if str(x).strip()})),
                    extensions=tuple(sorted({str(x).casefold().strip() for x in raw.get("extensions", []) if str(x).strip()})),
                    mime_types=tuple(sorted({str(x).casefold().strip() for x in raw.get("mime_types", []) if str(x).strip()})),
                    permissions=SkillPermissions(
                        network=network,
                        subprocess=subprocess,
                        filesystem=filesystem,
                        gpu=bool(permissions.get("gpu", False)),
                    ),
                    provenance={str(k): str(v) for k, v in provenance.items()},
                    priority=int(raw.get("priority", 100)),
                )
            )
        return cls(records)

    def records(self, *, include_unapproved: bool = False) -> tuple[SkillRecord, ...]:
        if include_unapproved:
            return self._records
        return tuple(record for record in self._records if record.status == "approved")

    def select(self, capability: str, artifact_type: str = "") -> SkillRecord:
        candidates = [
            record
            for record in self._records
            if record.status == "approved" and record.supports(capability, artifact_type)
        ]
        if not candidates:
            raise MissingSkillError(capability, artifact_type)
        candidates.sort(key=lambda record: (record.priority, record.skill_id, record.version))
        return candidates[0]

    def plan(self, capabilities: Iterable[str], artifact_type: str = "") -> tuple[SkillRecord, ...]:
        chosen: list[SkillRecord] = []
        seen: set[str] = set()
        for capability in capabilities:
            record = self.select(str(capability), artifact_type)
            if record.skill_id not in seen:
                chosen.append(record)
                seen.add(record.skill_id)
        return tuple(chosen)
