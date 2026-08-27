from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable


class SkillSecurityError(RuntimeError):
    pass


_SKILL_NAME_RE = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


def _frontmatter(text: str) -> tuple[dict[str, str], str]:
    if not text.startswith("---\n"):
        raise SkillSecurityError("SKILL.md must start with YAML frontmatter")
    end = text.find("\n---\n", 4)
    if end < 0:
        raise SkillSecurityError("SKILL.md frontmatter is not closed")
    metadata: dict[str, str] = {}
    for raw in text[4:end].splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        key, value = line.split(":", 1)
        metadata[key.strip()] = value.strip().strip('"').strip("'")
    return metadata, text[end + 5 :].strip()


class ApprovedSkillLoader:
    """Load only repository-local skills that passed the recorded security review."""

    def __init__(self, root: Path):
        self.root = Path(root)
        self.registry_path = self.root / "registry.json"

    def _registry(self) -> dict:
        if not self.registry_path.exists():
            return {"schema_version": 1, "policy": "no-registry-no-skills", "skills": {}}
        payload = json.loads(self.registry_path.read_text(encoding="utf-8"))
        if payload.get("schema_version") != 1 or not isinstance(payload.get("skills"), dict):
            raise SkillSecurityError("Unsupported or invalid skill registry")
        return payload

    def load_for_agent(self, agent_id: str, names: Iterable[str]) -> list[str]:
        registry = self._registry()
        approved = registry["skills"]
        blocks: list[str] = []

        for name in names:
            if not _SKILL_NAME_RE.fullmatch(name):
                raise SkillSecurityError(f"Invalid skill name: {name}")
            entry = approved.get(name)
            if not isinstance(entry, dict) or entry.get("enabled") is not True:
                raise SkillSecurityError(f"Skill is not approved/enabled: {name}")
            if agent_id not in entry.get("agent_ids", []):
                raise SkillSecurityError(f"Skill {name} is not approved for agent {agent_id}")
            if entry.get("instruction_only") is not True:
                raise SkillSecurityError(f"Executable third-party skills are not allowed by this loader: {name}")

            skill_dir = (self.root / name).resolve()
            root_resolved = self.root.resolve()
            if root_resolved not in skill_dir.parents:
                raise SkillSecurityError(f"Skill path escapes approved root: {name}")
            if (skill_dir / "scripts").exists():
                raise SkillSecurityError(f"Reviewed instruction-only skill unexpectedly contains scripts: {name}")

            path = skill_dir / "SKILL.md"
            raw = path.read_bytes()
            if len(raw) > 65536:
                raise SkillSecurityError(f"Skill exceeds 64 KiB review limit: {name}")
            actual = hashlib.sha256(raw).hexdigest()
            expected = str(entry.get("sha256", ""))
            if not expected or actual != expected:
                raise SkillSecurityError(f"Skill integrity mismatch: {name}")

            text = raw.decode("utf-8")
            metadata, body = _frontmatter(text)
            if metadata.get("name") != name:
                raise SkillSecurityError(f"Skill manifest name mismatch: {name}")
            if not metadata.get("description"):
                raise SkillSecurityError(f"Skill description is required: {name}")
            if not body:
                raise SkillSecurityError(f"Skill body is empty: {name}")
            blocks.append(f"## Approved local skill: {name}\n\n{body}")

        return blocks
