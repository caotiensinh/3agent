"""Progressive-disclosure projection over the canonical approved skill loader.

The catalog deliberately does not introduce another skill trust model. Every
listed or viewed production skill and reference remains subject to
``ApprovedSkillLoader`` registry, review, provenance, integrity, agent-scope,
instruction-only, and content-safety checks.

This module exposes compact metadata first, then the reviewed procedure or one
reviewed reference only on explicit view. It grants no filesystem, network,
credential, tool, or execution authority.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .skills import (
    ApprovedSkillLoader,
    SkillSecurityError,
    _canonical_instruction_text,
    _frontmatter,
)

SKILL_CATALOG_SCHEMA = "workspace-approved-skill-catalog/v1"
SKILL_REFERENCE_CATALOG_SCHEMA = "workspace-approved-skill-reference/v1"
MAX_SKILL_INDEX_DESCRIPTION_CHARS = 240


@dataclass(frozen=True)
class ApprovedSkillSummary:
    """Compact model-facing metadata for one already-approved production skill."""

    name: str
    description: str
    sha256: str
    provenance_count: int
    enterprise_tier: str | None = None
    risk_class: str | None = None
    schema_version: str = SKILL_CATALOG_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True)
class ApprovedSkillReferenceSummary:
    """Compact metadata for one reviewed, read-only skill reference."""

    reference_id: str
    path: str
    sha256: str
    size_bytes: int
    content_class: str
    provenance_count: int
    vendor_family: str | None = None
    version: str | None = None
    schema_version: str = SKILL_REFERENCE_CATALOG_SCHEMA

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def _compact_description(value: str) -> str:
    text = " ".join(str(value or "").split()).strip()
    if not text:
        raise SkillSecurityError("Skill description is required")
    if len(text) <= MAX_SKILL_INDEX_DESCRIPTION_CHARS:
        return text
    return text[: MAX_SKILL_INDEX_DESCRIPTION_CHARS - 3].rstrip() + "..."


class ApprovedSkillCatalog:
    """Read-only progressive view of production skills for one runtime agent.

    ``list_for_agent`` returns skill metadata only. ``view_for_agent`` returns
    exactly one approved procedure. ``list_references_for_agent`` returns compact
    reviewed-reference metadata, while ``view_reference_for_agent`` discloses one
    exact reference on demand. Candidate creation and production promotion remain
    in the adaptive-learning authority path, not in this read-only catalog.
    """

    def __init__(self, root: Path | ApprovedSkillLoader):
        self.loader = root if isinstance(root, ApprovedSkillLoader) else ApprovedSkillLoader(Path(root))

    def list_for_agent(self, agent_id: str) -> tuple[ApprovedSkillSummary, ...]:
        """Return compact metadata for enabled skills approved for ``agent_id``.

        The full registry is audited before disclosure. A tampered or unreviewed
        enabled skill therefore fails the catalog closed rather than being quietly
        omitted while other entries remain visible.
        """

        agent = str(agent_id or "").strip()
        if not agent or len(agent) > 128:
            raise SkillSecurityError("Invalid agent_id for skill catalog")

        audited = set(self.loader.audit_registry())
        registry = self.loader._registry()
        approved = registry["skills"]
        summaries: list[ApprovedSkillSummary] = []

        for name in sorted(audited):
            entry = approved.get(name)
            if not isinstance(entry, dict):
                raise SkillSecurityError(f"Invalid registry entry: {name}")
            if agent not in entry.get("agent_ids", []):
                continue

            # audit_registry already validated exact bytes. Read the reviewed
            # frontmatter only to project the compact description; never include
            # the skill body or reference bodies in the index.
            path = self.loader.root / name / "SKILL.md"
            text = _canonical_instruction_text(path.read_bytes())
            metadata, _ = _frontmatter(text)
            provenance = entry.get("provenance")
            if not isinstance(provenance, list):
                raise SkillSecurityError(f"Skill provenance is missing or invalid: {name}")

            enterprise_tier = entry.get("enterprise_tier")
            risk_class = entry.get("risk_class")
            summaries.append(
                ApprovedSkillSummary(
                    name=name,
                    description=_compact_description(metadata.get("description", "")),
                    sha256=str(entry.get("sha256") or ""),
                    provenance_count=len(provenance),
                    enterprise_tier=(
                        str(enterprise_tier).strip() if enterprise_tier is not None else None
                    ),
                    risk_class=(str(risk_class).strip() if risk_class is not None else None),
                )
            )

        return tuple(summaries)

    def view_for_agent(self, agent_id: str, name: str) -> str:
        """Return one reviewed skill procedure on demand."""

        blocks = self.loader.load_for_agent(str(agent_id or "").strip(), [str(name or "").strip()])
        if len(blocks) != 1:
            raise SkillSecurityError("Expected exactly one approved skill block")
        return blocks[0]

    def list_references_for_agent(
        self,
        agent_id: str,
        name: str,
    ) -> tuple[ApprovedSkillReferenceSummary, ...]:
        """Return compact reference metadata without disclosing reference text."""

        rows = self.loader.list_references_for_agent(
            str(agent_id or "").strip(),
            str(name or "").strip(),
        )
        return tuple(ApprovedSkillReferenceSummary(**row) for row in rows)

    def view_reference_for_agent(self, agent_id: str, name: str, reference_id: str) -> str:
        """Return exactly one reviewed reference after canonical revalidation."""

        return self.loader.load_reference_for_agent(
            str(agent_id or "").strip(),
            str(name or "").strip(),
            str(reference_id or "").strip(),
        )
