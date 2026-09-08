"""Progressive-disclosure projection over the canonical approved skill loader.

The catalog deliberately does not introduce another skill trust model. Every
listed, searched, viewed, or referenced production skill remains subject to
``ApprovedSkillLoader`` registry, review, provenance, integrity, agent-scope,
instruction-only, and content-safety checks.

This module exposes compact metadata first, then the reviewed procedure or one
reviewed reference only on explicit view. Metadata search never indexes the skill
body and grants no filesystem, network, credential, tool, or execution authority.
"""
from __future__ import annotations

import unicodedata
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

from .skills import (
    ApprovedSkillLoader,
    SkillSecurityError,
    _canonical_instruction_text,
    _frontmatter,
)

SKILL_CATALOG_SCHEMA = "workspace-approved-skill-catalog/v1"
SKILL_REFERENCE_CATALOG_SCHEMA = "workspace-approved-skill-reference/v1"
MAX_SKILL_INDEX_DESCRIPTION_CHARS = 240
MAX_SKILL_SEARCH_QUERY_CHARS = 240
MAX_SKILL_SEARCH_RESULTS = 16
MAX_SKILL_SEARCH_TAGS = 8
_MAX_METADATA_VALUE_CHARS = 64
_MAX_REGISTERED_TAGS = 16
_MAX_TAG_CHARS = 48


@dataclass(frozen=True)
class ApprovedSkillSummary:
    """Compact model-facing metadata for one already-approved production skill."""

    name: str
    description: str
    sha256: str
    provenance_count: int
    enterprise_tier: str | None = None
    risk_class: str | None = None
    category: str | None = None
    domain: str | None = None
    tags: tuple[str, ...] = ()
    schema_version: str = SKILL_CATALOG_SCHEMA

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["tags"] = list(self.tags)
        return payload


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


def _safe_metadata_value(value: object, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SkillSecurityError(f"Skill {field} metadata must be a string")
    text = " ".join(value.split()).strip()
    if (
        not text
        or len(text) > _MAX_METADATA_VALUE_CHARS
        or any(ord(char) < 32 for char in text)
    ):
        raise SkillSecurityError(f"Skill {field} metadata is invalid")
    return text


def _safe_registered_tags(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > _MAX_REGISTERED_TAGS:
        raise SkillSecurityError("Skill tags metadata must be a bounded list")
    tags: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise SkillSecurityError("Skill tag metadata must contain strings")
        tag = " ".join(raw.split()).strip()
        if (
            not tag
            or len(tag) > _MAX_TAG_CHARS
            or any(ord(char) < 32 for char in tag)
        ):
            raise SkillSecurityError("Skill tag metadata is invalid")
        tags.append(tag)
    if len(set(tag.casefold() for tag in tags)) != len(tags):
        raise SkillSecurityError("Skill tags metadata contains duplicates")
    return tuple(tags)


def _search_text(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", str(value or "")).casefold().split())


def _search_query(value: str) -> tuple[str, ...]:
    if not isinstance(value, str):
        raise SkillSecurityError("Skill catalog search query must be a string")
    text = " ".join(value.split()).strip()
    if len(text) > MAX_SKILL_SEARCH_QUERY_CHARS or any(ord(char) < 32 for char in text):
        raise SkillSecurityError("Skill catalog search query is invalid")
    normalized = _search_text(text)
    terms = tuple(dict.fromkeys(normalized.split())) if normalized else ()
    if len(terms) > 32:
        raise SkillSecurityError("Skill catalog search query has too many terms")
    return terms


def _filter_value(value: str | None, *, field: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise SkillSecurityError(f"Skill catalog {field} filter must be a string")
    text = " ".join(value.split()).strip()
    if (
        not text
        or len(text) > _MAX_METADATA_VALUE_CHARS
        or any(ord(char) < 32 for char in text)
    ):
        raise SkillSecurityError(f"Skill catalog {field} filter is invalid")
    return _search_text(text)


def _tag_filter(value: Iterable[str]) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)):
        raise SkillSecurityError("Skill catalog tags filter must be a sequence")
    try:
        raw_tags = tuple(value)
    except TypeError as exc:
        raise SkillSecurityError("Skill catalog tags filter must be a sequence") from exc
    if len(raw_tags) > MAX_SKILL_SEARCH_TAGS:
        raise SkillSecurityError("Skill catalog tags filter exceeds limit")
    tags: list[str] = []
    for raw in raw_tags:
        if not isinstance(raw, str):
            raise SkillSecurityError("Skill catalog tags filter must contain strings")
        text = " ".join(raw.split()).strip()
        if (
            not text
            or len(text) > _MAX_TAG_CHARS
            or any(ord(char) < 32 for char in text)
        ):
            raise SkillSecurityError("Skill catalog tags filter is invalid")
        tags.append(_search_text(text))
    if len(set(tags)) != len(tags):
        raise SkillSecurityError("Skill catalog tags filter contains duplicates")
    return tuple(tags)


class ApprovedSkillCatalog:
    """Read-only progressive view of production skills for one runtime agent.

    ``list_for_agent`` returns skill metadata only. ``search_for_agent`` filters
    only that audited compact metadata and remains bounded. ``view_for_agent``
    returns exactly one approved procedure. Reference list/view operations remain
    independently bounded by the canonical loader. Candidate creation and
    production promotion remain in the adaptive-learning authority path, not in
    this read-only catalog.
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

            summaries.append(
                ApprovedSkillSummary(
                    name=name,
                    description=_compact_description(metadata.get("description", "")),
                    sha256=str(entry.get("sha256") or ""),
                    provenance_count=len(provenance),
                    enterprise_tier=_safe_metadata_value(
                        entry.get("enterprise_tier"), field="enterprise_tier"
                    ),
                    risk_class=_safe_metadata_value(entry.get("risk_class"), field="risk_class"),
                    category=_safe_metadata_value(entry.get("category"), field="category"),
                    domain=_safe_metadata_value(entry.get("domain"), field="domain"),
                    tags=_safe_registered_tags(entry.get("tags")),
                )
            )

        return tuple(summaries)

    def search_for_agent(
        self,
        agent_id: str,
        *,
        query: str = "",
        category: str | None = None,
        domain: str | None = None,
        risk_class: str | None = None,
        enterprise_tier: str | None = None,
        tags: Iterable[str] = (),
        limit: int = 8,
    ) -> tuple[ApprovedSkillSummary, ...]:
        """Search only audited compact metadata; never rank on procedure/reference text.

        Query terms use deterministic AND matching across name, description,
        category, domain, and registered tags. Structured filters are exact,
        case-insensitive matches. Requested tags must all be present. Missing
        optional metadata never matches the corresponding structured filter.
        """

        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_SKILL_SEARCH_RESULTS:
            raise SkillSecurityError(
                f"Skill catalog search limit must be within 1..{MAX_SKILL_SEARCH_RESULTS}"
            )
        terms = _search_query(query)
        category_filter = _filter_value(category, field="category")
        domain_filter = _filter_value(domain, field="domain")
        risk_filter = _filter_value(risk_class, field="risk_class")
        tier_filter = _filter_value(enterprise_tier, field="enterprise_tier")
        tag_filters = _tag_filter(tags)

        matches: list[ApprovedSkillSummary] = []
        for summary in self.list_for_agent(agent_id):
            summary_category = _search_text(summary.category or "")
            summary_domain = _search_text(summary.domain or "")
            summary_risk = _search_text(summary.risk_class or "")
            summary_tier = _search_text(summary.enterprise_tier or "")
            summary_tags = tuple(_search_text(tag) for tag in summary.tags)

            if category_filter is not None and summary_category != category_filter:
                continue
            if domain_filter is not None and summary_domain != domain_filter:
                continue
            if risk_filter is not None and summary_risk != risk_filter:
                continue
            if tier_filter is not None and summary_tier != tier_filter:
                continue
            if tag_filters and not set(tag_filters).issubset(summary_tags):
                continue

            haystack = _search_text(
                " ".join(
                    (
                        summary.name,
                        summary.description,
                        summary.category or "",
                        summary.domain or "",
                        " ".join(summary.tags),
                    )
                )
            )
            if terms and not all(term in haystack for term in terms):
                continue
            matches.append(summary)
            if len(matches) >= limit:
                break

        return tuple(matches)

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
