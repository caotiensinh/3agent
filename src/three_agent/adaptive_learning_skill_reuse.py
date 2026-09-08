"""Exact bridge from adaptive retrieval to approved production skill reuse.

This module deliberately owns no ranking, registry, loader, promotion, or
persistence policy. ``LearningRetrievalGateway`` remains the only adaptive
selector, ``ApprovedSkillCatalog``/``ApprovedSkillLoader`` remain the production
trust boundary, and this bridge only proves that a selected active learning
version is the exact candidate recorded in one materialized production skill.

Materialized learned skills are withheld from generic untrusted learned-content
rendering. Their reviewed production ``SKILL.md`` body is loaded through the
canonical loader and may be exposed only to the caller's synthesis stage.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .adaptive_learning_contract import KnowledgeCandidate
from .adaptive_learning_retrieval import (
    LearningContext,
    LearningContextItem,
    LearningRetrievalError,
    LearningRetrievalGateway,
)
from .skill_catalog import ApprovedSkillCatalog
from .skills import SkillSecurityError

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_MATERIALIZED_LEARNED_SKILLS = 1


class AdaptiveLearningSkillReuseError(RuntimeError):
    """A selected learned skill could not be bound to exact approved production bytes."""


@dataclass(frozen=True)
class PreparedLearningReuse:
    """Synthesis-safe projection of one already-selected adaptive context."""

    reuse_context: LearningContext
    reference_context: LearningContext
    materialized_skill_blocks: tuple[str, ...]

    def validate(self) -> "PreparedLearningReuse":
        self.reuse_context.validate()
        self.reference_context.validate()
        reference_ids = {
            (item.item_id, item.knowledge_sha256)
            for item in self.reference_context.items
        }
        reuse_ids = {
            (item.item_id, item.knowledge_sha256)
            for item in self.reuse_context.items
        }
        if not reference_ids.issubset(reuse_ids):
            raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_REFERENCE_NOT_REUSED")
        if any(item.kind == "skill" for item in self.reference_context.items):
            raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_RAW_SKILL_REFERENCE_FORBIDDEN")
        if len(self.materialized_skill_blocks) > _MAX_MATERIALIZED_LEARNED_SKILLS:
            raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_SKILL_LIMIT_EXCEEDED")
        return self


def _stable_checkpoint(gateway: LearningRetrievalGateway) -> Any:
    return gateway._authority.verify(gateway._store)


def _exact_candidate_identity(
    gateway: LearningRetrievalGateway,
    item: LearningContextItem,
) -> tuple[str, str]:
    """Resolve one retrieved item back to its exact still-active candidate version."""

    item.validate()
    before = _stable_checkpoint(gateway)
    active = gateway._store.active(item.item_id)
    after = _stable_checkpoint(gateway)
    if (
        before.sequence != after.sequence
        or before.checkpoint_sha256 != after.checkpoint_sha256
        or before.state_sha256 != after.state_sha256
    ):
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_CHECKPOINT_CHANGED")
    if active is None:
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_ACTIVE_ITEM_MISSING")
    if str(active.get("knowledge_sha256") or "") != item.knowledge_sha256:
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_VERSION_CHANGED")
    if str(active.get("level") or "") != item.level:
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_LEVEL_CHANGED")

    try:
        candidate = KnowledgeCandidate.from_payload(active["candidate"])
    except (KeyError, TypeError, ValueError) as exc:
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_CANDIDATE_INVALID") from exc

    if (
        candidate.domain != item.domain
        or candidate.kind != item.kind
        or candidate.sensitivity != item.sensitivity
        or candidate.risk_level != item.risk_level
        or candidate.execution_mode != item.execution_mode
    ):
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_CONTEXT_IDENTITY_MISMATCH")
    candidate_sha256 = str(active.get("candidate_sha256") or "").strip().lower()
    if candidate.sha256 != candidate_sha256 or not _SHA_RE.fullmatch(candidate_sha256):
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_CANDIDATE_SHA_MISMATCH")
    if not _ID_RE.fullmatch(candidate.candidate_id):
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_CANDIDATE_ID_INVALID")
    return candidate.candidate_id, candidate_sha256


def _materialized_skill_name(
    catalog: ApprovedSkillCatalog,
    *,
    agent_id: str,
    candidate_id: str,
    candidate_sha256: str,
) -> str | None:
    """Find one exact materialized candidate without introducing another selector."""

    token = f"candidate:{candidate_id}:{candidate_sha256}"
    audited = set(catalog.loader.audit_registry())
    registry = catalog.loader._registry()
    skills = registry.get("skills")
    if not isinstance(skills, dict):
        raise SkillSecurityError("Unsupported or invalid skill registry")

    matches: list[str] = []
    for name in sorted(audited):
        entry = skills.get(name)
        if not isinstance(entry, dict):
            raise SkillSecurityError(f"Invalid registry entry: {name}")
        if agent_id not in entry.get("agent_ids", []):
            continue
        provenance = entry.get("provenance")
        if not isinstance(provenance, list):
            raise SkillSecurityError(f"Skill provenance is missing or invalid: {name}")
        if token in provenance:
            matches.append(name)

    if len(matches) > 1:
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_MATERIALIZATION_AMBIGUOUS")
    return matches[0] if matches else None


def prepare_learning_reuse(
    gateway: LearningRetrievalGateway,
    catalog: ApprovedSkillCatalog,
    *,
    agent_id: str,
    context: LearningContext,
) -> PreparedLearningReuse:
    """Bind retrieved skill items to exact production bytes for synthesis-only reuse.

    Non-skill adaptive knowledge remains ordinary untrusted reference data. A
    ``kind=skill`` item is reusable only when its exact current candidate identity
    maps to one materialized production skill. Unmaterialized skill candidates are
    withheld rather than silently falling back to raw learned instructions.
    """

    if not isinstance(gateway, LearningRetrievalGateway):
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_GATEWAY_REQUIRED")
    if not isinstance(catalog, ApprovedSkillCatalog):
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_CATALOG_REQUIRED")
    context.validate()
    agent = str(agent_id or "").strip()
    if not agent or len(agent) > 128:
        raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_AGENT_INVALID")

    reused: list[LearningContextItem] = []
    references: list[LearningContextItem] = []
    skill_blocks: list[str] = []

    for item in context.items:
        if item.kind != "skill":
            reused.append(item)
            references.append(item)
            continue

        if len(skill_blocks) >= _MAX_MATERIALIZED_LEARNED_SKILLS:
            continue
        candidate_id, candidate_sha256 = _exact_candidate_identity(gateway, item)
        skill_name = _materialized_skill_name(
            catalog,
            agent_id=agent,
            candidate_id=candidate_id,
            candidate_sha256=candidate_sha256,
        )
        if skill_name is None:
            continue
        block = catalog.view_for_agent(agent, skill_name)
        if not block.strip():
            raise AdaptiveLearningSkillReuseError("LEARNING_REUSE_PRODUCTION_SKILL_EMPTY")
        reused.append(item)
        skill_blocks.append(block)

    reuse_context = LearningContext(
        query_sha256=context.query_sha256,
        domain=context.domain,
        task_sensitivity=context.task_sensitivity,
        items=tuple(reused),
    ).validate()
    reference_context = LearningContext(
        query_sha256=context.query_sha256,
        domain=context.domain,
        task_sensitivity=context.task_sensitivity,
        items=tuple(references),
    ).validate()
    return PreparedLearningReuse(
        reuse_context=reuse_context,
        reference_context=reference_context,
        materialized_skill_blocks=tuple(skill_blocks),
    ).validate()
