"""Metadata-only telemetry adapter for the canonical approved skill catalog.

This module does not add another registry, loader, selector, or persistence
system. It delegates every list/search/view decision to ``ApprovedSkillCatalog``
and writes compact observations into the existing ``TaskStore.activities`` ledger.
Telemetry is observational only and never grants or widens runtime authority.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable

from .skill_catalog import ApprovedSkillCatalog, ApprovedSkillSummary
from .skills import SkillSecurityError

SKILL_CATALOG_TELEMETRY_SCHEMA = "workspace-approved-skill-catalog-telemetry/v1"
ACTION_LISTED = "skill_catalog_listed"
ACTION_VIEWED = "skill_catalog_viewed"
ACTION_SELECTED = "skill_catalog_selected"

_ALLOWED_ACTIONS = frozenset({ACTION_LISTED, ACTION_VIEWED, ACTION_SELECTED})
_ALLOWED_SURFACES = frozenset({"list", "search", "view", "runtime_selection"})
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_LISTED_IDENTITIES = 16
_MAX_EXACT_IDENTITIES = 2
_MAX_ACTIVITY_DETAILS_CHARS = 800


class SkillCatalogTelemetryError(ValueError):
    """Telemetry request is malformed or cannot be safely bound to catalog state."""


@dataclass(frozen=True)
class SkillCatalogIdentity:
    name: str
    production_sha256: str

    def validate(self) -> "SkillCatalogIdentity":
        name = str(self.name or "").strip()
        digest = str(self.production_sha256 or "").strip().lower()
        if name != self.name or not _ID.fullmatch(name):
            raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_NAME_INVALID")
        if digest != self.production_sha256 or not _SHA.fullmatch(digest):
            raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_SHA_INVALID")
        return self

    def to_payload(self) -> dict[str, str]:
        self.validate()
        return {"name": self.name, "production_sha256": self.production_sha256}


def _task_id(value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value or "").strip()
    if text != value or not _ID.fullmatch(text):
        raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_TASK_ID_INVALID")
    return text


def _agent_id(value: str) -> str:
    text = str(value or "").strip()
    if text != value or not _ID.fullmatch(text):
        raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_AGENT_ID_INVALID")
    return text


def _validated_identities(
    identities: tuple[SkillCatalogIdentity, ...],
    *,
    maximum: int,
) -> tuple[SkillCatalogIdentity, ...]:
    if len(identities) > maximum:
        raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_COUNT_EXCEEDED")
    if len({item.name for item in identities}) != len(identities):
        raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_DUPLICATE_SKILL")
    for item in identities:
        item.validate()
    return identities


def _identity_set_sha256(identities: tuple[SkillCatalogIdentity, ...]) -> str:
    canonical = json.dumps(
        [item.to_payload() for item in sorted(identities, key=lambda value: value.name)],
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _canonical_details(
    *,
    action: str,
    surface: str,
    identities: tuple[SkillCatalogIdentity, ...],
) -> str:
    if action not in _ALLOWED_ACTIONS:
        raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_ACTION_INVALID")
    if surface not in _ALLOWED_SURFACES:
        raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_SURFACE_INVALID")

    if action == ACTION_LISTED:
        _validated_identities(identities, maximum=_MAX_LISTED_IDENTITIES)
        payload: dict[str, Any] = {
            "schema_version": SKILL_CATALOG_TELEMETRY_SCHEMA,
            "event": action,
            "surface": surface,
            "count": len(identities),
            "skill_set_sha256": _identity_set_sha256(identities),
        }
    else:
        _validated_identities(identities, maximum=_MAX_EXACT_IDENTITIES)
        payload = {
            "schema_version": SKILL_CATALOG_TELEMETRY_SCHEMA,
            "event": action,
            "surface": surface,
            "count": len(identities),
            "skills": [item.to_payload() for item in identities],
        }

    details = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(details) > _MAX_ACTIVITY_DETAILS_CHARS:
        raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_DETAILS_TOO_LARGE")
    return details


class SkillCatalogTelemetry:
    """TaskStore-backed telemetry around one canonical ``ApprovedSkillCatalog``.

    List/search helpers record only count plus a deterministic digest of exact
    approved identities, keeping the existing activity-details budget bounded.
    View/runtime-selection events record exact name and production SHA for at most
    the canonical two-skill load ceiling. No raw query, description, prompt,
    reference text, or skill body is accepted by this API.
    """

    __slots__ = ("catalog", "store")

    def __init__(self, catalog: ApprovedSkillCatalog, store: Any) -> None:
        if not isinstance(catalog, ApprovedSkillCatalog):
            raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_CATALOG_REQUIRED")
        if not callable(getattr(store, "record_activity", None)):
            raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_STORE_REQUIRED")
        self.catalog = catalog
        self.store = store

    @staticmethod
    def _identities(rows: Iterable[ApprovedSkillSummary]) -> tuple[SkillCatalogIdentity, ...]:
        values = tuple(rows)
        if len(values) > _MAX_LISTED_IDENTITIES:
            raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_COUNT_EXCEEDED")
        identities: list[SkillCatalogIdentity] = []
        for row in values:
            if not isinstance(row, ApprovedSkillSummary):
                raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_SUMMARY_INVALID")
            identities.append(
                SkillCatalogIdentity(
                    name=row.name,
                    production_sha256=str(row.sha256 or "").strip().lower(),
                ).validate()
            )
        return tuple(identities)

    def identities_for_names(
        self,
        agent_id: str,
        names: Iterable[str],
    ) -> tuple[SkillCatalogIdentity, ...]:
        """Resolve names against audited production registry bytes only.

        This intentionally avoids category/tag/description projection so telemetry
        cannot widen or narrow the canonical runtime selection policy.
        """

        agent = _agent_id(agent_id)
        if isinstance(names, (str, bytes)):
            raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_NAMES_INVALID")
        requested = tuple(str(name or "").strip() for name in names)
        if len(requested) > _MAX_EXACT_IDENTITIES or len(set(requested)) != len(requested):
            raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_NAMES_INVALID")
        for name in requested:
            if not _ID.fullmatch(name):
                raise SkillCatalogTelemetryError("SKILL_CATALOG_TELEMETRY_NAME_INVALID")

        audited = set(self.catalog.loader.audit_registry())
        registry = self.catalog.loader._registry()
        skills = registry.get("skills")
        if not isinstance(skills, dict):
            raise SkillSecurityError("Unsupported or invalid skill registry")

        identities: list[SkillCatalogIdentity] = []
        for name in requested:
            if name not in audited:
                raise SkillSecurityError(f"Skill telemetry identity is not approved: {name}")
            entry = skills.get(name)
            if not isinstance(entry, dict) or agent not in entry.get("agent_ids", []):
                raise SkillSecurityError(
                    f"Skill telemetry identity is not approved for this agent: {name}"
                )
            identities.append(
                SkillCatalogIdentity(
                    name=name,
                    production_sha256=str(entry.get("sha256") or "").strip().lower(),
                ).validate()
            )
        return tuple(identities)

    def _record(
        self,
        *,
        task_id: str | None,
        agent_id: str,
        action: str,
        surface: str,
        identities: tuple[SkillCatalogIdentity, ...],
    ) -> None:
        task = _task_id(task_id)
        agent = _agent_id(agent_id)
        details = _canonical_details(action=action, surface=surface, identities=identities)
        self.store.record_activity(task, agent, action, "ok", details)

    def list_for_agent(
        self,
        task_id: str | None,
        agent_id: str,
    ) -> tuple[ApprovedSkillSummary, ...]:
        rows = self.catalog.list_for_agent(agent_id)
        identities = self._identities(rows)
        self._record(
            task_id=task_id,
            agent_id=agent_id,
            action=ACTION_LISTED,
            surface="list",
            identities=identities,
        )
        return rows

    def search_for_agent(
        self,
        task_id: str | None,
        agent_id: str,
        **filters: Any,
    ) -> tuple[ApprovedSkillSummary, ...]:
        rows = self.catalog.search_for_agent(agent_id, **filters)
        identities = self._identities(rows)
        self._record(
            task_id=task_id,
            agent_id=agent_id,
            action=ACTION_LISTED,
            surface="search",
            identities=identities,
        )
        return rows

    def view_for_agent(
        self,
        task_id: str | None,
        agent_id: str,
        name: str,
    ) -> str:
        block = self.catalog.view_for_agent(agent_id, name)
        identities = self.identities_for_names(agent_id, (name,))
        self._record(
            task_id=task_id,
            agent_id=agent_id,
            action=ACTION_VIEWED,
            surface="view",
            identities=identities,
        )
        return block

    def record_viewed(
        self,
        task_id: str | None,
        agent_id: str,
        identities: tuple[SkillCatalogIdentity, ...],
    ) -> None:
        self._record(
            task_id=task_id,
            agent_id=agent_id,
            action=ACTION_VIEWED,
            surface="view",
            identities=identities,
        )

    def record_selected(
        self,
        task_id: str | None,
        agent_id: str,
        identities: tuple[SkillCatalogIdentity, ...],
    ) -> None:
        self._record(
            task_id=task_id,
            agent_id=agent_id,
            action=ACTION_SELECTED,
            surface="runtime_selection",
            identities=identities,
        )
