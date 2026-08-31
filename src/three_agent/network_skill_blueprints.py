from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

BLUEPRINT_SCHEMA = "workspace-network-skill-blueprint/v1"
SUPPLEMENTAL_SCHEMA = "workspace-network-experience-supplemental-sources/v1"
DATASET_SCHEMA = "workspace-network-dataset-registry/v1"

REQUIRED_SKILLS = {
    "intrusion-trace-hunting",
    "log-incident-diagnosis",
    "host-log-forensics",
}
ALLOWED_FUTURE_SOURCES = {"verified-local-enterprise-incidents"}


class NetworkSkillBlueprintError(ValueError):
    """A network-skill blueprint violates the independent evidence-first contract."""


def _nonempty_list(value: Any, field: str, *, max_items: int = 128) -> tuple[str, ...]:
    if not isinstance(value, list) or not value or len(value) > max_items:
        raise NetworkSkillBlueprintError(f"{field} must contain 1..{max_items} items")
    items = tuple(str(item).strip() for item in value)
    if any(not item for item in items) or len(set(items)) != len(items):
        raise NetworkSkillBlueprintError(f"{field} must contain unique non-empty strings")
    return items


def _fingerprint(value: dict[str, Any]) -> str:
    payload = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(payload).hexdigest()


@dataclass(frozen=True)
class NetworkSkillBlueprint:
    skill_id: str
    name: str
    objective: str
    evidence_domains: tuple[str, ...]
    method: tuple[str, ...]
    required_output: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    source_curriculum: dict[str, tuple[str, ...]]
    raw: dict[str, Any]

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "NetworkSkillBlueprint":
        if value.get("schema_version") != BLUEPRINT_SCHEMA:
            raise NetworkSkillBlueprintError(f"blueprint schema must be {BLUEPRINT_SCHEMA}")
        skill_id = str(value.get("skill_id", "")).strip()
        name = str(value.get("name", "")).strip()
        objective = str(value.get("objective", "")).strip()
        if not skill_id or not name or not objective:
            raise NetworkSkillBlueprintError("skill_id, name and objective are required")
        if value.get("stage") != "candidate_blueprint":
            raise NetworkSkillBlueprintError("network skill blueprint must remain candidate_blueprint")
        if value.get("authority") != "advisory":
            raise NetworkSkillBlueprintError("network skill blueprint authority must remain advisory")
        if value.get("auto_promotable") is not False:
            raise NetworkSkillBlueprintError("network skill blueprint cannot auto-promote")

        curriculum_raw = value.get("source_curriculum")
        if not isinstance(curriculum_raw, dict) or not curriculum_raw:
            raise NetworkSkillBlueprintError("source_curriculum is required")
        curriculum = {
            str(group): _nonempty_list(items, f"source_curriculum.{group}", max_items=64)
            for group, items in curriculum_raw.items()
        }

        gate = value.get("promotion_gate")
        if not isinstance(gate, dict):
            raise NetworkSkillBlueprintError("promotion_gate is required")
        if gate.get("requires_held_out_evaluation") is not True:
            raise NetworkSkillBlueprintError("held-out evaluation is mandatory")
        if gate.get("requires_independent_skill_review") is not True:
            raise NetworkSkillBlueprintError("independent skill review is mandatory")

        return cls(
            skill_id=skill_id,
            name=name,
            objective=objective,
            evidence_domains=_nonempty_list(value.get("evidence_domains"), "evidence_domains"),
            method=_nonempty_list(value.get("method"), "method"),
            required_output=_nonempty_list(value.get("required_output"), "required_output"),
            stop_conditions=_nonempty_list(value.get("stop_conditions"), "stop_conditions"),
            source_curriculum=curriculum,
            raw=dict(value),
        )

    def fingerprint(self) -> str:
        return _fingerprint(self.raw)


class NetworkSkillBlueprintRegistry:
    """Validate independent network-skill blueprints and their reviewed source gates.

    This loader performs no network I/O and never exposes blueprints through the
    production ApprovedSkillLoader. It is a design/training contract only.
    """

    def __init__(
        self,
        blueprints: dict[str, NetworkSkillBlueprint],
        dataset_status: dict[str, str],
        supplemental_status: dict[str, str],
    ) -> None:
        self.blueprints = blueprints
        self.dataset_status = dataset_status
        self.supplemental_status = supplemental_status

    @classmethod
    def load(
        cls,
        *,
        blueprint_root: str | Path,
        dataset_registry: str | Path,
        supplemental_registry: str | Path,
    ) -> "NetworkSkillBlueprintRegistry":
        root = Path(blueprint_root)
        dataset_payload = json.loads(Path(dataset_registry).read_text(encoding="utf-8"))
        supplemental_payload = json.loads(Path(supplemental_registry).read_text(encoding="utf-8"))
        if dataset_payload.get("schema_version") != DATASET_SCHEMA:
            raise NetworkSkillBlueprintError("unsupported dataset registry schema")
        if supplemental_payload.get("schema_version") != SUPPLEMENTAL_SCHEMA:
            raise NetworkSkillBlueprintError("unsupported supplemental source registry schema")

        dataset_status = {
            str(item["id"]): str(item["status"])
            for item in dataset_payload.get("datasets", [])
            if isinstance(item, dict) and item.get("id")
        }
        supplemental_status = {
            str(item["id"]): str(item["status"])
            for item in supplemental_payload.get("sources", [])
            if isinstance(item, dict) and item.get("id")
        }

        blueprints: dict[str, NetworkSkillBlueprint] = {}
        for path in sorted(root.glob("*.json")):
            blueprint = NetworkSkillBlueprint.from_dict(json.loads(path.read_text(encoding="utf-8")))
            if blueprint.skill_id in blueprints:
                raise NetworkSkillBlueprintError(f"duplicate blueprint {blueprint.skill_id}")
            blueprints[blueprint.skill_id] = blueprint

        if set(blueprints) != REQUIRED_SKILLS:
            raise NetworkSkillBlueprintError(
                f"exact independent core skill set required: {sorted(REQUIRED_SKILLS)}"
            )

        registry = cls(blueprints, dataset_status, supplemental_status)
        registry._validate_sources()
        return registry

    def _validate_sources(self) -> None:
        for blueprint in self.blueprints.values():
            for source in blueprint.source_curriculum.get("enterprise_approved", ()):
                if self.dataset_status.get(source) != "enterprise_approved":
                    raise NetworkSkillBlueprintError(
                        f"{blueprint.skill_id}: enterprise source {source} is not enterprise_approved"
                    )
            for source in blueprint.source_curriculum.get("research_only", ()):
                status = self.dataset_status.get(source) or self.supplemental_status.get(source)
                if status != "research_only":
                    raise NetworkSkillBlueprintError(
                        f"{blueprint.skill_id}: research source {source} is not research_only"
                    )
            for source in blueprint.source_curriculum.get("license_gated_high_value", ()):
                if self.supplemental_status.get(source) != "review_required":
                    raise NetworkSkillBlueprintError(
                        f"{blueprint.skill_id}: gated source {source} must remain review_required"
                    )
            for source in blueprint.source_curriculum.get("authoritative_reference", ()):
                if self.supplemental_status.get(source) != "enterprise_reference":
                    raise NetworkSkillBlueprintError(
                        f"{blueprint.skill_id}: reference {source} is not enterprise_reference"
                    )
            for source in blueprint.source_curriculum.get("future_high_value", ()):
                if source not in ALLOWED_FUTURE_SOURCES:
                    raise NetworkSkillBlueprintError(
                        f"{blueprint.skill_id}: unreviewed future source {source}"
                    )

    def fingerprints(self) -> dict[str, str]:
        return {key: self.blueprints[key].fingerprint() for key in sorted(self.blueprints)}
