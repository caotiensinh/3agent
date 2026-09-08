from __future__ import annotations

import re
import unicodedata
from dataclasses import asdict, dataclass
from typing import Any, Iterable, Mapping

MICRO_TOOL_METADATA_SCHEMA = "workspace-micro-tool-metadata/v1"
MICRO_TOOL_REGISTRY_SCHEMA = "workspace-micro-tool-registry/v1"
TOOL_SELECTION_SCHEMA = "workspace-micro-tool-selection/v1"
TOOL_PRESET_SCHEMA = "workspace-micro-tool-preset/v1"
ESCALATION_DECISION_SCHEMA = "workspace-diagnostic-escalation/v1"

COST_ORDER = {"C0": 0, "C1": 1, "C2": 2, "C3": 3, "C4": 4, "C5": 5}
RISK_ORDER = {
    "read_only": 0,
    "sensitive_read": 1,
    "write": 2,
    "execute": 3,
    "destructive": 4,
}
NETWORK_ACCESS = frozenset({"none", "internal_only", "allowlisted_egress"})
EFFECTS = frozenset({"read", "network_read", "compute", "write", "execute", "control", "delete"})
INVESTIGATION_MODES = frozenset({"quick", "targeted", "full"})
_DIAGNOSTIC_EFFECTS = frozenset({"read", "network_read", "compute"})
_MODE_COST_CEILING = {"quick": "C2", "targeted": "C3", "full": "C5"}
_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{1,127}$")
_PLATFORM_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")


class RegistryValidationError(ValueError):
    """Tool metadata or preset metadata is malformed and must fail closed."""


class RegistryPolicyError(PermissionError):
    """A selection or preset request exceeds diagnostic policy boundaries."""


def _normalize_text(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", str(value).lower())
    return " ".join("".join(ch for ch in normalized if not unicodedata.combining(ch)).split())


def _tuple_strings(value: Iterable[Any], *, field: str, max_items: int = 64) -> tuple[str, ...]:
    items = tuple(str(item).strip() for item in value)
    if not items or len(items) > max_items or any(not item for item in items):
        raise RegistryValidationError(f"{field} must contain 1..{max_items} non-empty strings")
    if len(set(items)) != len(items):
        raise RegistryValidationError(f"{field} must not contain duplicates")
    return items


@dataclass(frozen=True)
class ToolMetadata:
    id: str
    platform: str
    category: str
    keywords: tuple[str, ...]
    cost: str
    risk: str
    requires_admin: bool
    network_access: str
    sensitive_outputs: bool
    effect: str
    implemented: bool = True
    schema_version: str = MICRO_TOOL_METADATA_SCHEMA

    def validate(self) -> "ToolMetadata":
        if self.schema_version != MICRO_TOOL_METADATA_SCHEMA:
            raise RegistryValidationError(f"unsupported metadata schema: {self.schema_version}")
        if not _ID_RE.fullmatch(self.id):
            raise RegistryValidationError(f"invalid tool id: {self.id!r}")
        if not _PLATFORM_RE.fullmatch(self.platform):
            raise RegistryValidationError(f"invalid platform: {self.platform!r}")
        if not _PLATFORM_RE.fullmatch(self.category):
            raise RegistryValidationError(f"invalid category: {self.category!r}")
        if self.cost not in COST_ORDER:
            raise RegistryValidationError(f"unknown cost class: {self.cost}")
        if self.risk not in RISK_ORDER:
            raise RegistryValidationError(f"unknown risk class: {self.risk}")
        if self.network_access not in NETWORK_ACCESS:
            raise RegistryValidationError(f"unknown network access class: {self.network_access}")
        if self.effect not in EFFECTS:
            raise RegistryValidationError(f"unknown effect: {self.effect}")
        keywords = _tuple_strings(self.keywords, field="keywords")
        if any(len(keyword) > 96 for keyword in keywords):
            raise RegistryValidationError("keyword exceeds 96 characters")
        if self.network_access == "none" and self.effect == "network_read":
            raise RegistryValidationError("network_read tool cannot declare network_access=none")
        if self.network_access != "none" and self.effect != "network_read":
            raise RegistryValidationError("network-access tool must use effect=network_read")
        if self.risk in {"read_only", "sensitive_read"} and self.effect in {"write", "control", "delete"}:
            raise RegistryValidationError("read risk class cannot declare a mutating effect")
        return self

    @classmethod
    def from_mapping(cls, payload: Mapping[str, Any]) -> "ToolMetadata":
        allowed = {
            "schema_version",
            "id",
            "platform",
            "category",
            "keywords",
            "cost",
            "risk",
            "requires_admin",
            "network_access",
            "sensitive_outputs",
            "effect",
            "implemented",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise RegistryValidationError(f"unknown metadata fields: {sorted(unknown)}")
        required = {
            "id",
            "platform",
            "category",
            "keywords",
            "cost",
            "risk",
            "requires_admin",
            "network_access",
            "sensitive_outputs",
            "effect",
        }
        missing = required - set(payload)
        if missing:
            raise RegistryValidationError(f"missing metadata fields: {sorted(missing)}")
        metadata = cls(
            id=str(payload["id"]),
            platform=str(payload["platform"]),
            category=str(payload["category"]),
            keywords=tuple(str(item) for item in payload["keywords"]),
            cost=str(payload["cost"]),
            risk=str(payload["risk"]),
            requires_admin=bool(payload["requires_admin"]),
            network_access=str(payload["network_access"]),
            sensitive_outputs=bool(payload["sensitive_outputs"]),
            effect=str(payload["effect"]),
            implemented=bool(payload.get("implemented", True)),
            schema_version=str(payload.get("schema_version", MICRO_TOOL_METADATA_SCHEMA)),
        )
        return metadata.validate()

    @classmethod
    def from_spec(cls, spec: Any) -> "ToolMetadata":
        return cls(
            id=str(spec.id),
            platform=str(spec.platform),
            category=str(spec.category),
            keywords=tuple(str(item) for item in spec.keywords),
            cost=str(spec.cost),
            risk=str(spec.risk),
            requires_admin=bool(spec.requires_admin),
            network_access=str(spec.network_access),
            sensitive_outputs=bool(spec.sensitive_outputs),
            effect=str(spec.effect),
            implemented=True,
        ).validate()

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["keywords"] = list(self.keywords)
        return payload


@dataclass(frozen=True)
class ToolPreset:
    id: str
    tool_ids: tuple[str, ...]
    explicit_only: bool = True
    schema_version: str = TOOL_PRESET_SCHEMA

    def validate(self) -> "ToolPreset":
        if self.schema_version != TOOL_PRESET_SCHEMA:
            raise RegistryValidationError(f"unsupported preset schema: {self.schema_version}")
        if not _ID_RE.fullmatch(self.id):
            raise RegistryValidationError(f"invalid preset id: {self.id!r}")
        _tuple_strings(self.tool_ids, field="tool_ids")
        return self


@dataclass(frozen=True)
class ToolSelectionRequest:
    query: str
    platform: str = "any"
    mode: str = "quick"
    max_tools: int = 4
    authority: Any | None = None
    admin_available: bool | None = None
    allow_external_network: bool = False
    full_authorized: bool = False
    escalated: bool = False
    cost_ceiling: str | None = None

    def validate(self) -> "ToolSelectionRequest":
        if not str(self.query).strip():
            raise ValueError("query is required")
        if self.mode not in INVESTIGATION_MODES:
            raise ValueError(f"unsupported investigation mode: {self.mode}")
        if not 1 <= int(self.max_tools) <= 64:
            raise ValueError("max_tools must be within 1..64")
        if self.cost_ceiling is not None and self.cost_ceiling not in COST_ORDER:
            raise ValueError(f"unknown cost ceiling: {self.cost_ceiling}")
        if self.mode == "full" and not (self.full_authorized or self.escalated):
            raise RegistryPolicyError("FULL_MODE_REQUIRES_EXPLICIT_OR_EVIDENCE_DRIVEN_AUTHORIZATION")
        return self


@dataclass(frozen=True)
class RejectedCandidate:
    tool_id: str
    reason_code: str


@dataclass(frozen=True)
class ToolSelectionResult:
    selected: tuple[ToolMetadata, ...]
    rejected: tuple[RejectedCandidate, ...]
    mode: str
    schema_version: str = TOOL_SELECTION_SCHEMA

    def selected_ids(self) -> tuple[str, ...]:
        return tuple(item.id for item in self.selected)


@dataclass(frozen=True)
class EscalationContext:
    evidence_sufficient: bool
    uncertainty_reduction_expected: bool
    authority_available: bool
    next_cost: str
    max_justified_cost: str
    explicit_full: bool = False


@dataclass(frozen=True)
class EscalationDecision:
    action: str
    reason_code: str
    stop: bool
    schema_version: str = ESCALATION_DECISION_SCHEMA


def decide_escalation(context: EscalationContext) -> EscalationDecision:
    if context.next_cost not in COST_ORDER or context.max_justified_cost not in COST_ORDER:
        raise RegistryValidationError("unknown escalation cost class")
    if context.evidence_sufficient:
        return EscalationDecision("stop", "EVIDENCE_SUFFICIENT", True)
    if not context.uncertainty_reduction_expected:
        return EscalationDecision("stop", "NO_MATERIAL_UNCERTAINTY_REDUCTION", True)
    if not context.authority_available:
        return EscalationDecision("stop", "AUTHORITY_UNAVAILABLE", True)
    if COST_ORDER[context.next_cost] > COST_ORDER[context.max_justified_cost] and not context.explicit_full:
        return EscalationDecision("human_decision", "COST_EXCEEDS_DIAGNOSTIC_VALUE", True)
    if context.explicit_full:
        return EscalationDecision("full", "FULL_EXPLICITLY_AUTHORIZED", False)
    return EscalationDecision("next_tool", "ESCALATION_JUSTIFIED", False)


class MicroToolRegistry:
    """Validated metadata index and deterministic minimum-evidence selector.

    This class selects tool *capabilities*. It never executes a tool and never grants
    execution authority. Exact resource/effect authorization remains the job of the
    existing TaskCapabilityAuthority at execution time.
    """

    def __init__(
        self,
        tools: Iterable[ToolMetadata],
        *,
        presets: Iterable[ToolPreset] = (),
    ) -> None:
        ordered_tools = tuple(tool.validate() for tool in tools)
        if not ordered_tools:
            raise RegistryValidationError("registry must contain at least one tool")
        ids = tuple(tool.id for tool in ordered_tools)
        if len(set(ids)) != len(ids):
            raise RegistryValidationError("duplicate tool ids")
        self._tools = tuple(sorted(ordered_tools, key=lambda item: item.id))
        self._by_id = {tool.id: tool for tool in self._tools}

        ordered_presets = tuple(preset.validate() for preset in presets)
        preset_ids = tuple(preset.id for preset in ordered_presets)
        if len(set(preset_ids)) != len(preset_ids):
            raise RegistryValidationError("duplicate preset ids")
        for preset in ordered_presets:
            unknown = set(preset.tool_ids) - set(self._by_id)
            if unknown:
                raise RegistryValidationError(
                    f"preset {preset.id} references unknown tools: {sorted(unknown)}"
                )
        self._presets = {preset.id: preset for preset in sorted(ordered_presets, key=lambda item: item.id)}

    @classmethod
    def from_metadata(
        cls,
        metadata: Iterable[Mapping[str, Any]],
        *,
        presets: Iterable[ToolPreset] = (),
    ) -> "MicroToolRegistry":
        return cls((ToolMetadata.from_mapping(item) for item in metadata), presets=presets)

    @classmethod
    def from_specs(
        cls,
        specs: Iterable[Any],
        *,
        presets: Iterable[ToolPreset] = (),
    ) -> "MicroToolRegistry":
        return cls((ToolMetadata.from_spec(spec) for spec in specs), presets=presets)

    def metadata_view(self) -> tuple[dict[str, Any], ...]:
        """Return lightweight metadata only; tool implementation code is not exposed."""
        return tuple(tool.to_dict() for tool in self._tools)

    def get(self, tool_id: str) -> ToolMetadata:
        try:
            return self._by_id[str(tool_id)]
        except KeyError as exc:
            raise RegistryValidationError(f"unknown tool: {tool_id}") from exc

    def _effective_cost_ceiling(self, request: ToolSelectionRequest) -> str:
        mode_ceiling = _MODE_COST_CEILING[request.mode]
        if request.cost_ceiling is None:
            return mode_ceiling
        if COST_ORDER[request.cost_ceiling] > COST_ORDER[mode_ceiling]:
            raise RegistryPolicyError("COST_CEILING_EXCEEDS_MODE_BOUNDARY")
        return request.cost_ceiling

    @staticmethod
    def _authority_reason(tool: ToolMetadata, authority: Any | None) -> str | None:
        if authority is None:
            return None
        allowed_tools = tuple(getattr(authority, "allowed_tools", ()))
        if tool.id not in allowed_tools:
            return "AUTHORITY_TOOL_NOT_ALLOWED"
        network_scope = str(getattr(authority, "network_scope", "deny"))
        if tool.network_access == "internal_only" and network_scope != "internal_only":
            return "AUTHORITY_NETWORK_SCOPE_NOT_ALLOWED"
        if tool.network_access == "allowlisted_egress" and network_scope != "allowlisted_egress":
            return "AUTHORITY_NETWORK_SCOPE_NOT_ALLOWED"
        return None

    def select(self, request: ToolSelectionRequest) -> ToolSelectionResult:
        request.validate()
        ceiling = self._effective_cost_ceiling(request)
        query = _normalize_text(request.query)
        platform = _normalize_text(request.platform)
        scored: list[tuple[int, int, str, ToolMetadata]] = []
        rejected: list[RejectedCandidate] = []

        for tool in self._tools:
            if not tool.implemented:
                rejected.append(RejectedCandidate(tool.id, "NOT_IMPLEMENTED"))
                continue
            if tool.platform != "any" and platform not in {"", "any"} and tool.platform not in platform:
                rejected.append(RejectedCandidate(tool.id, "PLATFORM_MISMATCH"))
                continue
            match_count = sum(1 for keyword in tool.keywords if _normalize_text(keyword) in query)
            if match_count == 0:
                rejected.append(RejectedCandidate(tool.id, "IRRELEVANT"))
                continue
            if COST_ORDER[tool.cost] > COST_ORDER[ceiling]:
                rejected.append(RejectedCandidate(tool.id, "COST_ABOVE_MODE"))
                continue
            if tool.effect not in _DIAGNOSTIC_EFFECTS:
                rejected.append(RejectedCandidate(tool.id, "NON_DIAGNOSTIC_EFFECT"))
                continue
            if tool.network_access == "allowlisted_egress" and not request.allow_external_network:
                rejected.append(RejectedCandidate(tool.id, "EXTERNAL_EGRESS_DISABLED"))
                continue
            if tool.requires_admin and request.admin_available is False:
                rejected.append(RejectedCandidate(tool.id, "ADMIN_AUTHORITY_UNAVAILABLE"))
                continue
            authority_reason = self._authority_reason(tool, request.authority)
            if authority_reason is not None:
                rejected.append(RejectedCandidate(tool.id, authority_reason))
                continue
            scored.append((COST_ORDER[tool.cost], -match_count, tool.id, tool))

        scored.sort(key=lambda item: (item[0], item[1], item[2]))
        selected = tuple(item[3] for item in scored[: request.max_tools])
        selected_ids = {tool.id for tool in selected}
        for _, _, tool_id, _ in scored[request.max_tools :]:
            if tool_id not in selected_ids:
                rejected.append(RejectedCandidate(tool_id, "MAX_TOOL_LIMIT"))
        rejected.sort(key=lambda item: (item.tool_id, item.reason_code))
        return ToolSelectionResult(selected=selected, rejected=tuple(rejected), mode=request.mode)

    def expand_preset(
        self,
        preset_id: str,
        *,
        full_authorized: bool,
        authority: Any | None = None,
    ) -> tuple[ToolMetadata, ...]:
        try:
            preset = self._presets[str(preset_id)]
        except KeyError as exc:
            raise RegistryValidationError(f"unknown preset: {preset_id}") from exc
        if preset.explicit_only and not full_authorized:
            raise RegistryPolicyError("FULL_PRESET_REQUIRES_EXPLICIT_AUTHORIZATION")
        result: list[ToolMetadata] = []
        for tool_id in preset.tool_ids:
            tool = self._by_id[tool_id]
            if not tool.implemented:
                raise RegistryPolicyError(f"PRESET_TOOL_NOT_IMPLEMENTED:{tool_id}")
            if tool.effect not in _DIAGNOSTIC_EFFECTS:
                raise RegistryPolicyError(f"PRESET_NON_DIAGNOSTIC_TOOL:{tool_id}")
            authority_reason = self._authority_reason(tool, authority)
            if authority_reason is not None:
                raise RegistryPolicyError(f"{authority_reason}:{tool_id}")
            result.append(tool)
        return tuple(result)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": MICRO_TOOL_REGISTRY_SCHEMA,
            "tools": [tool.to_dict() for tool in self._tools],
            "presets": [asdict(self._presets[key]) for key in sorted(self._presets)],
        }
