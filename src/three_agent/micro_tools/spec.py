from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType
from typing import Any, Mapping
import math
import re


_TOOL_ID_RE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2,}$")
_SEMVER_RE = re.compile(r"^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)$")
_EXECUTOR_REF_RE = re.compile(
    r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:"
    r"[A-Za-z_][A-Za-z0-9_]*$"
)
_FORBIDDEN_ID_SEGMENT_RE = re.compile(
    r"(?:^v\d+$|_v\d+$|_(?:new|final|old|backup|bak|copy)(?:\d+)?$)"
)


class ToolSpecValidationError(ValueError):
    """Raised when micro-tool metadata violates the canonical ToolSpec contract."""


class ToolCost(str, Enum):
    C0 = "C0"
    C1 = "C1"
    C2 = "C2"
    C3 = "C3"
    C4 = "C4"
    C5 = "C5"


class ToolEffect(str, Enum):
    READ_ONLY = "read_only"
    LOCAL_EVIDENCE_WRITE = "local_evidence_write"
    ACTIVE_NETWORK_READONLY = "active_network_readonly"
    REMEDIATION = "remediation"


class ToolPrivilege(str, Enum):
    USER = "user"
    USER_OR_ELEVATED_WHEN_REQUIRED = "user_or_elevated_when_required"
    ADMIN = "admin"
    ROOT = "root"
    CAPABILITY_SPECIFIC = "capability_specific"


class ToolSensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    HIGH_SENSITIVITY = "high_sensitivity"


class ToolNetworkRequirement(str, Enum):
    NONE = "none"
    LOCALHOST = "localhost"
    LAN = "lan"
    PUBLIC = "public"


class ToolPlatform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    NETWORK = "network"
    CAMERA = "camera"
    SWITCH = "switch"
    CROSS_PLATFORM = "cross_platform"


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ToolSpecValidationError("preset mapping keys must be strings")
        return MappingProxyType({key: _freeze(value[key]) for key in sorted(value)})
    if isinstance(value, (tuple, list)):
        return tuple(_freeze(item) for item in value)
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ToolSpecValidationError("preset numbers must be finite")
        return value
    raise ToolSpecValidationError(
        f"preset contains unsupported value type: {type(value).__name__}"
    )


def _thaw(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _thaw(value[key]) for key in sorted(value)}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


def _require_text(value: str, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ToolSpecValidationError(f"{field_name} must be a non-empty string")
    return value


def _require_unique_texts(values: tuple[str, ...], field_name: str) -> None:
    if not isinstance(values, tuple):
        raise ToolSpecValidationError(f"{field_name} must be a tuple")
    if not values:
        raise ToolSpecValidationError(f"{field_name} must be non-empty")
    if any(not isinstance(value, str) or not value.strip() for value in values):
        raise ToolSpecValidationError(f"{field_name} must contain only non-empty strings")
    if len(set(values)) != len(values):
        raise ToolSpecValidationError(f"{field_name} must not contain duplicates")


def _parse_enum(enum_type: type[Enum], value: Any, field_name: str) -> Enum:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        raise ToolSpecValidationError(f"{field_name} has an unsupported value: {value!r}") from exc


@dataclass(frozen=True, slots=True)
class ToolSpec:
    """Metadata-only contract for one bounded WorkSpace micro-tool capability."""

    id: str
    version: str
    title: str
    platforms: tuple[ToolPlatform, ...]
    category: str
    intents: tuple[str, ...]
    keywords: tuple[str, ...]
    cost: ToolCost
    effect: ToolEffect
    privilege: ToolPrivilege
    network_requirement: ToolNetworkRequirement
    sensitivity: ToolSensitivity
    timeout_seconds: int
    max_output_bytes: int
    executor_ref: str
    preset: Mapping[str, Any]
    input_schema_ref: str
    output_schema_ref: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "preset", _freeze(self.preset))
        self.validate()

    def validate(self) -> None:
        _require_text(self.id, "id")
        if not _TOOL_ID_RE.fullmatch(self.id):
            raise ToolSpecValidationError(
                "id must be a lowercase dotted identifier with at least three segments"
            )
        if any(_FORBIDDEN_ID_SEGMENT_RE.search(segment) for segment in self.id.split(".")):
            raise ToolSpecValidationError(
                "id must not encode implementation versions or copy/archive suffixes"
            )

        _require_text(self.version, "version")
        if not _SEMVER_RE.fullmatch(self.version):
            raise ToolSpecValidationError("version must use MAJOR.MINOR.PATCH semantic versioning")

        _require_text(self.title, "title")
        _require_text(self.category, "category")
        _require_unique_texts(self.intents, "intents")
        _require_unique_texts(self.keywords, "keywords")

        if not isinstance(self.platforms, tuple) or not self.platforms:
            raise ToolSpecValidationError("platforms must be a non-empty tuple")
        if any(not isinstance(platform, ToolPlatform) for platform in self.platforms):
            raise ToolSpecValidationError("platforms must contain ToolPlatform values")
        if len(set(self.platforms)) != len(self.platforms):
            raise ToolSpecValidationError("platforms must not contain duplicates")

        for field_name, value, enum_type in (
            ("cost", self.cost, ToolCost),
            ("effect", self.effect, ToolEffect),
            ("privilege", self.privilege, ToolPrivilege),
            ("network_requirement", self.network_requirement, ToolNetworkRequirement),
            ("sensitivity", self.sensitivity, ToolSensitivity),
        ):
            if not isinstance(value, enum_type):
                raise ToolSpecValidationError(f"{field_name} must be a {enum_type.__name__} value")

        if isinstance(self.timeout_seconds, bool) or not isinstance(self.timeout_seconds, int):
            raise ToolSpecValidationError("timeout_seconds must be an integer")
        if self.timeout_seconds <= 0:
            raise ToolSpecValidationError("timeout_seconds must be greater than zero")

        if isinstance(self.max_output_bytes, bool) or not isinstance(self.max_output_bytes, int):
            raise ToolSpecValidationError("max_output_bytes must be an integer")
        if self.max_output_bytes <= 0:
            raise ToolSpecValidationError("max_output_bytes must be greater than zero")

        _require_text(self.executor_ref, "executor_ref")
        if not _EXECUTOR_REF_RE.fullmatch(self.executor_ref):
            raise ToolSpecValidationError(
                "executor_ref must use the form 'python.module:function' without importing it"
            )

        if not isinstance(self.preset, Mapping):
            raise ToolSpecValidationError("preset must be a mapping")

        _require_text(self.input_schema_ref, "input_schema_ref")
        _require_text(self.output_schema_ref, "output_schema_ref")

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ToolSpec":
        if not isinstance(raw, Mapping):
            raise ToolSpecValidationError("ToolSpec input must be a mapping")

        expected = {
            "id",
            "version",
            "title",
            "platforms",
            "category",
            "intents",
            "keywords",
            "cost",
            "effect",
            "privilege",
            "network_requirement",
            "sensitivity",
            "timeout_seconds",
            "max_output_bytes",
            "executor_ref",
            "preset",
            "input_schema_ref",
            "output_schema_ref",
        }
        actual = set(raw)
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        if missing:
            raise ToolSpecValidationError(f"missing ToolSpec fields: {', '.join(missing)}")
        if extra:
            raise ToolSpecValidationError(f"unsupported ToolSpec fields: {', '.join(extra)}")

        platforms_raw = raw["platforms"]
        intents_raw = raw["intents"]
        keywords_raw = raw["keywords"]
        if not isinstance(platforms_raw, (list, tuple)):
            raise ToolSpecValidationError("platforms must be a list or tuple")
        if not isinstance(intents_raw, (list, tuple)):
            raise ToolSpecValidationError("intents must be a list or tuple")
        if not isinstance(keywords_raw, (list, tuple)):
            raise ToolSpecValidationError("keywords must be a list or tuple")

        preset_raw = raw["preset"]
        if not isinstance(preset_raw, Mapping):
            raise ToolSpecValidationError("preset must be a mapping")

        return cls(
            id=raw["id"],
            version=raw["version"],
            title=raw["title"],
            platforms=tuple(
                _parse_enum(ToolPlatform, value, "platforms") for value in platforms_raw
            ),
            category=raw["category"],
            intents=tuple(intents_raw),
            keywords=tuple(keywords_raw),
            cost=_parse_enum(ToolCost, raw["cost"], "cost"),
            effect=_parse_enum(ToolEffect, raw["effect"], "effect"),
            privilege=_parse_enum(ToolPrivilege, raw["privilege"], "privilege"),
            network_requirement=_parse_enum(
                ToolNetworkRequirement, raw["network_requirement"], "network_requirement"
            ),
            sensitivity=_parse_enum(ToolSensitivity, raw["sensitivity"], "sensitivity"),
            timeout_seconds=raw["timeout_seconds"],
            max_output_bytes=raw["max_output_bytes"],
            executor_ref=raw["executor_ref"],
            preset=preset_raw,
            input_schema_ref=raw["input_schema_ref"],
            output_schema_ref=raw["output_schema_ref"],
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "title": self.title,
            "platforms": [platform.value for platform in self.platforms],
            "category": self.category,
            "intents": list(self.intents),
            "keywords": list(self.keywords),
            "cost": self.cost.value,
            "effect": self.effect.value,
            "privilege": self.privilege.value,
            "network_requirement": self.network_requirement.value,
            "sensitivity": self.sensitivity.value,
            "timeout_seconds": self.timeout_seconds,
            "max_output_bytes": self.max_output_bytes,
            "executor_ref": self.executor_ref,
            "preset": _thaw(self.preset),
            "input_schema_ref": self.input_schema_ref,
            "output_schema_ref": self.output_schema_ref,
        }
