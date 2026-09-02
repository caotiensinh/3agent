from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from .contracts import (
    COLLECTOR_CAPABILITIES,
    MonitoringContractError,
    SEVERITIES,
    _compact,
    canonical_json,
    sha256_fingerprint,
)

RULE_SOURCE_SCHEMA = "workspace-security-monitoring/rule-source-v1"
MAX_RULE_SOURCE_BYTES = 64 * 1024
_ALLOWED_TOP_LEVEL_FIELDS = {
    "schema_version",
    "rule_id",
    "rule_version",
    "enabled",
    "predicates",
    "required_capabilities",
}
_ALLOWED_PREDICATE_FIELDS = {"source_type", "category", "min_severity"}


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise MonitoringContractError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _optional_compact(value: Any, field_name: str, *, max_len: int) -> str | None:
    if value is None:
        return None
    return _compact(str(value), field_name, max_len=max_len)


@dataclass(frozen=True)
class RulePredicates:
    """Side-effect-free event predicates; execution targets never belong here."""

    source_type: str | None = None
    category: str | None = None
    min_severity: str | None = None

    def validate(self) -> "RulePredicates":
        object.__setattr__(self, "source_type", _optional_compact(self.source_type, "source_type", max_len=64))
        object.__setattr__(self, "category", _optional_compact(self.category, "category", max_len=96))
        if self.min_severity not in {None, *SEVERITIES}:
            raise MonitoringContractError("rule min_severity is unsupported")
        if self.source_type is None and self.category is None and self.min_severity is None:
            raise MonitoringContractError("rule requires at least one deterministic predicate")
        return self

    def to_dict(self) -> dict[str, str | None]:
        self.validate()
        return {
            "category": self.category,
            "min_severity": self.min_severity,
            "source_type": self.source_type,
        }


@dataclass(frozen=True)
class RuleSource:
    """Validated detection intent. It can request capabilities but can never authorize them."""

    rule_id: str
    rule_version: int
    enabled: bool
    predicates: RulePredicates
    required_capabilities: tuple[str, ...] = ()
    schema_version: str = RULE_SOURCE_SCHEMA

    def validate(self) -> "RuleSource":
        object.__setattr__(self, "rule_id", _compact(self.rule_id, "rule_id", max_len=128))
        if isinstance(self.rule_version, bool) or not isinstance(self.rule_version, int) or not 1 <= self.rule_version <= 1_000_000:
            raise MonitoringContractError("rule_version must be an integer within 1..1000000")
        if not isinstance(self.enabled, bool):
            raise MonitoringContractError("rule enabled must be boolean")
        self.predicates.validate()
        capabilities = tuple(str(value or "").strip() for value in self.required_capabilities)
        if any(not value for value in capabilities):
            raise MonitoringContractError("required_capabilities cannot contain empty values")
        if len(capabilities) != len(set(capabilities)):
            raise MonitoringContractError("required_capabilities cannot contain duplicates")
        unknown = set(capabilities) - COLLECTOR_CAPABILITIES
        if unknown:
            raise MonitoringContractError(f"unknown rule capability requirements: {sorted(unknown)}")
        if len(capabilities) > len(COLLECTOR_CAPABILITIES):
            raise MonitoringContractError("required_capabilities exceed capability vocabulary")
        object.__setattr__(self, "required_capabilities", tuple(sorted(capabilities)))
        if self.schema_version != RULE_SOURCE_SCHEMA:
            raise MonitoringContractError(f"unsupported rule source schema: {self.schema_version}")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "enabled": self.enabled,
            "predicates": self.predicates.to_dict(),
            "required_capabilities": list(self.required_capabilities),
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "schema_version": self.schema_version,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


def parse_rule_source(payload: str | bytes) -> RuleSource:
    """Parse one bounded JSON rule with strict fields and duplicate-key rejection."""

    if isinstance(payload, bytes):
        raw = payload
        try:
            text = raw.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise MonitoringContractError("rule source must be UTF-8") from exc
    elif isinstance(payload, str):
        text = payload
        raw = text.encode("utf-8")
    else:
        raise MonitoringContractError("rule source must be str or bytes")
    if not raw or len(raw) > MAX_RULE_SOURCE_BYTES:
        raise MonitoringContractError("rule source byte size is outside bounds")
    try:
        decoded = json.loads(text, object_pairs_hook=_strict_object)
    except MonitoringContractError:
        raise
    except (json.JSONDecodeError, TypeError) as exc:
        raise MonitoringContractError("rule source must be valid JSON") from exc
    if not isinstance(decoded, dict):
        raise MonitoringContractError("rule source root must be an object")
    unknown = set(decoded) - _ALLOWED_TOP_LEVEL_FIELDS
    missing = _ALLOWED_TOP_LEVEL_FIELDS - set(decoded)
    if unknown:
        raise MonitoringContractError(f"unknown rule source fields: {sorted(unknown)}")
    if missing:
        raise MonitoringContractError(f"missing rule source fields: {sorted(missing)}")
    predicates_payload = decoded["predicates"]
    if not isinstance(predicates_payload, dict):
        raise MonitoringContractError("predicates must be an object")
    predicate_unknown = set(predicates_payload) - _ALLOWED_PREDICATE_FIELDS
    predicate_missing = _ALLOWED_PREDICATE_FIELDS - set(predicates_payload)
    if predicate_unknown:
        raise MonitoringContractError(f"unknown predicate fields: {sorted(predicate_unknown)}")
    if predicate_missing:
        raise MonitoringContractError(f"missing predicate fields: {sorted(predicate_missing)}")
    capabilities = decoded["required_capabilities"]
    if not isinstance(capabilities, list) or any(not isinstance(value, str) for value in capabilities):
        raise MonitoringContractError("required_capabilities must be a string array")
    return RuleSource(
        rule_id=decoded["rule_id"],
        rule_version=decoded["rule_version"],
        enabled=decoded["enabled"],
        predicates=RulePredicates(
            source_type=predicates_payload["source_type"],
            category=predicates_payload["category"],
            min_severity=predicates_payload["min_severity"],
        ),
        required_capabilities=tuple(capabilities),
        schema_version=decoded["schema_version"],
    ).validate()
