from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .contracts import CanonicalEvent, MonitoringContractError, _compact, canonical_json, sha256_fingerprint
from .log_pipeline import DeterministicEventRuleEngine, EventRule
from .rule_contracts import RuleSource

RULE_COMPILER_VERSION = "workspace-rule-compiler-v1"
COMPILED_RULE_SCHEMA = "workspace-security-monitoring/compiled-rule-v1"
RULE_MATCH_SCHEMA = "workspace-security-monitoring/rule-match-v1"


@dataclass(frozen=True)
class RuleMatchReceipt:
    rule_id: str
    event_id: str
    evidence_ref: str | None
    source_type: str
    category: str
    severity: str
    required_capabilities: tuple[str, ...]
    compiled_rule_fingerprint: str
    authority: str = "advisory"
    schema_version: str = RULE_MATCH_SCHEMA

    def validate(self) -> "RuleMatchReceipt":
        object.__setattr__(self, "rule_id", _compact(self.rule_id, "rule_id", max_len=128))
        object.__setattr__(self, "event_id", _compact(self.event_id, "event_id", max_len=128))
        if self.evidence_ref is not None:
            object.__setattr__(self, "evidence_ref", _compact(self.evidence_ref, "evidence_ref", max_len=256))
        object.__setattr__(self, "source_type", _compact(self.source_type, "source_type", max_len=64))
        object.__setattr__(self, "category", _compact(self.category, "category", max_len=96))
        if self.severity not in {"info", "low", "medium", "high", "critical"}:
            raise MonitoringContractError("rule match severity is unsupported")
        capabilities = tuple(sorted(set(str(value) for value in self.required_capabilities)))
        if capabilities != self.required_capabilities:
            raise MonitoringContractError("rule match capabilities must already be sorted and unique")
        fingerprint = str(self.compiled_rule_fingerprint or "").strip().lower()
        if not fingerprint.startswith("sha256:") or len(fingerprint) != 71:
            raise MonitoringContractError("compiled_rule_fingerprint must be a sha256 digest")
        object.__setattr__(self, "compiled_rule_fingerprint", fingerprint)
        if self.authority != "advisory":
            raise MonitoringContractError("rule match authority must remain advisory")
        if self.schema_version != RULE_MATCH_SCHEMA:
            raise MonitoringContractError("unsupported rule match schema")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "authority": self.authority,
            "category": self.category,
            "compiled_rule_fingerprint": self.compiled_rule_fingerprint,
            "event_id": self.event_id,
            "evidence_ref": self.evidence_ref,
            "required_capabilities": list(self.required_capabilities),
            "rule_id": self.rule_id,
            "schema_version": self.schema_version,
            "severity": self.severity,
            "source_type": self.source_type,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


@dataclass(frozen=True)
class CompiledRulePlan:
    rule_id: str
    rule_version: int
    enabled: bool
    source_fingerprint: str
    required_capabilities: tuple[str, ...]
    matcher: EventRule
    compiler_version: str = RULE_COMPILER_VERSION
    schema_version: str = COMPILED_RULE_SCHEMA

    def validate(self) -> "CompiledRulePlan":
        object.__setattr__(self, "rule_id", _compact(self.rule_id, "rule_id", max_len=128))
        if isinstance(self.rule_version, bool) or not isinstance(self.rule_version, int) or self.rule_version < 1:
            raise MonitoringContractError("compiled rule_version is invalid")
        if not isinstance(self.enabled, bool):
            raise MonitoringContractError("compiled enabled must be boolean")
        fingerprint = str(self.source_fingerprint or "").strip().lower()
        if not fingerprint.startswith("sha256:") or len(fingerprint) != 71:
            raise MonitoringContractError("source_fingerprint must be a sha256 digest")
        object.__setattr__(self, "source_fingerprint", fingerprint)
        capabilities = tuple(sorted(set(str(value) for value in self.required_capabilities)))
        if capabilities != self.required_capabilities:
            raise MonitoringContractError("compiled required_capabilities must be sorted and unique")
        self.matcher.validate()
        if self.matcher.rule_id != self.rule_id:
            raise MonitoringContractError("compiled matcher rule_id mismatch")
        if self.compiler_version != RULE_COMPILER_VERSION:
            raise MonitoringContractError("unsupported rule compiler version")
        if self.schema_version != COMPILED_RULE_SCHEMA:
            raise MonitoringContractError("unsupported compiled rule schema")
        return self

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "compiler_version": self.compiler_version,
            "enabled": self.enabled,
            "matcher": {
                "category": self.matcher.category,
                "min_severity": self.matcher.min_severity,
                "rule_id": self.matcher.rule_id,
                "source_type": self.matcher.source_type,
            },
            "required_capabilities": list(self.required_capabilities),
            "rule_id": self.rule_id,
            "rule_version": self.rule_version,
            "schema_version": self.schema_version,
            "source_fingerprint": self.source_fingerprint,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())

    def matches(self, event: CanonicalEvent) -> bool:
        self.validate()
        event.validate()
        if not self.enabled:
            return False
        return bool(DeterministicEventRuleEngine((self.matcher,)).match(event))

    def extract(self, event: CanonicalEvent) -> RuleMatchReceipt | None:
        """Return normalized metadata/evidence only. Raw message bodies are never extracted."""
        if not self.matches(event):
            return None
        return RuleMatchReceipt(
            rule_id=self.rule_id,
            event_id=event.event_id,
            evidence_ref=event.evidence_ref,
            source_type=event.source_type,
            category=event.category,
            severity=event.severity,
            required_capabilities=self.required_capabilities,
            compiled_rule_fingerprint=self.fingerprint,
        ).validate()


class DeterministicRuleCompiler:
    """Compile validated rule intent into immutable side-effect-free matcher/extractor plans."""

    def __init__(self, *, max_rules: int = 4096) -> None:
        if isinstance(max_rules, bool) or not isinstance(max_rules, int) or not 1 <= max_rules <= 10000:
            raise MonitoringContractError("max_rules must be an integer within 1..10000")
        self.max_rules = max_rules

    def compile(self, sources: Iterable[RuleSource]) -> tuple[CompiledRulePlan, ...]:
        validated: list[RuleSource] = []
        seen: set[str] = set()
        for raw in sources:
            source = raw.validate()
            if source.rule_id in seen:
                raise MonitoringContractError("duplicate rule_id in compilation set")
            seen.add(source.rule_id)
            validated.append(source)
            if len(validated) > self.max_rules:
                raise MonitoringContractError("rule compilation bound exceeded")

        plans: list[CompiledRulePlan] = []
        for source in sorted(validated, key=lambda item: item.rule_id):
            predicates = source.predicates
            matcher = EventRule(
                rule_id=source.rule_id,
                source_type=predicates.source_type,
                category=predicates.category,
                min_severity=predicates.min_severity,
            ).validate()
            plans.append(
                CompiledRulePlan(
                    rule_id=source.rule_id,
                    rule_version=source.rule_version,
                    enabled=source.enabled,
                    source_fingerprint=source.fingerprint,
                    required_capabilities=source.required_capabilities,
                    matcher=matcher,
                ).validate()
            )
        return tuple(plans)
