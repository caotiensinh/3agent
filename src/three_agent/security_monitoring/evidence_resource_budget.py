from __future__ import annotations

from dataclasses import dataclass

from .contracts import MonitoringContractError

RESOURCE_BUDGET_SCHEMA = "workspace-security-monitoring/evidence-resource-budget-v1"


@dataclass(frozen=True)
class EvidenceResourceBudget:
    max_evidence_items: int = 256
    max_total_bytes: int = 16 * 1024 * 1024
    max_window_seconds: int = 24 * 60 * 60
    max_provenance_refs: int = 16
    schema_version: str = RESOURCE_BUDGET_SCHEMA

    def validate(self) -> "EvidenceResourceBudget":
        if self.schema_version != RESOURCE_BUDGET_SCHEMA:
            raise MonitoringContractError("unsupported resource budget schema")
        limits = {
            "max_evidence_items": (self.max_evidence_items, 1, 4096),
            "max_total_bytes": (self.max_total_bytes, 1024, 256 * 1024 * 1024),
            "max_window_seconds": (self.max_window_seconds, 1, 7 * 24 * 60 * 60),
            "max_provenance_refs": (self.max_provenance_refs, 1, 128),
        }
        for name, (value, minimum, maximum) in limits.items():
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                raise MonitoringContractError(f"{name} is out of bounds")
        return self

    def admit(self, *, evidence_items: int, total_bytes: int, window_seconds: int, provenance_refs: int) -> bool:
        self.validate()
        values = (evidence_items, total_bytes, window_seconds, provenance_refs)
        if any(isinstance(value, bool) or not isinstance(value, int) or value < 0 for value in values):
            raise MonitoringContractError("resource usage values must be non-negative integers")
        return (
            evidence_items <= self.max_evidence_items
            and total_bytes <= self.max_total_bytes
            and window_seconds <= self.max_window_seconds
            and provenance_refs <= self.max_provenance_refs
        )

    def require_admitted(self, **usage: int) -> None:
        if not self.admit(**usage):
            raise MonitoringContractError("evidence resource budget exceeded")
