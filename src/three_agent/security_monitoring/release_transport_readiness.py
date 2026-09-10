from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

RELEASE_TRANSPORT_SCHEMA = "workspace-security-monitoring/release-transport-readiness-v1"
MAX_CHECKS = 64


def _compact(value: str, field: str, max_len: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or "://" in text or any(ch.isspace() for ch in text):
        raise MonitoringContractError(f"{field} must be a bounded compact identifier")
    return text


@dataclass(frozen=True)
class ReleaseTransportSnapshot:
    branch: str
    branch_protected: bool
    active_ruleset_count: int
    required_status_checks: tuple[str, ...]
    source_ref: str

    def validate(self) -> "ReleaseTransportSnapshot":
        object.__setattr__(self, "branch", _compact(self.branch, "branch"))
        object.__setattr__(self, "source_ref", _compact(self.source_ref, "source_ref", 180))
        if not isinstance(self.branch_protected, bool):
            raise MonitoringContractError("branch_protected must be boolean")
        if isinstance(self.active_ruleset_count, bool) or not isinstance(self.active_ruleset_count, int) or not 0 <= self.active_ruleset_count <= 128:
            raise MonitoringContractError("active_ruleset_count is out of bounds")
        checks = tuple(sorted(_compact(item, "required_status_check", 160) for item in self.required_status_checks))
        if len(checks) > MAX_CHECKS or len(set(checks)) != len(checks):
            raise MonitoringContractError("required status checks are duplicated or exceed bounds")
        object.__setattr__(self, "required_status_checks", checks)
        return self


@dataclass(frozen=True)
class ReleaseTransportAssessment:
    status: str
    blockers: tuple[str, ...]
    assessment_id: str
    source_ref: str
    authority: str = "read_only"
    schema_version: str = RELEASE_TRANSPORT_SCHEMA

    @classmethod
    def assess(cls, snapshot: ReleaseTransportSnapshot, *, required_checks: Iterable[str]) -> "ReleaseTransportAssessment":
        snapshot.validate()
        expected = tuple(sorted(_compact(item, "expected_status_check", 160) for item in required_checks))
        if not expected or len(expected) > MAX_CHECKS or len(set(expected)) != len(expected):
            raise MonitoringContractError("expected status checks are empty, duplicated, or exceed bounds")
        blockers: list[str] = []
        if not snapshot.branch_protected:
            blockers.append("branch_protection_disabled")
        if snapshot.active_ruleset_count < 1:
            blockers.append("no_active_ruleset")
        missing = sorted(set(expected) - set(snapshot.required_status_checks))
        blockers.extend(f"missing_required_check:{name}" for name in missing)
        status = "ready" if not blockers else "blocked_external"
        identity = {
            "schema_version": RELEASE_TRANSPORT_SCHEMA,
            "branch": snapshot.branch,
            "source_ref": snapshot.source_ref,
            "status": status,
            "blockers": blockers,
            "required_checks": expected,
            "authority": "read_only",
        }
        assessment_id = "release-transport:" + sha256_fingerprint(identity).split(":", 1)[1][:24]
        return cls(status, tuple(blockers), assessment_id, snapshot.source_ref)

    @property
    def ready(self) -> bool:
        return self.status == "ready"
