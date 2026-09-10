from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

RELEASE_TRANSPORT_SCHEMA = "workspace-security-monitoring/release-transport-readiness-v1"
MAX_CHECKS = 64
_ASSESSMENT_ID_RE = re.compile(r"^release-transport:[0-9a-f]{24}$")


def _compact(value: str, field: str, max_len: int = 128) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or "://" in text or any(ch.isspace() for ch in text):
        raise MonitoringContractError(f"{field} must be a bounded compact identifier")
    return text


def _normalize_checks(values: Iterable[str], *, field: str, require_nonempty: bool) -> tuple[str, ...]:
    checks = tuple(sorted(_compact(item, field, 160) for item in values))
    if require_nonempty and not checks:
        raise MonitoringContractError(f"{field} must not be empty")
    if len(checks) > MAX_CHECKS or len(set(checks)) != len(checks):
        raise MonitoringContractError(f"{field} values are duplicated or exceed bounds")
    return checks


def _derive_blockers(
    *,
    branch_protected: bool,
    active_ruleset_count: int,
    observed_required_status_checks: tuple[str, ...],
    required_checks: tuple[str, ...],
) -> tuple[str, ...]:
    blockers: list[str] = []
    if not branch_protected:
        blockers.append("branch_protection_disabled")
    if active_ruleset_count < 1:
        blockers.append("no_active_ruleset")
    missing = sorted(set(required_checks) - set(observed_required_status_checks))
    blockers.extend(f"missing_required_check:{name}" for name in missing)
    return tuple(blockers)


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
        if (
            isinstance(self.active_ruleset_count, bool)
            or not isinstance(self.active_ruleset_count, int)
            or not 0 <= self.active_ruleset_count <= 128
        ):
            raise MonitoringContractError("active_ruleset_count is out of bounds")
        object.__setattr__(
            self,
            "required_status_checks",
            _normalize_checks(
                self.required_status_checks,
                field="required_status_check",
                require_nonempty=False,
            ),
        )
        return self


@dataclass(frozen=True)
class ReleaseTransportAssessment:
    branch: str
    branch_protected: bool
    active_ruleset_count: int
    observed_required_status_checks: tuple[str, ...]
    required_checks: tuple[str, ...]
    status: str
    blockers: tuple[str, ...]
    assessment_id: str
    source_ref: str
    authority: str = "read_only"
    schema_version: str = RELEASE_TRANSPORT_SCHEMA

    @classmethod
    def assess(
        cls,
        snapshot: ReleaseTransportSnapshot,
        *,
        required_checks: Iterable[str],
    ) -> "ReleaseTransportAssessment":
        snapshot.validate()
        expected = _normalize_checks(
            required_checks,
            field="expected_status_check",
            require_nonempty=True,
        )
        blockers = _derive_blockers(
            branch_protected=snapshot.branch_protected,
            active_ruleset_count=snapshot.active_ruleset_count,
            observed_required_status_checks=snapshot.required_status_checks,
            required_checks=expected,
        )
        status = "ready" if not blockers else "blocked_external"
        provisional = cls(
            branch=snapshot.branch,
            branch_protected=snapshot.branch_protected,
            active_ruleset_count=snapshot.active_ruleset_count,
            observed_required_status_checks=snapshot.required_status_checks,
            required_checks=expected,
            status=status,
            blockers=blockers,
            assessment_id="release-transport:" + "0" * 24,
            source_ref=snapshot.source_ref,
        )
        assessment_id = "release-transport:" + sha256_fingerprint(
            provisional._identity_payload()
        ).split(":", 1)[1][:24]
        return cls(
            branch=snapshot.branch,
            branch_protected=snapshot.branch_protected,
            active_ruleset_count=snapshot.active_ruleset_count,
            observed_required_status_checks=snapshot.required_status_checks,
            required_checks=expected,
            status=status,
            blockers=blockers,
            assessment_id=assessment_id,
            source_ref=snapshot.source_ref,
        ).validate()

    def _identity_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "branch": self.branch,
            "branch_protected": self.branch_protected,
            "active_ruleset_count": self.active_ruleset_count,
            "observed_required_status_checks": list(self.observed_required_status_checks),
            "required_checks": list(self.required_checks),
            "source_ref": self.source_ref,
            "status": self.status,
            "blockers": list(self.blockers),
            "authority": self.authority,
        }

    def validate(self) -> "ReleaseTransportAssessment":
        if self.schema_version != RELEASE_TRANSPORT_SCHEMA:
            raise MonitoringContractError("unsupported release transport readiness schema")
        if self.authority != "read_only":
            raise MonitoringContractError("release transport assessment must remain read_only")
        object.__setattr__(self, "branch", _compact(self.branch, "branch"))
        object.__setattr__(self, "source_ref", _compact(self.source_ref, "source_ref", 180))
        if not isinstance(self.branch_protected, bool):
            raise MonitoringContractError("branch_protected must be boolean")
        if (
            isinstance(self.active_ruleset_count, bool)
            or not isinstance(self.active_ruleset_count, int)
            or not 0 <= self.active_ruleset_count <= 128
        ):
            raise MonitoringContractError("active_ruleset_count is out of bounds")
        observed = _normalize_checks(
            self.observed_required_status_checks,
            field="required_status_check",
            require_nonempty=False,
        )
        required = _normalize_checks(
            self.required_checks,
            field="expected_status_check",
            require_nonempty=True,
        )
        object.__setattr__(self, "observed_required_status_checks", observed)
        object.__setattr__(self, "required_checks", required)

        expected_blockers = _derive_blockers(
            branch_protected=self.branch_protected,
            active_ruleset_count=self.active_ruleset_count,
            observed_required_status_checks=observed,
            required_checks=required,
        )
        if self.blockers != expected_blockers:
            raise MonitoringContractError("release transport blockers do not match observed state")
        expected_status = "ready" if not expected_blockers else "blocked_external"
        if self.status != expected_status:
            raise MonitoringContractError("release transport status does not match observed state")
        if not _ASSESSMENT_ID_RE.fullmatch(str(self.assessment_id or "")):
            raise MonitoringContractError("assessment_id is invalid")
        expected_id = "release-transport:" + sha256_fingerprint(self._identity_payload()).split(":", 1)[1][:24]
        if self.assessment_id != expected_id:
            raise MonitoringContractError("assessment_id does not match assessment content")
        return self

    @property
    def ready(self) -> bool:
        self.validate()
        return self.status == "ready"

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "assessment_id": self.assessment_id,
            **self._identity_payload(),
        }
