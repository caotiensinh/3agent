from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from .contracts import MonitoringContractError, _compact, canonical_json, sha256_fingerprint

DISCOVERY_CANDIDATE_SCHEMA = "workspace-security-monitoring/discovery-candidate-v1"
DISCOVERY_IDENTITY_KINDS = {"ip", "mac", "dns", "device"}
MAX_CANDIDATE_EVIDENCE_REFS = 64
MAX_CANDIDATE_PROVENANCE_REFS = 32
_MAC_RE = re.compile(r"(?i)^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")
_CANDIDATE_REF_RE = re.compile(r"^candidate:(ip|mac|dns|device):sha256:[0-9a-f]{64}$")


def _utc(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize_identity(kind: str, value: str) -> str:
    identity_kind = str(kind or "").strip().lower()
    if identity_kind not in DISCOVERY_IDENTITY_KINDS:
        raise MonitoringContractError("unsupported discovery identity kind")
    text = str(value or "").strip()
    if not text or len(text) > 512 or any(ord(ch) < 32 for ch in text):
        raise MonitoringContractError("discovery identity value is invalid")
    if identity_kind == "ip":
        try:
            return str(ipaddress.ip_address(text))
        except ValueError as exc:
            raise MonitoringContractError("discovery IP identity must be a literal address") from exc
    if identity_kind == "mac":
        normalized = text.replace("-", ":").lower()
        if not _MAC_RE.fullmatch(normalized):
            raise MonitoringContractError("discovery MAC identity is invalid")
        return normalized
    if identity_kind == "dns":
        normalized = text.rstrip(".").lower()
        if not normalized or len(normalized) > 253 or any(ch.isspace() for ch in normalized):
            raise MonitoringContractError("discovery DNS identity is invalid")
        return normalized
    return text


def discovery_identity_ref(kind: str, value: str) -> str:
    """Return a typed hash; candidate contracts never retain a raw discovered target."""

    identity_kind = str(kind or "").strip().lower()
    normalized = _normalize_identity(identity_kind, value)
    digest = hashlib.sha256(
        (f"workspace-discovery-candidate-v1:{identity_kind}:" + normalized).encode("utf-8")
    ).hexdigest()
    return f"candidate:{identity_kind}:sha256:{digest}"


@dataclass(frozen=True)
class DiscoveryCandidate:
    candidate_id: str
    identity_ref: str
    first_seen: str
    last_seen: str
    observation_count: int
    confidence_basis_points: int
    provenance_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    trust_state: str = "untrusted"
    inventory_status: str = "not_enrolled"
    authority: str = "none"
    schema_version: str = DISCOVERY_CANDIDATE_SCHEMA

    @classmethod
    def build(
        cls,
        *,
        identity_kind: str,
        identity_value: str,
        first_seen: str,
        last_seen: str,
        observation_count: int,
        confidence_basis_points: int,
        provenance_refs: Iterable[str],
        evidence_refs: Iterable[str],
    ) -> "DiscoveryCandidate":
        identity_ref = discovery_identity_ref(identity_kind, identity_value)
        digest = identity_ref.rsplit(":", 1)[1]
        return cls(
            candidate_id="candidate-" + digest[:24],
            identity_ref=identity_ref,
            first_seen=first_seen,
            last_seen=last_seen,
            observation_count=observation_count,
            confidence_basis_points=confidence_basis_points,
            provenance_refs=tuple(provenance_refs),
            evidence_refs=tuple(evidence_refs),
        ).validate()

    def validate(self) -> "DiscoveryCandidate":
        object.__setattr__(self, "candidate_id", _compact(self.candidate_id, "candidate_id", max_len=128))
        ref = str(self.identity_ref or "").strip().lower()
        match = _CANDIDATE_REF_RE.fullmatch(ref)
        if match is None:
            raise MonitoringContractError("identity_ref must be a typed discovery candidate hash")
        object.__setattr__(self, "identity_ref", ref)
        expected_id = "candidate-" + ref.rsplit(":", 1)[1][:24]
        if self.candidate_id != expected_id:
            raise MonitoringContractError("candidate_id must derive from identity_ref")
        first = _utc(self.first_seen, "first_seen")
        last = _utc(self.last_seen, "last_seen")
        if datetime.fromisoformat(last.replace("Z", "+00:00")) < datetime.fromisoformat(first.replace("Z", "+00:00")):
            raise MonitoringContractError("candidate last_seen precedes first_seen")
        object.__setattr__(self, "first_seen", first)
        object.__setattr__(self, "last_seen", last)
        if isinstance(self.observation_count, bool) or not isinstance(self.observation_count, int) or not 1 <= self.observation_count <= 1_000_000_000:
            raise MonitoringContractError("candidate observation_count is outside bounds")
        if (
            isinstance(self.confidence_basis_points, bool)
            or not isinstance(self.confidence_basis_points, int)
            or not 0 <= self.confidence_basis_points <= 10_000
        ):
            raise MonitoringContractError("candidate confidence_basis_points must be within 0..10000")
        provenance = tuple(sorted(set(_compact(value, "provenance_ref", max_len=256) for value in self.provenance_refs)))
        evidence = tuple(sorted(set(_compact(value, "evidence_ref", max_len=256) for value in self.evidence_refs)))
        if not provenance or len(provenance) > MAX_CANDIDATE_PROVENANCE_REFS:
            raise MonitoringContractError("candidate provenance_refs are outside bounds")
        if not evidence or len(evidence) > MAX_CANDIDATE_EVIDENCE_REFS:
            raise MonitoringContractError("candidate evidence_refs are outside bounds")
        object.__setattr__(self, "provenance_refs", provenance)
        object.__setattr__(self, "evidence_refs", evidence)
        if self.trust_state != "untrusted":
            raise MonitoringContractError("discovery candidate trust_state must remain untrusted")
        if self.inventory_status != "not_enrolled":
            raise MonitoringContractError("discovery candidate cannot self-enroll into inventory")
        if self.authority != "none":
            raise MonitoringContractError("discovery candidate cannot grant authority")
        if self.schema_version != DISCOVERY_CANDIDATE_SCHEMA:
            raise MonitoringContractError("unsupported discovery candidate schema")
        return self

    @property
    def identity_kind(self) -> str:
        self.validate()
        return self.identity_ref.split(":", 2)[1]

    def to_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "authority": self.authority,
            "candidate_id": self.candidate_id,
            "confidence_basis_points": self.confidence_basis_points,
            "evidence_refs": list(self.evidence_refs),
            "first_seen": self.first_seen,
            "identity_ref": self.identity_ref,
            "inventory_status": self.inventory_status,
            "last_seen": self.last_seen,
            "observation_count": self.observation_count,
            "provenance_refs": list(self.provenance_refs),
            "schema_version": self.schema_version,
            "trust_state": self.trust_state,
        }

    def to_json(self) -> str:
        return canonical_json(self.to_dict())

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.to_dict())


def deduplicate_discovery_candidates(
    candidates: Iterable[DiscoveryCandidate],
    *,
    max_input_candidates: int = 10000,
    max_output_candidates: int = 10000,
) -> tuple[DiscoveryCandidate, ...]:
    """Merge exact typed candidate identities without increasing trust or authority."""

    if (
        isinstance(max_input_candidates, bool)
        or not isinstance(max_input_candidates, int)
        or not 1 <= max_input_candidates <= 100000
    ):
        raise MonitoringContractError("max_input_candidates must be an integer within 1..100000")
    if (
        isinstance(max_output_candidates, bool)
        or not isinstance(max_output_candidates, int)
        or not 1 <= max_output_candidates <= 100000
    ):
        raise MonitoringContractError("max_output_candidates must be an integer within 1..100000")

    grouped: dict[str, list[DiscoveryCandidate]] = {}
    count = 0
    for raw in candidates:
        candidate = raw.validate()
        count += 1
        if count > max_input_candidates:
            raise MonitoringContractError("discovery candidate input bound exceeded")
        grouped.setdefault(candidate.identity_ref, []).append(candidate)
    if len(grouped) > max_output_candidates:
        raise MonitoringContractError("discovery candidate output bound exceeded")

    merged: list[DiscoveryCandidate] = []
    for identity_ref in sorted(grouped):
        members = grouped[identity_ref]
        first_seen = min(item.first_seen for item in members)
        last_seen = max(item.last_seen for item in members)
        total_count = sum(item.observation_count for item in members)
        if total_count > 1_000_000_000:
            raise MonitoringContractError("merged discovery observation_count exceeds bound")
        provenance = tuple(sorted({ref for item in members for ref in item.provenance_refs}))
        evidence = tuple(sorted({ref for item in members for ref in item.evidence_refs}))
        if len(provenance) > MAX_CANDIDATE_PROVENANCE_REFS or len(evidence) > MAX_CANDIDATE_EVIDENCE_REFS:
            raise MonitoringContractError("merged discovery reference bound exceeded")
        confidence = max(item.confidence_basis_points for item in members)
        digest = identity_ref.rsplit(":", 1)[1]
        merged.append(
            DiscoveryCandidate(
                candidate_id="candidate-" + digest[:24],
                identity_ref=identity_ref,
                first_seen=first_seen,
                last_seen=last_seen,
                observation_count=total_count,
                confidence_basis_points=confidence,
                provenance_refs=provenance,
                evidence_refs=evidence,
            ).validate()
        )
    return tuple(merged)
