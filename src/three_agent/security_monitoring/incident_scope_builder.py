from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

SCOPE_LINK_SCHEMA = "workspace-security-forensics/scope-link-v1"
INCIDENT_SCOPE_SCHEMA = "workspace-security-forensics/incident-scope-v1"
SCOPE_RELATIONS = frozenset({"authentication", "process", "network", "dns", "file_transfer", "shared_identity"})
MAX_SCOPE_LINKS = 20_000
MAX_SCOPE_ASSETS = 4096
MAX_SCOPE_HOPS = 8

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$")


def _identifier(value: str, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _ID_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a compact identifier")
    if "://" in text or "/" in text or "\\" in text:
        raise MonitoringContractError(f"{field_name} must not expose a URL or filesystem path")
    return text


def _timestamp(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError(f"{field_name} must include timezone")
    return text


def _strict_bool(value: bool, field_name: str) -> bool:
    if not isinstance(value, bool):
        raise MonitoringContractError(f"{field_name} must be boolean")
    return value


@dataclass(frozen=True)
class ScopeEvidenceLink:
    link_id: str
    from_asset_ref: str
    to_asset_ref: str
    relation: str
    observed_at: str
    evidence_ref: str
    schema_version: str = SCOPE_LINK_SCHEMA

    def validate(self) -> "ScopeEvidenceLink":
        object.__setattr__(self, "link_id", _identifier(self.link_id, "link_id", max_len=128))
        object.__setattr__(self, "from_asset_ref", _identifier(self.from_asset_ref, "from_asset_ref", max_len=128))
        object.__setattr__(self, "to_asset_ref", _identifier(self.to_asset_ref, "to_asset_ref", max_len=128))
        if self.from_asset_ref == self.to_asset_ref:
            raise MonitoringContractError("scope evidence link requires distinct assets")
        if self.relation not in SCOPE_RELATIONS:
            raise MonitoringContractError("unsupported incident scope relation")
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "evidence_ref", _identifier(self.evidence_ref, "evidence_ref", max_len=128))
        if self.schema_version != SCOPE_LINK_SCHEMA:
            raise MonitoringContractError("unsupported scope link schema")
        return self


@dataclass(frozen=True)
class ScopedAsset:
    asset_ref: str
    depth: int
    parent_asset_ref: str | None
    relation: str | None
    evidence_ref: str | None


@dataclass(frozen=True)
class IncidentScopeAssessment:
    seed_asset_refs: tuple[str, ...]
    authorized_asset_refs: tuple[str, ...]
    scoped_assets: tuple[ScopedAsset, ...]
    evidence_refs: tuple[str, ...]
    truncated: bool
    active_discovery_performed: bool = False
    authority: str = "advisory"
    schema_version: str = INCIDENT_SCOPE_SCHEMA

    def validate(self) -> "IncidentScopeAssessment":
        seeds = tuple(sorted({_identifier(v, "seed_asset_ref", max_len=128) for v in self.seed_asset_refs}))
        authorized = tuple(sorted({_identifier(v, "authorized_asset_ref", max_len=128) for v in self.authorized_asset_refs}))
        if not seeds or not authorized:
            raise MonitoringContractError("incident scope requires seed and authorized assets")
        if not set(seeds).issubset(set(authorized)):
            raise MonitoringContractError("seed assets must exist in authorized inventory")
        object.__setattr__(self, "seed_asset_refs", seeds)
        object.__setattr__(self, "authorized_asset_refs", authorized)
        if not self.scoped_assets or len(self.scoped_assets) > MAX_SCOPE_ASSETS:
            raise MonitoringContractError("scoped asset count is invalid")
        refs = [asset.asset_ref for asset in self.scoped_assets]
        if len(refs) != len(set(refs)):
            raise MonitoringContractError("scoped assets must be unique")
        if not set(refs).issubset(set(authorized)):
            raise MonitoringContractError("incident scope exceeds authorized inventory")
        for asset in self.scoped_assets:
            _identifier(asset.asset_ref, "asset_ref", max_len=128)
            if isinstance(asset.depth, bool) or not isinstance(asset.depth, int) or not 0 <= asset.depth <= MAX_SCOPE_HOPS:
                raise MonitoringContractError("scope asset depth is invalid")
            if asset.parent_asset_ref is not None:
                _identifier(asset.parent_asset_ref, "parent_asset_ref", max_len=128)
            if asset.relation is not None and asset.relation not in SCOPE_RELATIONS:
                raise MonitoringContractError("scope asset relation is invalid")
            if asset.evidence_ref is not None:
                _identifier(asset.evidence_ref, "evidence_ref", max_len=128)
        object.__setattr__(self, "evidence_refs", tuple(sorted({_identifier(v, "evidence_ref", max_len=128) for v in self.evidence_refs})))
        _strict_bool(self.truncated, "truncated")
        _strict_bool(self.active_discovery_performed, "active_discovery_performed")
        if self.active_discovery_performed:
            raise MonitoringContractError("incident scope builder must not perform active discovery")
        if self.authority != "advisory":
            raise MonitoringContractError("incident scope assessment must remain advisory")
        if self.schema_version != INCIDENT_SCOPE_SCHEMA:
            raise MonitoringContractError("unsupported incident scope schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "seed_asset_refs": list(self.seed_asset_refs),
            "authorized_asset_refs": list(self.authorized_asset_refs),
            "scoped_assets": [asdict(asset) for asset in self.scoped_assets],
            "evidence_refs": list(self.evidence_refs),
            "truncated": self.truncated,
            "active_discovery_performed": self.active_discovery_performed,
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def build_incident_scope(
    links: Iterable[ScopeEvidenceLink],
    *,
    seed_asset_refs: Iterable[str],
    authorized_asset_refs: Iterable[str],
    max_assets: int = 256,
    max_hops: int = 4,
) -> IncidentScopeAssessment:
    """Expand incident scope only through evidence and pre-authorized inventory.

    No ping, port scan, DNS enumeration, directory query, remote login, packet
    acquisition, or other discovery action is performed. Unknown assets fail
    closed instead of being added to the investigation target set.
    """

    if isinstance(max_assets, bool) or not isinstance(max_assets, int) or not 1 <= max_assets <= MAX_SCOPE_ASSETS:
        raise MonitoringContractError(f"max_assets must be within 1..{MAX_SCOPE_ASSETS}")
    if isinstance(max_hops, bool) or not isinstance(max_hops, int) or not 1 <= max_hops <= MAX_SCOPE_HOPS:
        raise MonitoringContractError(f"max_hops must be within 1..{MAX_SCOPE_HOPS}")
    seeds = tuple(sorted({_identifier(v, "seed_asset_ref", max_len=128) for v in seed_asset_refs}))
    authorized = tuple(sorted({_identifier(v, "authorized_asset_ref", max_len=128) for v in authorized_asset_refs}))
    if not seeds or not authorized:
        raise MonitoringContractError("incident scope requires seed and authorized assets")
    allowed = set(authorized)
    if not set(seeds).issubset(allowed):
        raise MonitoringContractError("seed assets must exist in authorized inventory")

    rows = tuple(link.validate() for link in links)
    if len(rows) > MAX_SCOPE_LINKS:
        raise MonitoringContractError("scope link bound exceeded")
    for link in rows:
        if link.from_asset_ref not in allowed or link.to_asset_ref not in allowed:
            raise MonitoringContractError("scope evidence references an asset outside authorized inventory")

    adjacency: dict[str, list[ScopeEvidenceLink]] = {}
    for link in rows:
        adjacency.setdefault(link.from_asset_ref, []).append(link)
        adjacency.setdefault(link.to_asset_ref, []).append(
            ScopeEvidenceLink(
                link_id=link.link_id + ":reverse",
                from_asset_ref=link.to_asset_ref,
                to_asset_ref=link.from_asset_ref,
                relation=link.relation,
                observed_at=link.observed_at,
                evidence_ref=link.evidence_ref,
            ).validate()
        )
    for values in adjacency.values():
        values.sort(key=lambda link: (link.observed_at, link.to_asset_ref, link.link_id))

    scoped: dict[str, ScopedAsset] = {
        seed: ScopedAsset(seed, 0, None, None, None)
        for seed in seeds
    }
    queue: list[str] = list(seeds)
    evidence_refs: set[str] = set()
    truncated = False
    while queue:
        current = queue.pop(0)
        current_depth = scoped[current].depth
        if current_depth >= max_hops:
            if any(link.to_asset_ref not in scoped for link in adjacency.get(current, [])):
                truncated = True
            continue
        for link in adjacency.get(current, []):
            target = link.to_asset_ref
            if target in scoped:
                continue
            if len(scoped) >= max_assets:
                truncated = True
                continue
            scoped[target] = ScopedAsset(
                asset_ref=target,
                depth=current_depth + 1,
                parent_asset_ref=current,
                relation=link.relation,
                evidence_ref=link.evidence_ref,
            )
            evidence_refs.add(link.evidence_ref)
            queue.append(target)

    scoped_assets = tuple(sorted(scoped.values(), key=lambda asset: (asset.depth, asset.asset_ref)))
    return IncidentScopeAssessment(
        seed_asset_refs=seeds,
        authorized_asset_refs=authorized,
        scoped_assets=scoped_assets,
        evidence_refs=tuple(sorted(evidence_refs)),
        truncated=truncated,
    ).validate()
