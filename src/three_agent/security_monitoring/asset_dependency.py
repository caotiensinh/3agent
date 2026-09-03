from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable

from .contracts import AssetInventoryRecord, MonitoringContractError, sha256_fingerprint

ASSET_DEPENDENCY_SCHEMA = "workspace-security-monitoring/asset-dependency-v1"
ASSET_IMPACT_SCHEMA = "workspace-security-monitoring/asset-impact-v1"
MAX_ASSETS = 256
MAX_DEPENDENCIES = 2048
MAX_IMPACT_SEEDS = 64
MAX_IMPACT_DEPTH = 32

ALLOWED_DEPENDENCY_RELATIONS = frozenset(
    {
        "network_path",
        "dns_service",
        "authentication_service",
        "application_service",
        "storage_service",
        "monitoring_service",
        "power_dependency",
    }
)

_ASSET_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _asset_id(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _ASSET_ID_RE.fullmatch(text) or "://" in text:
        raise MonitoringContractError(f"{field_name} must be a compact asset identifier")
    return text


def _sha256(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _SHA256_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a SHA-256 fingerprint")
    return text


@dataclass(frozen=True, order=True)
class AssetDependency:
    """One administrator-declared dependency between two approved assets.

    `upstream_asset_id -> downstream_asset_id` means the downstream asset relies on
    the upstream asset for the declared relation. This contract never discovers or
    infers topology from network traffic.
    """

    upstream_asset_id: str
    downstream_asset_id: str
    relation: str
    declaration_sha256: str
    schema_version: str = ASSET_DEPENDENCY_SCHEMA

    def validate(self) -> "AssetDependency":
        object.__setattr__(self, "upstream_asset_id", _asset_id(self.upstream_asset_id, "upstream_asset_id"))
        object.__setattr__(self, "downstream_asset_id", _asset_id(self.downstream_asset_id, "downstream_asset_id"))
        if self.upstream_asset_id == self.downstream_asset_id:
            raise MonitoringContractError("asset dependency self-loops are forbidden")
        relation = str(self.relation or "").strip()
        if relation not in ALLOWED_DEPENDENCY_RELATIONS:
            raise MonitoringContractError(f"unsupported asset dependency relation: {relation}")
        object.__setattr__(self, "relation", relation)
        object.__setattr__(self, "declaration_sha256", _sha256(self.declaration_sha256, "declaration_sha256"))
        if self.schema_version != ASSET_DEPENDENCY_SCHEMA:
            raise MonitoringContractError("unsupported asset dependency schema")
        return self

    @property
    def dependency_id(self) -> str:
        self.validate()
        identity = {
            "upstream_asset_id": self.upstream_asset_id,
            "downstream_asset_id": self.downstream_asset_id,
            "relation": self.relation,
            "declaration_sha256": self.declaration_sha256,
        }
        return "dependency-" + sha256_fingerprint(identity).split(":", 1)[1][:24]

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "dependency_id": self.dependency_id,
            "upstream_asset_id": self.upstream_asset_id,
            "downstream_asset_id": self.downstream_asset_id,
            "relation": self.relation,
            "declaration_sha256": self.declaration_sha256,
        }


@dataclass(frozen=True)
class AssetImpactAssessment:
    assessment_id: str
    seed_asset_ids: tuple[str, ...]
    potentially_affected_asset_ids: tuple[str, ...]
    dependency_ids: tuple[str, ...]
    depth_by_asset: tuple[tuple[str, int], ...]
    max_depth: int
    truncated: bool
    authority: str = "advisory"
    basis: str = "declared_dependencies_only"
    impact_type: str = "potential_dependency_impact"
    downstream_state_confirmed: bool = False
    discovery_performed: bool = False
    inferred_topology: bool = False
    network_executed: bool = False
    remediation_executed: bool = False
    schema_version: str = ASSET_IMPACT_SCHEMA

    def public_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "assessment_id": self.assessment_id,
            "seed_asset_ids": list(self.seed_asset_ids),
            "potentially_affected_asset_ids": list(self.potentially_affected_asset_ids),
            "dependency_ids": list(self.dependency_ids),
            "depth_by_asset": [
                {"asset_id": asset_id, "depth": depth}
                for asset_id, depth in self.depth_by_asset
            ],
            "max_depth": self.max_depth,
            "truncated": self.truncated,
            "authority": self.authority,
            "basis": self.basis,
            "impact_type": self.impact_type,
            "downstream_state_confirmed": self.downstream_state_confirmed,
            "discovery_performed": self.discovery_performed,
            "inferred_topology": self.inferred_topology,
            "network_executed": self.network_executed,
            "remediation_executed": self.remediation_executed,
        }


class DeclaredAssetDependencyGraph:
    """Bounded deterministic impact analysis over approved, enabled inventory only."""

    def __init__(
        self,
        assets: Iterable[AssetInventoryRecord],
        dependencies: Iterable[AssetDependency],
    ) -> None:
        asset_by_id: dict[str, AssetInventoryRecord] = {}
        for index, raw in enumerate(assets):
            if index >= MAX_ASSETS:
                raise MonitoringContractError("asset dependency inventory bound exceeded")
            if not isinstance(raw, AssetInventoryRecord):
                raise MonitoringContractError("asset dependency inventory requires AssetInventoryRecord values")
            item = raw.validate()
            previous = asset_by_id.get(item.asset_id)
            if previous is not None:
                if previous.fingerprint != item.fingerprint:
                    raise MonitoringContractError("duplicate asset_id has conflicting inventory content")
                continue
            asset_by_id[item.asset_id] = item

        enabled_ids = {asset_id for asset_id, item in asset_by_id.items() if item.enabled}
        dependency_by_id: dict[str, AssetDependency] = {}
        for index, raw in enumerate(dependencies):
            if index >= MAX_DEPENDENCIES:
                raise MonitoringContractError("asset dependency bound exceeded")
            if not isinstance(raw, AssetDependency):
                raise MonitoringContractError("asset dependencies require AssetDependency values")
            item = raw.validate()
            if item.upstream_asset_id not in enabled_ids or item.downstream_asset_id not in enabled_ids:
                raise MonitoringContractError("asset dependency endpoints must reference enabled approved inventory")
            dependency_id = item.dependency_id
            previous = dependency_by_id.get(dependency_id)
            if previous is not None and previous != item:
                raise MonitoringContractError("duplicate dependency_id has conflicting content")
            dependency_by_id[dependency_id] = item

        self._assets = dict(sorted(asset_by_id.items()))
        self._enabled_ids = frozenset(enabled_ids)
        self._dependencies = tuple(sorted(dependency_by_id.values(), key=lambda item: item.dependency_id))
        adjacency: dict[str, list[AssetDependency]] = {}
        for dependency in self._dependencies:
            adjacency.setdefault(dependency.upstream_asset_id, []).append(dependency)
        self._adjacency = {
            asset_id: tuple(sorted(rows, key=lambda item: item.dependency_id))
            for asset_id, rows in adjacency.items()
        }

    @property
    def inventory_fingerprint(self) -> str:
        return sha256_fingerprint(
            [
                {
                    "asset_id": asset_id,
                    "asset_fingerprint": self._assets[asset_id].fingerprint,
                    "enabled": self._assets[asset_id].enabled,
                }
                for asset_id in sorted(self._assets)
            ]
        )

    @property
    def dependency_fingerprint(self) -> str:
        return sha256_fingerprint([item.public_dict() for item in self._dependencies])

    def impact(
        self,
        seed_asset_ids: Iterable[str],
        *,
        max_depth: int = 16,
    ) -> AssetImpactAssessment:
        depth_limit = int(max_depth)
        if not 1 <= depth_limit <= MAX_IMPACT_DEPTH:
            raise MonitoringContractError(f"max_depth must be within 1..{MAX_IMPACT_DEPTH}")

        seed_rows: list[str] = []
        for index, raw in enumerate(seed_asset_ids):
            if index >= MAX_IMPACT_SEEDS:
                raise MonitoringContractError("asset impact seed bound exceeded")
            seed_rows.append(_asset_id(raw, "seed_asset_id"))
        seeds = tuple(sorted(set(seed_rows)))
        if not seeds:
            raise MonitoringContractError("asset impact requires at least one seed asset")
        unknown = sorted(set(seeds) - self._enabled_ids)
        if unknown:
            raise MonitoringContractError(f"asset impact seeds must reference enabled approved inventory: {unknown}")

        depths: dict[str, int] = {asset_id: 0 for asset_id in seeds}
        queue: list[str] = list(seeds)
        used_dependency_ids: set[str] = set()
        truncated = False
        cursor = 0
        while cursor < len(queue):
            upstream = queue[cursor]
            cursor += 1
            current_depth = depths[upstream]
            outgoing = self._adjacency.get(upstream, ())
            if current_depth >= depth_limit:
                if any(dep.downstream_asset_id not in depths for dep in outgoing):
                    truncated = True
                continue
            for dependency in outgoing:
                downstream = dependency.downstream_asset_id
                candidate_depth = current_depth + 1
                previous_depth = depths.get(downstream)
                if previous_depth is None:
                    depths[downstream] = candidate_depth
                    queue.append(downstream)
                    used_dependency_ids.add(dependency.dependency_id)
                elif candidate_depth < previous_depth:
                    depths[downstream] = candidate_depth
                    queue.append(downstream)
                    used_dependency_ids.add(dependency.dependency_id)
                elif downstream not in seeds and candidate_depth == previous_depth:
                    used_dependency_ids.add(dependency.dependency_id)

        affected = tuple(sorted(asset_id for asset_id, depth in depths.items() if depth > 0))
        depth_by_asset = tuple(sorted((asset_id, depths[asset_id]) for asset_id in affected))
        dependency_ids = tuple(sorted(used_dependency_ids))
        identity = {
            "seed_asset_ids": list(seeds),
            "potentially_affected_asset_ids": list(affected),
            "dependency_ids": list(dependency_ids),
            "depth_by_asset": [[asset_id, depth] for asset_id, depth in depth_by_asset],
            "max_depth": depth_limit,
            "truncated": truncated,
            "inventory_fingerprint": self.inventory_fingerprint,
            "dependency_fingerprint": self.dependency_fingerprint,
            "authority": "advisory",
            "basis": "declared_dependencies_only",
            "impact_type": "potential_dependency_impact",
        }
        assessment_id = "impact-" + sha256_fingerprint(identity).split(":", 1)[1][:24]
        return AssetImpactAssessment(
            assessment_id=assessment_id,
            seed_asset_ids=seeds,
            potentially_affected_asset_ids=affected,
            dependency_ids=dependency_ids,
            depth_by_asset=depth_by_asset,
            max_depth=depth_limit,
            truncated=truncated,
        )
