from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Iterable

from .contracts import MonitoringContractError, sha256_fingerprint

LATERAL_OBSERVATION_SCHEMA = "workspace-security-forensics/lateral-observation-v1"
LATERAL_TRACE_SCHEMA = "workspace-security-forensics/lateral-trace-v1"
LATERAL_CHANNELS = frozenset({"rdp", "smb", "winrm", "ssh", "wmi", "remote_service"})
MAX_LATERAL_OBSERVATIONS = 8192
MAX_LATERAL_EDGES = 512
MAX_LATERAL_CHAINS = 256
MAX_LATERAL_HOPS = 8

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-]{0,255}$")


def _identifier(value: str, field_name: str, *, max_len: int = 256) -> str:
    text = str(value or "").strip()
    if not text or len(text) > max_len or not _ID_RE.fullmatch(text):
        raise MonitoringContractError(f"{field_name} must be a compact identifier")
    if "://" in text or "/" in text or "\\" in text:
        raise MonitoringContractError(f"{field_name} must not contain a URL or filesystem path")
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
class LateralMovementObservation:
    event_id: str
    src_asset_ref: str
    dst_asset_ref: str
    user_ref: str
    channel: str
    observed_at: str
    evidence_ref: str
    authenticated: bool
    remote_process_created: bool
    privileged_context: bool = False
    process_ref: str | None = None
    schema_version: str = LATERAL_OBSERVATION_SCHEMA

    def validate(self) -> "LateralMovementObservation":
        object.__setattr__(self, "event_id", _identifier(self.event_id, "event_id", max_len=128))
        object.__setattr__(self, "src_asset_ref", _identifier(self.src_asset_ref, "src_asset_ref", max_len=128))
        object.__setattr__(self, "dst_asset_ref", _identifier(self.dst_asset_ref, "dst_asset_ref", max_len=128))
        if self.src_asset_ref == self.dst_asset_ref:
            raise MonitoringContractError("lateral movement requires distinct source and destination assets")
        object.__setattr__(self, "user_ref", _identifier(self.user_ref, "user_ref", max_len=128))
        if self.channel not in LATERAL_CHANNELS:
            raise MonitoringContractError("unsupported lateral movement channel")
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at, "observed_at"))
        object.__setattr__(self, "evidence_ref", _identifier(self.evidence_ref, "evidence_ref", max_len=128))
        _strict_bool(self.authenticated, "authenticated")
        _strict_bool(self.remote_process_created, "remote_process_created")
        _strict_bool(self.privileged_context, "privileged_context")
        if self.process_ref is not None:
            object.__setattr__(self, "process_ref", _identifier(self.process_ref, "process_ref", max_len=128))
        if self.remote_process_created and self.process_ref is None:
            raise MonitoringContractError("remote process creation requires process_ref evidence")
        if self.schema_version != LATERAL_OBSERVATION_SCHEMA:
            raise MonitoringContractError("unsupported lateral observation schema")
        return self


@dataclass(frozen=True)
class LateralMovementEdge:
    edge_id: str
    src_asset_ref: str
    dst_asset_ref: str
    user_ref: str
    channel: str
    reasons: tuple[str, ...]
    confidence: float
    evidence_refs: tuple[str, ...]
    process_refs: tuple[str, ...]
    first_seen: str
    last_seen: str


@dataclass(frozen=True)
class LateralMovementAssessment:
    edges: tuple[LateralMovementEdge, ...]
    chains: tuple[tuple[str, ...], ...]
    observations_analyzed: int
    authorized_asset_refs: tuple[str, ...]
    authority: str = "advisory"
    schema_version: str = LATERAL_TRACE_SCHEMA

    def validate(self) -> "LateralMovementAssessment":
        if isinstance(self.observations_analyzed, bool) or not isinstance(self.observations_analyzed, int):
            raise MonitoringContractError("observations_analyzed must be an integer")
        if not 0 <= self.observations_analyzed <= MAX_LATERAL_OBSERVATIONS:
            raise MonitoringContractError("observations_analyzed is out of bounds")
        if len(self.edges) > MAX_LATERAL_EDGES or len(self.chains) > MAX_LATERAL_CHAINS:
            raise MonitoringContractError("lateral trace output bound exceeded")
        authorized = tuple(sorted({_identifier(v, "authorized_asset_ref", max_len=128) for v in self.authorized_asset_refs}))
        if not authorized:
            raise MonitoringContractError("authorized asset scope is required")
        object.__setattr__(self, "authorized_asset_refs", authorized)
        allowed = set(authorized)
        for edge in self.edges:
            if edge.src_asset_ref not in allowed or edge.dst_asset_ref not in allowed:
                raise MonitoringContractError("lateral edge exceeds authorized asset scope")
            _identifier(edge.edge_id, "edge_id", max_len=128)
            _identifier(edge.user_ref, "user_ref", max_len=128)
            if edge.channel not in LATERAL_CHANNELS:
                raise MonitoringContractError("unsupported lateral edge channel")
            if len(edge.reasons) < 2:
                raise MonitoringContractError("lateral edge requires multiple supporting reasons")
            if not 0.0 <= edge.confidence <= 1.0:
                raise MonitoringContractError("lateral edge confidence must be within [0,1]")
            if not edge.evidence_refs:
                raise MonitoringContractError("lateral edge requires evidence refs")
            _timestamp(edge.first_seen, "first_seen")
            _timestamp(edge.last_seen, "last_seen")
        for chain in self.chains:
            if len(chain) < 2 or len(chain) > MAX_LATERAL_HOPS + 1:
                raise MonitoringContractError("lateral chain length is invalid")
            if len(chain) != len(set(chain)):
                raise MonitoringContractError("lateral chain must not contain an asset cycle")
            if any(asset not in allowed for asset in chain):
                raise MonitoringContractError("lateral chain exceeds authorized asset scope")
        if self.authority != "advisory":
            raise MonitoringContractError("lateral movement assessment must remain advisory")
        if self.schema_version != LATERAL_TRACE_SCHEMA:
            raise MonitoringContractError("unsupported lateral trace schema")
        return self

    def public_dict(self) -> dict[str, object]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "edges": [asdict(edge) for edge in self.edges],
            "chains": [list(chain) for chain in self.chains],
            "observations_analyzed": self.observations_analyzed,
            "authorized_asset_refs": list(self.authorized_asset_refs),
            "authority": self.authority,
        }

    @property
    def fingerprint(self) -> str:
        return sha256_fingerprint(self.public_dict())


def _edge_reasons(rows: list[LateralMovementObservation]) -> tuple[str, ...]:
    reasons: set[str] = set()
    if any(row.authenticated for row in rows):
        reasons.add("successful_remote_auth")
    if any(row.remote_process_created for row in rows):
        reasons.add("remote_process_created")
    if any(row.privileged_context for row in rows):
        reasons.add("privileged_context")
    if len({row.evidence_ref for row in rows}) >= 2:
        reasons.add("multi_source_evidence")
    return tuple(sorted(reasons))


def _edge_confidence(reasons: tuple[str, ...]) -> float:
    weights = {
        "successful_remote_auth": 0.32,
        "remote_process_created": 0.34,
        "privileged_context": 0.14,
        "multi_source_evidence": 0.12,
    }
    return round(min(0.95, sum(weights[reason] for reason in reasons)), 2)


def _build_chains(edges: tuple[LateralMovementEdge, ...], max_hops: int) -> tuple[tuple[str, ...], ...]:
    adjacency: dict[str, set[str]] = {}
    incoming: set[str] = set()
    for edge in edges:
        adjacency.setdefault(edge.src_asset_ref, set()).add(edge.dst_asset_ref)
        incoming.add(edge.dst_asset_ref)
    starts = sorted(set(adjacency) - incoming) or sorted(adjacency)
    chains: set[tuple[str, ...]] = set()

    def walk(path: tuple[str, ...]) -> None:
        if len(chains) >= MAX_LATERAL_CHAINS:
            return
        current = path[-1]
        next_assets = sorted(adjacency.get(current, set()))
        extended = False
        if len(path) - 1 < max_hops:
            for next_asset in next_assets:
                if next_asset in path:
                    continue
                extended = True
                walk(path + (next_asset,))
        if len(path) >= 2 and (not extended or len(path) - 1 == max_hops):
            chains.add(path)

    for start in starts:
        walk((start,))
        if len(chains) >= MAX_LATERAL_CHAINS:
            break
    return tuple(sorted(chains))


def trace_lateral_movement(
    observations: Iterable[LateralMovementObservation],
    *,
    authorized_asset_refs: Iterable[str],
    max_hops: int = 4,
) -> LateralMovementAssessment:
    """Correlate authorized remote-auth/process evidence into bounded lateral paths.

    This analyzer cannot discover assets, scan networks, acquire credentials, or
    execute remote actions. Every source and destination must already exist in
    the caller-supplied authorized inventory scope.
    """

    if isinstance(max_hops, bool) or not isinstance(max_hops, int) or not 1 <= max_hops <= MAX_LATERAL_HOPS:
        raise MonitoringContractError(f"max_hops must be within 1..{MAX_LATERAL_HOPS}")
    authorized = tuple(sorted({_identifier(v, "authorized_asset_ref", max_len=128) for v in authorized_asset_refs}))
    if not authorized:
        raise MonitoringContractError("authorized asset scope is required")
    allowed = set(authorized)
    rows = tuple(row.validate() for row in observations)
    if len(rows) > MAX_LATERAL_OBSERVATIONS:
        raise MonitoringContractError("lateral observation bound exceeded")
    if any(row.src_asset_ref not in allowed or row.dst_asset_ref not in allowed for row in rows):
        raise MonitoringContractError("lateral observation exceeds authorized asset scope")

    grouped: dict[tuple[str, str, str, str], list[LateralMovementObservation]] = {}
    for row in rows:
        grouped.setdefault((row.src_asset_ref, row.dst_asset_ref, row.user_ref, row.channel), []).append(row)

    edges: list[LateralMovementEdge] = []
    for key in sorted(grouped):
        group = sorted(grouped[key], key=lambda row: (row.observed_at, row.event_id))
        reasons = _edge_reasons(group)
        if len(reasons) < 2 or "successful_remote_auth" not in reasons:
            continue
        evidence_refs = tuple(sorted({row.evidence_ref for row in group}))
        process_refs = tuple(sorted({row.process_ref for row in group if row.process_ref is not None}))
        identity = {
            "src": key[0],
            "dst": key[1],
            "user": key[2],
            "channel": key[3],
            "evidence_refs": evidence_refs,
            "schema": LATERAL_TRACE_SCHEMA,
        }
        edges.append(
            LateralMovementEdge(
                edge_id="lateral:" + sha256_fingerprint(identity).split(":", 1)[1][:24],
                src_asset_ref=key[0],
                dst_asset_ref=key[1],
                user_ref=key[2],
                channel=key[3],
                reasons=reasons,
                confidence=_edge_confidence(reasons),
                evidence_refs=evidence_refs,
                process_refs=process_refs,
                first_seen=group[0].observed_at,
                last_seen=group[-1].observed_at,
            )
        )
        if len(edges) > MAX_LATERAL_EDGES:
            raise MonitoringContractError("lateral edge bound exceeded")

    edges_tuple = tuple(sorted(edges, key=lambda edge: (edge.src_asset_ref, edge.dst_asset_ref, edge.user_ref, edge.channel)))
    return LateralMovementAssessment(
        edges=edges_tuple,
        chains=_build_chains(edges_tuple, max_hops),
        observations_analyzed=len(rows),
        authorized_asset_refs=authorized,
    ).validate()
