from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

from .contracts import AssetInventoryRecord, MonitoringContractError, sha256_fingerprint
from .entity_context import approved_asset_ref, opaque_entity_ref

DHCP_IP_OBSERVATION_SCHEMA = "workspace-security-monitoring/dhcp-ip-observation-v1"
DHCP_IP_FINDING_SCHEMA = "workspace-security-monitoring/dhcp-ip-finding-v1"
MAX_DHCP_ASSETS = 256
MAX_DHCP_OBSERVATIONS = 4096

LEASE_STATES = frozenset({"bound", "renewing", "expired", "missing", "declined"})
FINDING_SEVERITY = {
    "DHCP_LEASE_MISSING": "medium",
    "DHCP_LEASE_EXPIRED": "medium",
    "DHCP_ADDRESS_DECLINED": "high",
    "IP_LINK_LOCAL_FALLBACK": "medium",
    "IP_ASSIGNED_OUTSIDE_SUBNET": "high",
    "IP_GATEWAY_OUTSIDE_SUBNET": "high",
    "IP_DUPLICATE_ADDRESS_CLAIM": "high",
}

_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@+\-/]{0,127}$")
_INTERFACE_REF_RE = re.compile(r"^entity:interface:sha256:[0-9a-f]{64}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def _compact(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _COMPACT_RE.fullmatch(text) or "://" in text:
        raise MonitoringContractError(f"{field_name} must be a compact identifier")
    return text


def _timestamp(value: str) -> str:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise MonitoringContractError("observed_at must be ISO-8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise MonitoringContractError("observed_at must include timezone")
    return text


def _ip(value: str | None, field_name: str):
    if value is None:
        return None
    try:
        return ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise MonitoringContractError(f"{field_name} must be a literal IP address") from exc


def _network(value: str | None):
    if value is None:
        return None
    try:
        return ipaddress.ip_network(str(value).strip(), strict=False)
    except ValueError as exc:
        raise MonitoringContractError("subnet_cidr must be a valid IP network") from exc


@dataclass(frozen=True)
class DhcpIpObservation:
    snapshot_id: str
    asset_id: str
    observed_at: str
    client_ref: str
    lease_state: str
    assigned_ip: str | None
    subnet_cidr: str | None
    gateway_ip: str | None
    evidence_ref: str
    schema_version: str = DHCP_IP_OBSERVATION_SCHEMA

    def validate(self) -> "DhcpIpObservation":
        object.__setattr__(self, "snapshot_id", _compact(self.snapshot_id, "snapshot_id"))
        object.__setattr__(self, "asset_id", _compact(self.asset_id, "asset_id"))
        object.__setattr__(self, "observed_at", _timestamp(self.observed_at))
        client_ref = str(self.client_ref or "").strip()
        if not _INTERFACE_REF_RE.fullmatch(client_ref):
            raise MonitoringContractError("client_ref must be an opaque interface SHA-256 reference")
        object.__setattr__(self, "client_ref", client_ref)
        state = str(self.lease_state or "").strip().lower()
        if state not in LEASE_STATES:
            raise MonitoringContractError("unsupported DHCP lease state")
        object.__setattr__(self, "lease_state", state)
        evidence_ref = str(self.evidence_ref or "").strip()
        if not _SHA256_RE.fullmatch(evidence_ref):
            raise MonitoringContractError("evidence_ref must be a SHA-256 fingerprint")
        object.__setattr__(self, "evidence_ref", evidence_ref)
        if self.schema_version != DHCP_IP_OBSERVATION_SCHEMA:
            raise MonitoringContractError("unsupported DHCP/IP observation schema")

        assigned = _ip(self.assigned_ip, "assigned_ip")
        subnet = _network(self.subnet_cidr)
        gateway = _ip(self.gateway_ip, "gateway_ip")
        if state in {"bound", "renewing"} and (assigned is None or subnet is None):
            raise MonitoringContractError("bound/renewing DHCP observations require assigned_ip and subnet_cidr")
        if state == "missing" and any(value is not None for value in (assigned, subnet, gateway)):
            raise MonitoringContractError("missing DHCP lease must not carry address metadata")
        if assigned is not None and subnet is not None and assigned.version != subnet.version:
            raise MonitoringContractError("assigned_ip and subnet_cidr IP versions must match")
        if gateway is not None and subnet is not None and gateway.version != subnet.version:
            raise MonitoringContractError("gateway_ip and subnet_cidr IP versions must match")
        return self

    @property
    def observation_id(self) -> str:
        self.validate()
        identity = {
            "snapshot_id": self.snapshot_id,
            "asset_id": self.asset_id,
            "observed_at": self.observed_at,
            "client_ref": self.client_ref,
            "lease_state": self.lease_state,
            "assigned_ip_ref": None if self.assigned_ip is None else opaque_entity_ref("ip", self.assigned_ip),
            "subnet_sha256": None if self.subnet_cidr is None else sha256_fingerprint(str(_network(self.subnet_cidr))),
            "gateway_ip_ref": None if self.gateway_ip is None else opaque_entity_ref("ip", self.gateway_ip),
            "evidence_ref": self.evidence_ref,
        }
        return "dhcp-observation-" + sha256_fingerprint(identity).split(":", 1)[1][:24]


@dataclass(frozen=True, order=True)
class DhcpIpFinding:
    snapshot_id: str
    finding_code: str
    severity: str
    asset_refs: tuple[str, ...]
    address_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    reason_codes: tuple[str, ...]
    finding_id: str
    authority: str = "advisory"
    basis: str = "normalized_dhcp_ip_snapshot_only"
    network_executed: bool = False
    discovery_performed: bool = False
    remediation_executed: bool = False
    schema_version: str = DHCP_IP_FINDING_SCHEMA

    def public_dict(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "finding_id": self.finding_id,
            "snapshot_id": self.snapshot_id,
            "finding_code": self.finding_code,
            "severity": self.severity,
            "asset_refs": list(self.asset_refs),
            "address_refs": list(self.address_refs),
            "evidence_refs": list(self.evidence_refs),
            "reason_codes": list(self.reason_codes),
            "authority": self.authority,
            "basis": self.basis,
            "network_executed": self.network_executed,
            "discovery_performed": self.discovery_performed,
            "remediation_executed": self.remediation_executed,
        }


def _finding(
    *,
    snapshot_id: str,
    code: str,
    asset_ids: Iterable[str],
    addresses: Iterable[str],
    evidence_refs: Iterable[str],
    reasons: Iterable[str],
) -> DhcpIpFinding:
    assets = tuple(sorted({approved_asset_ref(value) for value in asset_ids}))
    address_refs = tuple(sorted({opaque_entity_ref("ip", value) for value in addresses}))
    evidence = tuple(sorted(set(evidence_refs)))
    reason_codes = tuple(sorted(set(reasons)))
    identity = {
        "snapshot_id": snapshot_id,
        "finding_code": code,
        "severity": FINDING_SEVERITY[code],
        "asset_refs": list(assets),
        "address_refs": list(address_refs),
        "evidence_refs": list(evidence),
        "reason_codes": list(reason_codes),
        "authority": "advisory",
    }
    return DhcpIpFinding(
        snapshot_id=snapshot_id,
        finding_code=code,
        severity=FINDING_SEVERITY[code],
        asset_refs=assets,
        address_refs=address_refs,
        evidence_refs=evidence,
        reason_codes=reason_codes,
        finding_id="dhcp-finding-" + sha256_fingerprint(identity).split(":", 1)[1][:24],
    )


class DeterministicDhcpIpTriage:
    """Analyze normalized DHCP/IP snapshots without collecting new network evidence."""

    def __init__(self, assets: Iterable[AssetInventoryRecord]) -> None:
        approved: dict[str, AssetInventoryRecord] = {}
        for index, raw in enumerate(assets):
            if index >= MAX_DHCP_ASSETS:
                raise MonitoringContractError("DHCP/IP asset inventory bound exceeded")
            if not isinstance(raw, AssetInventoryRecord):
                raise MonitoringContractError("DHCP/IP triage requires AssetInventoryRecord inventory")
            item = raw.validate()
            previous = approved.get(item.asset_id)
            if previous is not None and previous.fingerprint != item.fingerprint:
                raise MonitoringContractError("duplicate asset_id has conflicting inventory content")
            approved[item.asset_id] = item
        self._enabled_asset_ids = frozenset(asset_id for asset_id, item in approved.items() if item.enabled)

    def triage(self, observations: Iterable[DhcpIpObservation]) -> tuple[DhcpIpFinding, ...]:
        by_logical_key: dict[tuple[str, str, str], tuple[DhcpIpObservation, str]] = {}
        for index, raw in enumerate(observations):
            if index >= MAX_DHCP_OBSERVATIONS:
                raise MonitoringContractError("DHCP/IP observation bound exceeded")
            if not isinstance(raw, DhcpIpObservation):
                raise MonitoringContractError("DHCP/IP triage requires DhcpIpObservation values")
            item = raw.validate()
            if item.asset_id not in self._enabled_asset_ids:
                raise MonitoringContractError("DHCP/IP observation asset must reference enabled approved inventory")
            fingerprint = sha256_fingerprint({
                "observation_id": item.observation_id,
                "schema_version": item.schema_version,
            })
            key = (item.snapshot_id, item.asset_id, item.client_ref)
            previous = by_logical_key.get(key)
            if previous is not None:
                if previous[1] != fingerprint:
                    raise MonitoringContractError("DHCP/IP logical observation has conflicting snapshot content")
                continue
            by_logical_key[key] = (item, fingerprint)

        rows = [item for item, _ in by_logical_key.values()]
        findings: list[DhcpIpFinding] = []
        for item in rows:
            addresses = [] if item.assigned_ip is None else [item.assigned_ip]
            if item.lease_state == "missing":
                findings.append(_finding(snapshot_id=item.snapshot_id, code="DHCP_LEASE_MISSING", asset_ids=[item.asset_id], addresses=[], evidence_refs=[item.evidence_ref], reasons=["NO_LEASE_REPORTED"]))
            elif item.lease_state == "expired":
                findings.append(_finding(snapshot_id=item.snapshot_id, code="DHCP_LEASE_EXPIRED", asset_ids=[item.asset_id], addresses=addresses, evidence_refs=[item.evidence_ref], reasons=["LEASE_STATE_EXPIRED"]))
            elif item.lease_state == "declined":
                findings.append(_finding(snapshot_id=item.snapshot_id, code="DHCP_ADDRESS_DECLINED", asset_ids=[item.asset_id], addresses=addresses, evidence_refs=[item.evidence_ref], reasons=["LEASE_STATE_DECLINED"]))

            assigned = _ip(item.assigned_ip, "assigned_ip")
            subnet = _network(item.subnet_cidr)
            gateway = _ip(item.gateway_ip, "gateway_ip")
            if assigned is not None:
                if assigned.version == 4 and assigned in ipaddress.ip_network("169.254.0.0/16"):
                    findings.append(_finding(snapshot_id=item.snapshot_id, code="IP_LINK_LOCAL_FALLBACK", asset_ids=[item.asset_id], addresses=[str(assigned)], evidence_refs=[item.evidence_ref], reasons=["IPV4_LINK_LOCAL_ADDRESS"]))
                if subnet is not None and assigned not in subnet:
                    findings.append(_finding(snapshot_id=item.snapshot_id, code="IP_ASSIGNED_OUTSIDE_SUBNET", asset_ids=[item.asset_id], addresses=[str(assigned)], evidence_refs=[item.evidence_ref], reasons=["ASSIGNED_ADDRESS_NOT_IN_DECLARED_SUBNET"]))
            if gateway is not None and subnet is not None and gateway not in subnet:
                findings.append(_finding(snapshot_id=item.snapshot_id, code="IP_GATEWAY_OUTSIDE_SUBNET", asset_ids=[item.asset_id], addresses=[str(gateway)], evidence_refs=[item.evidence_ref], reasons=["GATEWAY_NOT_IN_DECLARED_SUBNET"]))

        snapshot_ip_rows: dict[tuple[str, str], list[DhcpIpObservation]] = {}
        for item in rows:
            if item.assigned_ip is None or item.lease_state not in {"bound", "renewing"}:
                continue
            canonical_ip = str(_ip(item.assigned_ip, "assigned_ip"))
            snapshot_ip_rows.setdefault((item.snapshot_id, canonical_ip), []).append(item)
        for (snapshot_id, address), claimants in sorted(snapshot_ip_rows.items()):
            if len({item.client_ref for item in claimants}) < 2:
                continue
            findings.append(
                _finding(
                    snapshot_id=snapshot_id,
                    code="IP_DUPLICATE_ADDRESS_CLAIM",
                    asset_ids=[item.asset_id for item in claimants],
                    addresses=[address],
                    evidence_refs=[item.evidence_ref for item in claimants],
                    reasons=["MULTIPLE_CLIENT_REFS_CLAIM_SAME_ADDRESS_IN_SNAPSHOT"],
                )
            )
        return tuple(sorted(set(findings), key=lambda item: (item.snapshot_id, item.finding_code, item.finding_id)))
