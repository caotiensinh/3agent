from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from .contracts import AssetInventoryRecord, MonitoringContractError, SecretReference
from .discovery_candidate_store import DiscoveryCandidateStore
from .discovery_enrollment import DiscoveryEnrollmentRequest, DiscoveryEnrollmentService
from .ui_config_v2 import SecurityMonitoringUIConfigManagerV2

ONBOARDING_DRAFT_SCHEMA = "workspace-security-monitoring/asset-onboarding-draft-v1"
ONBOARDING_CANDIDATES_SCHEMA = "workspace-security-monitoring/onboarding-candidates-v1"
MAX_ONBOARDING_CANDIDATES = 200
_ASSET_KEYS = {
    "asset_id",
    "role",
    "management_host",
    "collector_capabilities",
    "allowed_tcp_ports",
    "data_class",
    "enabled",
    "credential_ref",
}


def _asset_from_payload(value: Any) -> AssetInventoryRecord:
    if not isinstance(value, dict):
        raise MonitoringContractError("onboarding asset must be an object")
    unknown = set(value) - _ASSET_KEYS
    if unknown:
        raise MonitoringContractError(f"unknown onboarding asset keys: {sorted(unknown)}")
    credential_value = value.get("credential_ref")
    if credential_value is not None and not isinstance(credential_value, str):
        raise MonitoringContractError("credential_ref must be an opaque secret-ref string")
    credential = SecretReference(credential_value).validate() if credential_value else None
    return AssetInventoryRecord(
        asset_id=value.get("asset_id", ""),
        role=value.get("role", ""),
        management_host=value.get("management_host", ""),
        collector_capabilities=tuple(value.get("collector_capabilities") or ()),
        allowed_tcp_ports=tuple(value.get("allowed_tcp_ports") or ()),
        data_class=value.get("data_class", "confidential"),
        enabled=bool(value.get("enabled", True)),
        credential_ref=credential,
    ).validate()


def _asset_config_dict(asset: AssetInventoryRecord) -> dict[str, Any]:
    return {
        "asset_id": asset.asset_id,
        "role": asset.role,
        "management_host": asset.management_host,
        "collector_capabilities": list(asset.collector_capabilities),
        "allowed_tcp_ports": list(asset.allowed_tcp_ports),
        "data_class": asset.data_class,
        "enabled": bool(asset.enabled),
        "credential_ref": asset.credential_ref.handle if asset.credential_ref else None,
    }


class SecurityAssetOnboardingService:
    """Prepare explicit operator-approved assets for the authoritative config.

    Discovery candidates remain untrusted evidence. This service never inserts an
    approved asset into SQLite and never runs a collector. It verifies an exact
    candidate-to-management-host binding, then returns a validated configuration
    draft that an admin may save through the existing Configuration Center gate.
    """

    def __init__(self, config_manager: SecurityMonitoringUIConfigManagerV2) -> None:
        self.config_manager = config_manager

    def _database_path(self) -> Path:
        envelope = self.config_manager.get()
        raw = envelope.get("config", {}).get("database_path")
        path = Path(str(raw or ""))
        if not path.is_absolute():
            raise MonitoringContractError("monitoring database path must be absolute")
        if path.is_symlink():
            raise MonitoringContractError("monitoring database path must not be a symlink")
        if not path.is_file():
            raise MonitoringContractError("monitoring database is not initialized")
        return path

    def _connect_readonly(self) -> sqlite3.Connection:
        path = self._database_path()
        conn = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA query_only=ON")
        return conn

    def _candidate(self, candidate_id: str):
        try:
            with self._connect_readonly() as conn:
                row = conn.execute(
                    "SELECT * FROM discovery_candidates WHERE candidate_id=?",
                    (str(candidate_id or "").strip(),),
                ).fetchone()
        except sqlite3.DatabaseError as exc:
            raise MonitoringContractError("discovery candidate store is unavailable") from exc
        if row is None:
            raise MonitoringContractError("discovery onboarding requires an existing candidate")
        return DiscoveryCandidateStore._from_row(row)

    def list_candidates(self, *, limit: int = 50) -> dict[str, Any]:
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_ONBOARDING_CANDIDATES:
            raise MonitoringContractError(
                f"onboarding candidate limit must be within 1..{MAX_ONBOARDING_CANDIDATES}"
            )
        try:
            with self._connect_readonly() as conn:
                rows = conn.execute(
                    "SELECT * FROM discovery_candidates ORDER BY last_seen DESC, candidate_id LIMIT ?",
                    (limit,),
                ).fetchall()
        except sqlite3.DatabaseError as exc:
            raise MonitoringContractError("discovery candidate store is unavailable") from exc
        items = []
        for row in rows:
            candidate = DiscoveryCandidateStore._from_row(row)
            items.append(
                {
                    "candidate_id": candidate.candidate_id,
                    "candidate_fingerprint": candidate.fingerprint,
                    "identity_kind": candidate.identity_kind,
                    "first_seen": candidate.first_seen,
                    "last_seen": candidate.last_seen,
                    "observation_count": candidate.observation_count,
                    "confidence_basis_points": candidate.confidence_basis_points,
                    "trust_state": "untrusted",
                    "inventory_status": "not_enrolled",
                    "authority": "none",
                }
            )
        return {
            "schema_version": ONBOARDING_CANDIDATES_SCHEMA,
            "items": items,
            "authority": {
                "discovery_grants_authority": False,
                "raw_discovered_targets_exposed": False,
                "database_write": False,
                "network_execution": False,
            },
        }

    def prepare(self, payload: Any) -> dict[str, Any]:
        if not isinstance(payload, dict):
            raise MonitoringContractError("onboarding request must be an object")
        allowed = {
            "candidate_id",
            "candidate_fingerprint",
            "operator_approval_ref",
            "asset",
        }
        unknown = set(payload) - allowed
        if unknown:
            raise MonitoringContractError(f"unknown onboarding request keys: {sorted(unknown)}")

        asset = _asset_from_payload(payload.get("asset"))
        request = DiscoveryEnrollmentRequest(
            candidate_id=str(payload.get("candidate_id") or ""),
            candidate_fingerprint=str(payload.get("candidate_fingerprint") or ""),
            asset=asset,
            operator_approval_ref=str(payload.get("operator_approval_ref") or ""),
        ).validate()
        candidate = self._candidate(request.candidate_id)
        if candidate.fingerprint != request.candidate_fingerprint:
            raise MonitoringContractError("discovery candidate fingerprint changed before onboarding")
        DiscoveryEnrollmentService._verify_candidate_binding(candidate, asset)

        envelope = self.config_manager.get()
        config = envelope.get("config")
        if not isinstance(config, dict):
            raise MonitoringContractError("authoritative monitoring config is unavailable")
        raw_assets = config.get("assets") or []
        if not isinstance(raw_assets, list):
            raise MonitoringContractError("authoritative monitoring assets are invalid")

        transition = "append_required"
        for raw in raw_assets:
            existing = _asset_from_payload(raw)
            if existing.asset_id == asset.asset_id:
                if existing.fingerprint != asset.fingerprint:
                    raise MonitoringContractError(
                        "onboarding cannot mutate an existing asset definition"
                    )
                transition = "already_configured"
            if existing.management_host == asset.management_host and existing.asset_id != asset.asset_id:
                raise MonitoringContractError(
                    "management_host is already owned by another configured asset"
                )

        return {
            "schema_version": ONBOARDING_DRAFT_SCHEMA,
            "status": "prepared_not_saved",
            "transition": transition,
            "candidate": {
                "candidate_id": candidate.candidate_id,
                "candidate_fingerprint": candidate.fingerprint,
                "identity_kind": candidate.identity_kind,
                "trust_state": "untrusted",
                "inventory_status": "not_enrolled",
                "authority": "none",
            },
            "asset": _asset_config_dict(asset),
            "operator_approval_ref": request.operator_approval_ref,
            "authority": {
                "result": "configuration_draft_only",
                "config_is_authoritative": True,
                "config_saved": False,
                "database_write": False,
                "network_execution": False,
                "collector_execution": False,
                "remediation_execution": False,
                "packet_capture_execution": False,
            },
            "next_step": "append_or_confirm_asset_in_configuration_center_then_save",
        }
