from __future__ import annotations

from typing import Any

from .contracts import COLLECTOR_CAPABILITIES
from .policy import ACTIVE_LIVENESS_CAPABILITIES
from .readiness import evaluate_monitoring_readiness
from .runtime_config import MonitoringRuntimeConfig

CAPABILITY_MATRIX_SCHEMA = "workspace-security-monitoring/capability-matrix-v1"

_READ_SURFACES = (
    "summary",
    "asset_intelligence",
    "evidence_summary",
    "incident_posture",
    "operator_posture",
    "analyst_workspace",
)

_RESTRICTED_SURFACES = (
    "arbitrary_target_scan",
    "credential_entry",
    "packet_capture",
    "remediation",
    "shell_execution",
)


def _row(name: str, state: str, reason_code: str, **extra: object) -> dict[str, object]:
    return {
        "name": name,
        "state": state,
        "reason_code": reason_code,
        **extra,
    }


def _collector_state(
    config: MonitoringRuntimeConfig,
    capability: str,
    *,
    configured_asset_count: int,
    readiness_issue_codes: frozenset[str],
) -> tuple[str, str]:
    if configured_asset_count <= 0:
        return "not_configured", "NO_APPROVED_ASSET_CAPABILITY"
    if not config.enabled:
        return "disabled", "MONITORING_DISABLED"
    if capability not in config.policy.allowed_capabilities:
        return "gated", "CAPABILITY_POLICY_DENIED"
    if capability in ACTIVE_LIVENESS_CAPABILITIES and not config.policy.allow_active_liveness:
        return "gated", "ACTIVE_LIVENESS_DISABLED"
    if not config.allow_real_network:
        return "gated", "REAL_NETWORK_NOT_ALLOWED"
    if capability == "snmpv3_read" and readiness_issue_codes.intersection(
        {
            "SECRET_DIRECTORY_REQUIRED",
            "CREDENTIAL_REF_REQUIRED",
            "SECRET_REF_UNRESOLVED",
        }
    ):
        return "gated", "SNMP_CREDENTIAL_BOUNDARY_NOT_READY"
    if readiness_issue_codes:
        return "gated", "MONITORING_READINESS_BLOCKED"
    return "ready", "READONLY_CAPABILITY_READY"


def safe_capability_matrix(
    config: MonitoringRuntimeConfig,
    *,
    config_saved: bool,
) -> dict[str, Any]:
    """Describe backend activation state without granting execution authority.

    The matrix is metadata-only. It does not resolve credentials, probe targets,
    execute collectors, capture packets, perform remediation, or accept browser
    selectors. Asset identifiers, hosts, ports, and credential references are never
    returned.
    """

    readiness = evaluate_monitoring_readiness(config, config_saved=config_saved)
    raw_issues = readiness.get("issues")
    issue_codes = frozenset(
        str(item.get("code"))
        for item in raw_issues
        if isinstance(item, dict) and item.get("code")
    ) if isinstance(raw_issues, list) else frozenset()

    enabled_assets = tuple(asset for asset in config.assets if asset.enabled)
    collectors: list[dict[str, object]] = []
    for capability in sorted(COLLECTOR_CAPABILITIES):
        configured_count = sum(
            1 for asset in enabled_assets if capability in asset.collector_capabilities
        )
        state, reason_code = _collector_state(
            config,
            capability,
            configured_asset_count=configured_count,
            readiness_issue_codes=issue_codes,
        )
        collectors.append(
            _row(
                capability,
                state,
                reason_code,
                configured_asset_count=configured_count,
                read_only=True,
                user_confirmation_required=True,
            )
        )

    if not config.enabled:
        run_state, run_reason = "disabled", "MONITORING_DISABLED"
    elif not config.allow_real_network:
        run_state, run_reason = "gated", "REAL_NETWORK_NOT_ALLOWED"
    elif issue_codes:
        run_state, run_reason = "gated", "MONITORING_READINESS_BLOCKED"
    else:
        run_state, run_reason = "ready", "READONLY_MONITORING_READY"

    initialize_state = "ready" if config_saved else "gated"
    initialize_reason = "LOCAL_DATABASE_INITIALIZE_READY" if config_saved else "CONFIG_NOT_SAVED"

    return {
        "schema_version": CAPABILITY_MATRIX_SCHEMA,
        "activation_scope": "local_console_metadata_only",
        "monitoring_enabled": bool(config.enabled),
        "real_network_read_enabled": bool(config.allow_real_network),
        "readiness": {
            "ready": readiness.get("ready") is True,
            "status": "ready" if readiness.get("ready") is True else "blocked",
            "issue_codes": sorted(issue_codes),
        },
        "read_surfaces": [
            _row(name, "active", "LOCAL_READ_SURFACE_ACTIVE", read_only=True)
            for name in _READ_SURFACES
        ],
        "local_operations": [
            _row(
                "initialize_local_database",
                initialize_state,
                initialize_reason,
                local_only=True,
                network_execution=False,
                user_confirmation_required=True,
            ),
            _row(
                "run_hourly_readonly",
                run_state,
                run_reason,
                local_only=True,
                network_execution=run_state == "ready",
                user_confirmation_required=True,
            ),
        ],
        "collector_capabilities": collectors,
        "restricted_surfaces": [
            _row(name, "disabled", "NOT_EXPOSED_BY_LOCAL_CONSOLE")
            for name in _RESTRICTED_SURFACES
        ],
        "contains_identifiers": False,
        "contains_raw_credentials": False,
        "authority": {
            "metadata_only": True,
            "config_is_authoritative": True,
            "browser_filters_exposed": False,
            "database_write": False,
            "network_execution": False,
            "collector_execution": False,
            "packet_capture_execution": False,
            "remediation_execution": False,
            "shell_execution": False,
        },
    }
