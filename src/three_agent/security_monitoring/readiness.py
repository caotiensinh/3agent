from __future__ import annotations

from typing import Any

from .runtime_config import MonitoringRuntimeConfig

READINESS_SCHEMA = "workspace-security-monitoring/readiness-v1"


def evaluate_monitoring_readiness(
    config: MonitoringRuntimeConfig, *, config_saved: bool
) -> dict[str, Any]:
    """Evaluate whether configured collectors may enter the runtime boundary.

    This check is deliberately metadata-only. It may inspect the existence and
    file type of an opaque credential reference, but it never opens secret
    files, probes the network, captures packets, executes remediation, or runs
    shell commands.
    """
    issues: list[dict[str, str]] = []
    warnings: list[dict[str, str]] = []

    if not config_saved:
        issues.append(
            {
                "code": "CONFIG_NOT_SAVED",
                "message": "Save configuration before monitoring can run.",
            }
        )
    if not config.enabled:
        warnings.append(
            {
                "code": "MONITORING_DISABLED",
                "message": "Monitoring is currently disabled.",
            }
        )
    if config.enabled and not config.allow_real_network:
        issues.append(
            {
                "code": "REAL_NETWORK_NOT_ALLOWED",
                "message": "Enable approved real-network reads before running the collector.",
            }
        )
    if not config.assets:
        warnings.append(
            {
                "code": "NO_ASSETS",
                "message": "No approved monitoring assets are configured.",
            }
        )

    secret_dir = config.secret_directory
    for asset in config.assets:
        if not asset.enabled or "snmpv3_read" not in asset.collector_capabilities:
            continue
        if secret_dir is None:
            issues.append(
                {
                    "code": "SECRET_DIRECTORY_REQUIRED",
                    "message": f"{asset.asset_id}: SNMPv3 requires a secret directory.",
                }
            )
            continue
        if asset.credential_ref is None:
            issues.append(
                {
                    "code": "CREDENTIAL_REF_REQUIRED",
                    "message": f"{asset.asset_id}: SNMPv3 requires an opaque credential reference.",
                }
            )
            continue
        secret_name = asset.credential_ref.handle.removeprefix("secret-ref:")
        secret_file = secret_dir / f"{secret_name}.json"
        if not secret_file.is_file() or secret_file.is_symlink():
            issues.append(
                {
                    "code": "SECRET_REF_UNRESOLVED",
                    "message": f"{asset.asset_id}: credential reference is not present in the local secret boundary.",
                }
            )

    ready = not issues
    return {
        "schema_version": READINESS_SCHEMA,
        "ready": ready,
        "status": "ready" if ready else "blocked",
        "config_saved": bool(config_saved),
        "policy_fingerprint": config.policy.fingerprint,
        "enabled_asset_count": sum(1 for asset in config.assets if asset.enabled),
        "issues": issues,
        "warnings": warnings,
        "network_test_executed": False,
        "secret_values_read": False,
        "packet_capture_executed": False,
        "remediation_executed": False,
    }
