from __future__ import annotations

from pathlib import Path

from .autonomous_diagnostics import AutonomousNetworkDiagnosticAgent
from .policy import MonitoringPolicyEngine
from .runtime_config import load_runtime_config


class AutonomousDiagnosticService:
    """Guarded application entrypoint for one-shot read-only diagnostics.

    The operator request can select only an asset already present in the configured
    inventory. Network authority remains entirely controlled by the stored monitoring
    policy and the asset's collector/port allowlist.
    """

    def __init__(self, config_path: Path | str) -> None:
        self.config_path = Path(config_path)

    def diagnose(self, request: str, *, execute_readonly: bool) -> dict[str, object]:
        config = load_runtime_config(self.config_path)
        if not config.enabled:
            raise RuntimeError("MONITORING_DISABLED")
        if not config.allow_real_network:
            raise RuntimeError("REAL_NETWORK_NOT_ALLOWED_BY_CONFIG")
        if not execute_readonly:
            raise RuntimeError("EXPLICIT_READONLY_EXECUTION_FLAG_REQUIRED")
        if not config.policy.allow_active_liveness:
            raise RuntimeError("ACTIVE_LIVENESS_NOT_ALLOWED_BY_POLICY")

        report_dir = config.database_path.parent / "diagnostic_reports"
        agent = AutonomousNetworkDiagnosticAgent(
            MonitoringPolicyEngine(config.policy),
            config.assets,
        )
        return agent.diagnose(request, report_dir=report_dir).public_dict()
