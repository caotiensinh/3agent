from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any

from .contracts import (
    COLLECTOR_CAPABILITIES,
    AssetInventoryRecord,
    MonitoringContractError,
    SecretReference,
    sha256_fingerprint,
    validate_management_host,
)

NETWORK_SCOPE = "approved_inventory_only"
ACTIVE_LIVENESS_CAPABILITIES = frozenset({"icmp_echo", "tcp_connect"})
PASSIVE_OR_COUNTER_CAPABILITIES = frozenset({"snmpv3_read", "local_net_read", "fixed_readonly_adapter"})
PRODUCTION_SAFETY_PROFILE = "non_disruptive_v1"
BANDWIDTH_MEASUREMENT_MODE = "counter_only"
PACKET_ANALYSIS_MODE = "passive_only"
READ_ONLY_EFFECTS = {
    "icmp_echo": "network_read",
    "tcp_connect": "network_read",
    "snmpv3_read": "network_read",
    "local_net_read": "local_read",
    "fixed_readonly_adapter": "execute_readonly",
}


@dataclass(frozen=True)
class MonitoringPolicy:
    profile_id: str = "default"
    network_scope: str = NETWORK_SCOPE
    read_only: bool = True
    production_safety_profile: str = PRODUCTION_SAFETY_PROFILE
    allow_active_liveness: bool = False
    bandwidth_measurement_mode: str = BANDWIDTH_MEASUREMENT_MODE
    packet_analysis_mode: str = PACKET_ANALYSIS_MODE
    max_workers: int = 4
    timeout_seconds: float = 3.0
    max_retries: int = 1
    max_catch_up_runs: int = 1
    allowed_capabilities: tuple[str, ...] = field(default_factory=lambda: tuple(sorted(COLLECTOR_CAPABILITIES)))
    schema_version: str = "workspace-security-monitoring/policy-v2"

    def validate(self) -> "MonitoringPolicy":
        profile = str(self.profile_id or "").strip()
        if not profile or len(profile) > 128 or any(ch.isspace() for ch in profile):
            raise MonitoringContractError("profile_id must be a compact identifier")
        object.__setattr__(self, "profile_id", profile)
        if self.network_scope != NETWORK_SCOPE:
            raise MonitoringContractError("monitoring network scope must be approved_inventory_only")
        if not self.read_only:
            raise MonitoringContractError("monitoring v1 is read-only by policy")
        if self.production_safety_profile != PRODUCTION_SAFETY_PROFILE:
            raise MonitoringContractError("production monitoring requires non_disruptive_v1")
        if not isinstance(self.allow_active_liveness, bool):
            raise MonitoringContractError("allow_active_liveness must be boolean")
        if self.bandwidth_measurement_mode != BANDWIDTH_MEASUREMENT_MODE:
            raise MonitoringContractError("bandwidth measurement must be counter_only")
        if self.packet_analysis_mode != PACKET_ANALYSIS_MODE:
            raise MonitoringContractError("packet analysis must be passive_only")
        if not 1 <= self.max_workers <= 4:
            raise MonitoringContractError("production-safe max_workers must be within 1..4")
        if not 0.1 <= float(self.timeout_seconds) <= 5.0:
            raise MonitoringContractError("production-safe timeout_seconds must be within 0.1..5")
        if not 0 <= self.max_retries <= 1:
            raise MonitoringContractError("max_retries must be within 0..1")
        if not 0 <= self.max_catch_up_runs <= 1:
            raise MonitoringContractError("max_catch_up_runs must be within 0..1")
        caps = tuple(dict.fromkeys(str(v).strip() for v in self.allowed_capabilities if str(v).strip()))
        unknown = set(caps) - COLLECTOR_CAPABILITIES
        if unknown:
            raise MonitoringContractError(f"unknown policy capabilities: {sorted(unknown)}")
        object.__setattr__(self, "allowed_capabilities", caps)
        return self

    @property
    def fingerprint(self) -> str:
        self.validate()
        payload = asdict(self)
        payload["allowed_capabilities"] = list(self.allowed_capabilities)
        return sha256_fingerprint(payload)


@dataclass(frozen=True)
class MonitoringCapabilityDecision:
    asset_id: str
    capability: str
    effect: str
    target_host: str
    target_port: int | None
    allowed: bool
    reason_code: str
    policy_fingerprint: str
    asset_fingerprint: str
    schema_version: str = "workspace-security-monitoring/capability-decision-v1"

    def metadata(self) -> dict[str, Any]:
        target_digest = hashlib.sha256(self.target_host.encode("utf-8")).hexdigest()
        return {
            "schema_version": self.schema_version,
            "asset_id": self.asset_id,
            "capability": self.capability,
            "effect": self.effect,
            "target_sha256": "sha256:" + target_digest,
            "target_port": self.target_port,
            "allowed": self.allowed,
            "reason_code": self.reason_code,
            "policy_fingerprint": self.policy_fingerprint,
            "asset_fingerprint": self.asset_fingerprint,
        }


class MonitoringPolicyEngine:
    """Specialized deterministic, non-disruptive LAN read authority.

    The authority is separate from model/task authority. It can only authorize the
    exact read-only capability/host/port declared by operator-approved inventory.
    Active ICMP/TCP liveness is disabled by default and can never be used for
    throughput measurement. State-changing or traffic-generating operations do not
    exist in the capability vocabulary.
    """

    def __init__(self, policy: MonitoringPolicy):
        self.policy = policy.validate()

    def _decision(
        self,
        asset: AssetInventoryRecord,
        capability: str,
        effect: str,
        target_host: str,
        target_port: int | None,
        *,
        allowed: bool,
        reason_code: str,
    ) -> MonitoringCapabilityDecision:
        return MonitoringCapabilityDecision(
            asset_id=asset.asset_id,
            capability=capability,
            effect=effect,
            target_host=target_host,
            target_port=target_port,
            allowed=allowed,
            reason_code=reason_code,
            policy_fingerprint=self.policy.fingerprint,
            asset_fingerprint=asset.fingerprint,
        )

    def authorize(
        self,
        asset: AssetInventoryRecord,
        *,
        capability: str,
        effect: str,
        target_host: str,
        target_port: int | None = None,
        credential_ref: SecretReference | None = None,
    ) -> MonitoringCapabilityDecision:
        asset.validate()
        cap = str(capability or "").strip()
        eff = str(effect or "").strip()
        try:
            host = validate_management_host(target_host)
        except MonitoringContractError:
            host = "invalid-target"
            return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="TARGET_INVALID")

        if not asset.enabled:
            return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="ASSET_DISABLED")
        if cap not in COLLECTOR_CAPABILITIES:
            return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="CAPABILITY_UNKNOWN")
        if cap not in self.policy.allowed_capabilities:
            return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="CAPABILITY_POLICY_DENIED")
        if cap in ACTIVE_LIVENESS_CAPABILITIES and not self.policy.allow_active_liveness:
            return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="ACTIVE_LIVENESS_DISABLED")
        if cap not in asset.collector_capabilities:
            return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="CAPABILITY_NOT_IN_ASSET_PROFILE")
        expected_effect = READ_ONLY_EFFECTS[cap]
        if eff != expected_effect:
            return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="EFFECT_NOT_READ_ONLY")
        if host != asset.management_host:
            return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="TARGET_NOT_APPROVED")

        if cap == "tcp_connect":
            if target_port is None or int(target_port) not in asset.allowed_tcp_ports:
                return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="PORT_NOT_APPROVED")
        elif target_port is not None:
            return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="PORT_NOT_APPLICABLE")

        if cap == "snmpv3_read":
            if asset.credential_ref is None or credential_ref is None:
                return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="CREDENTIAL_REF_REQUIRED")
            try:
                credential_ref.validate()
            except MonitoringContractError:
                return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="CREDENTIAL_REF_INVALID")
            if credential_ref.handle != asset.credential_ref.handle:
                return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="CREDENTIAL_REF_NOT_APPROVED")
        elif credential_ref is not None:
            return self._decision(asset, cap, eff, host, target_port, allowed=False, reason_code="CREDENTIAL_REF_NOT_APPLICABLE")

        return self._decision(asset, cap, eff, host, target_port, allowed=True, reason_code="MONITORING_READ_AUTHORIZED")

    def require(self, *args: Any, **kwargs: Any) -> MonitoringCapabilityDecision:
        decision = self.authorize(*args, **kwargs)
        if not decision.allowed:
            raise PermissionError(decision.reason_code)
        return decision
