from __future__ import annotations

from dataclasses import dataclass

from .contracts import AssetInventoryRecord, MonitoringContractError, SecretReference, sha256_fingerprint
from .policy import ACTIVE_LIVENESS_CAPABILITIES, MonitoringPolicy

MAX_ACTIVE_LIVENESS_WORK_PER_ASSET = 2


@dataclass(frozen=True)
class CollectorWorkItem:
    work_id: str
    asset_id: str
    capability: str
    target_host: str
    target_port: int | None = None
    credential_ref: SecretReference | None = None


def compile_collection_plan(
    assets: tuple[AssetInventoryRecord, ...],
    *,
    policy: MonitoringPolicy | None = None,
) -> tuple[CollectorWorkItem, ...]:
    """Compile operator-approved inventory into bounded non-disruptive read work.

    The production-safe default deliberately omits ICMP/TCP active liveness. Those
    probes appear only when the operator explicitly enables `allow_active_liveness`.
    Even then, active work is hard-capped per asset and is never a bandwidth test.
    """

    effective_policy = (policy or MonitoringPolicy()).validate()
    work: list[CollectorWorkItem] = []
    for asset in sorted((a.validate() for a in assets if a.enabled), key=lambda a: a.asset_id):
        active_for_asset = 0
        for capability in asset.collector_capabilities:
            if capability in ACTIVE_LIVENESS_CAPABILITIES and not effective_policy.allow_active_liveness:
                continue
            if capability == "tcp_connect":
                for port in asset.allowed_tcp_ports:
                    active_for_asset += 1
                    if active_for_asset > MAX_ACTIVE_LIVENESS_WORK_PER_ASSET:
                        raise MonitoringContractError("active liveness work exceeds production-safe per-asset cap")
                    payload = [asset.asset_id, capability, asset.management_host, int(port)]
                    work.append(
                        CollectorWorkItem(
                            work_id="work-" + sha256_fingerprint(payload).split(":", 1)[1][:24],
                            asset_id=asset.asset_id,
                            capability=capability,
                            target_host=asset.management_host,
                            target_port=int(port),
                        )
                    )
            elif capability == "icmp_echo":
                active_for_asset += 1
                if active_for_asset > MAX_ACTIVE_LIVENESS_WORK_PER_ASSET:
                    raise MonitoringContractError("active liveness work exceeds production-safe per-asset cap")
                payload = [asset.asset_id, capability, asset.management_host]
                work.append(
                    CollectorWorkItem(
                        work_id="work-" + sha256_fingerprint(payload).split(":", 1)[1][:24],
                        asset_id=asset.asset_id,
                        capability=capability,
                        target_host=asset.management_host,
                    )
                )
            elif capability in {"local_net_read", "snmpv3_read"}:
                payload = [asset.asset_id, capability, asset.management_host]
                work.append(
                    CollectorWorkItem(
                        work_id="work-" + sha256_fingerprint(payload).split(":", 1)[1][:24],
                        asset_id=asset.asset_id,
                        capability=capability,
                        target_host=asset.management_host,
                        credential_ref=asset.credential_ref if capability == "snmpv3_read" else None,
                    )
                )
            # fixed_readonly_adapter intentionally requires a later immutable adapter
            # registry. It is never converted into free-form shell text.
    return tuple(work)
