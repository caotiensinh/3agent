from __future__ import annotations

from dataclasses import dataclass

from .contracts import AssetInventoryRecord, SecretReference, sha256_fingerprint


@dataclass(frozen=True)
class CollectorWorkItem:
    work_id: str
    asset_id: str
    capability: str
    target_host: str
    target_port: int | None = None
    credential_ref: SecretReference | None = None


def compile_collection_plan(assets: tuple[AssetInventoryRecord, ...]) -> tuple[CollectorWorkItem, ...]:
    """Compile only operator-approved inventory into fixed typed read work."""

    work: list[CollectorWorkItem] = []
    for asset in sorted((a.validate() for a in assets if a.enabled), key=lambda a: a.asset_id):
        for capability in asset.collector_capabilities:
            if capability == "tcp_connect":
                for port in asset.allowed_tcp_ports:
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
            elif capability in {"icmp_echo", "local_net_read", "snmpv3_read"}:
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
            # fixed_readonly_adapter intentionally requires a later adapter registry
            # with an immutable command ID. It is not converted into free-form shell.
    return tuple(work)
