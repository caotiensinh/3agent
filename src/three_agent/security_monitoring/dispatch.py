from __future__ import annotations

from pathlib import Path

from .collectors import (
    CollectorResult,
    IcmpCollector,
    LocalProcNetCollector,
    SnmpV3Backend,
    SnmpV3Collector,
    TcpConnectCollector,
)
from .contracts import AssetInventoryRecord
from .plan import CollectorWorkItem
from .policy import MonitoringPolicyEngine


class DefaultCollectorDispatcher:
    """Typed dispatcher. There is no free-form command or target input."""

    def __init__(
        self,
        policy_engine: MonitoringPolicyEngine,
        *,
        snmp_backend: SnmpV3Backend | None = None,
        proc_net_path: str | Path = "/proc/net/dev",
    ):
        self.policy_engine = policy_engine
        self.tcp = TcpConnectCollector(policy_engine)
        self.icmp = IcmpCollector(policy_engine)
        self.local = LocalProcNetCollector(policy_engine, proc_path=proc_net_path)
        self.snmp = SnmpV3Collector(policy_engine, snmp_backend) if snmp_backend is not None else None

    def __call__(
        self,
        item: CollectorWorkItem,
        asset: AssetInventoryRecord,
        run_id: str,
        observed_at: str,
    ) -> CollectorResult:
        if item.asset_id != asset.asset_id or item.target_host != asset.management_host:
            raise PermissionError("COLLECTOR_PLAN_ASSET_MISMATCH")
        if item.capability == "tcp_connect":
            if item.target_port is None:
                raise PermissionError("COLLECTOR_PLAN_PORT_REQUIRED")
            return self.tcp.collect(asset=asset, port=item.target_port, run_id=run_id, observed_at=observed_at)
        if item.capability == "icmp_echo":
            return self.icmp.collect(asset=asset, run_id=run_id, observed_at=observed_at)
        if item.capability == "local_net_read":
            return self.local.collect(asset=asset, run_id=run_id, observed_at=observed_at)
        if item.capability == "snmpv3_read":
            if self.snmp is None:
                return CollectorResult((), "SNMPV3_BACKEND_UNAVAILABLE")
            return self.snmp.collect(asset=asset, run_id=run_id, observed_at=observed_at)
        raise PermissionError("COLLECTOR_CAPABILITY_NOT_IMPLEMENTED")
