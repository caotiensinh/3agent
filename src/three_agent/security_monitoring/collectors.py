from __future__ import annotations

import re
import socket
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Protocol, Sequence

from .contracts import AssetInventoryRecord, ObservationRecord, SecretReference
from .policy import MonitoringPolicyEngine


@dataclass(frozen=True)
class CollectorResult:
    observations: tuple[ObservationRecord, ...]
    failure_code: str | None = None


class SnmpV3Backend(Protocol):
    """Backend must resolve an opaque secret reference internally, never via argv/logs."""

    def read_interface_counters(
        self,
        *,
        target_host: str,
        credential_ref: SecretReference,
        timeout_seconds: float,
    ) -> Sequence[dict]: ...


class TcpConnectCollector:
    def __init__(
        self,
        policy_engine: MonitoringPolicyEngine,
        *,
        dialer: Callable[[tuple[str, int], float], object] | None = None,
    ):
        self.policy_engine = policy_engine
        self._dialer = dialer or (lambda address, timeout: socket.create_connection(address, timeout=timeout))

    def collect(
        self,
        *,
        asset: AssetInventoryRecord,
        port: int,
        run_id: str,
        observed_at: str | None = None,
    ) -> CollectorResult:
        self.policy_engine.require(
            asset,
            capability="tcp_connect",
            effect="network_read",
            target_host=asset.management_host,
            target_port=port,
        )
        timestamp = observed_at or datetime.now(timezone.utc).isoformat()
        timeout = self.policy_engine.policy.timeout_seconds
        try:
            connection = self._dialer((asset.management_host, int(port)), timeout)
            close = getattr(connection, "close", None)
            if callable(close):
                close()
            status, value, failure = "ok", True, None
        except TimeoutError:
            status, value, failure = "timeout", False, "TCP_CONNECT_TIMEOUT"
        except OSError:
            status, value, failure = "unreachable", False, "TCP_CONNECT_FAILED"
        observation = ObservationRecord(
            run_id=run_id,
            asset_id=asset.asset_id,
            collector="tcp_connect",
            observed_at=timestamp,
            metric=f"tcp_port_{int(port)}_reachable",
            status=status,
            value=value,
            unit="bool",
        ).validate()
        return CollectorResult((observation,), failure)


class IcmpCollector:
    _RTT_RE = re.compile(r"time[=<]([0-9.]+)\s*ms", re.IGNORECASE)

    def __init__(
        self,
        policy_engine: MonitoringPolicyEngine,
        *,
        executor: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ):
        self.policy_engine = policy_engine
        self._executor = executor or subprocess.run

    def _argv(self, host: str) -> list[str]:
        seconds = max(1, int(round(self.policy_engine.policy.timeout_seconds)))
        return ["ping", "-n", "-c", "1", "-W", str(seconds), host]

    def collect(
        self,
        *,
        asset: AssetInventoryRecord,
        run_id: str,
        observed_at: str | None = None,
    ) -> CollectorResult:
        self.policy_engine.require(
            asset,
            capability="icmp_echo",
            effect="network_read",
            target_host=asset.management_host,
        )
        timestamp = observed_at or datetime.now(timezone.utc).isoformat()
        timeout = self.policy_engine.policy.timeout_seconds + 1.0
        try:
            result = self._executor(
                self._argv(asset.management_host),
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
                shell=False,
            )
            stdout = str(result.stdout or "")
            reachable = result.returncode == 0
            match = self._RTT_RE.search(stdout)
            rtt = float(match.group(1)) if match else None
            observations = [
                ObservationRecord(
                    run_id=run_id,
                    asset_id=asset.asset_id,
                    collector="icmp_echo",
                    observed_at=timestamp,
                    metric="icmp_reachable",
                    status="ok" if reachable else "unreachable",
                    value=reachable,
                    unit="bool",
                ).validate()
            ]
            if rtt is not None:
                observations.append(
                    ObservationRecord(
                        run_id=run_id,
                        asset_id=asset.asset_id,
                        collector="icmp_echo",
                        observed_at=timestamp,
                        metric="icmp_rtt_ms",
                        status="ok",
                        value=rtt,
                        unit="ms",
                    ).validate()
                )
            return CollectorResult(tuple(observations), None if reachable else "ICMP_UNREACHABLE")
        except subprocess.TimeoutExpired:
            observation = ObservationRecord(
                run_id=run_id,
                asset_id=asset.asset_id,
                collector="icmp_echo",
                observed_at=timestamp,
                metric="icmp_reachable",
                status="timeout",
                value=False,
                unit="bool",
            ).validate()
            return CollectorResult((observation,), "ICMP_TIMEOUT")
        except FileNotFoundError:
            observation = ObservationRecord(
                run_id=run_id,
                asset_id=asset.asset_id,
                collector="icmp_echo",
                observed_at=timestamp,
                metric="icmp_reachable",
                status="unsupported",
                value=None,
                unit="bool",
            ).validate()
            return CollectorResult((observation,), "PING_BINARY_UNAVAILABLE")


class LocalProcNetCollector:
    """Linux-only zero-dependency network counters from /proc/net/dev."""

    def __init__(self, policy_engine: MonitoringPolicyEngine, *, proc_path: str | Path = "/proc/net/dev"):
        self.policy_engine = policy_engine
        self.proc_path = Path(proc_path)

    @staticmethod
    def parse(text: str) -> tuple[dict[str, int | str], ...]:
        rows: list[dict[str, int | str]] = []
        for raw in str(text).splitlines()[2:]:
            if ":" not in raw:
                continue
            interface, values = raw.split(":", 1)
            fields = values.split()
            if len(fields) < 16:
                continue
            name = interface.strip()
            if not name:
                continue
            rows.append(
                {
                    "interface": name,
                    "rx_bytes": int(fields[0]),
                    "rx_packets": int(fields[1]),
                    "rx_errors": int(fields[2]),
                    "rx_dropped": int(fields[3]),
                    "tx_bytes": int(fields[8]),
                    "tx_packets": int(fields[9]),
                    "tx_errors": int(fields[10]),
                    "tx_dropped": int(fields[11]),
                }
            )
        return tuple(rows)

    def collect(
        self,
        *,
        asset: AssetInventoryRecord,
        run_id: str,
        observed_at: str | None = None,
    ) -> CollectorResult:
        self.policy_engine.require(
            asset,
            capability="local_net_read",
            effect="local_read",
            target_host=asset.management_host,
        )
        timestamp = observed_at or datetime.now(timezone.utc).isoformat()
        try:
            rows = self.parse(self.proc_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            observation = ObservationRecord(
                run_id=run_id,
                asset_id=asset.asset_id,
                collector="local_net_read",
                observed_at=timestamp,
                metric="local_net_state",
                status="error",
                value=None,
            ).validate()
            return CollectorResult((observation,), "LOCAL_PROC_NET_READ_FAILED")
        observations: list[ObservationRecord] = []
        for row in rows:
            interface = str(row["interface"]).replace(".", "_")
            for metric in ("rx_bytes", "rx_packets", "rx_errors", "rx_dropped", "tx_bytes", "tx_packets", "tx_errors", "tx_dropped"):
                observations.append(
                    ObservationRecord(
                        run_id=run_id,
                        asset_id=asset.asset_id,
                        collector="local_net_read",
                        observed_at=timestamp,
                        metric=f"if_{interface}_{metric}",
                        status="ok",
                        value=int(row[metric]),
                        unit="bytes" if metric.endswith("bytes") else "count",
                    ).validate()
                )
        if not observations:
            return CollectorResult((), "LOCAL_PROC_NET_EMPTY")
        return CollectorResult(tuple(observations), None)


class SnmpV3Collector:
    """Read-only adapter contract; backend implementation is admitted separately."""

    def __init__(self, policy_engine: MonitoringPolicyEngine, backend: SnmpV3Backend):
        self.policy_engine = policy_engine
        self.backend = backend

    def collect(
        self,
        *,
        asset: AssetInventoryRecord,
        run_id: str,
        observed_at: str | None = None,
    ) -> CollectorResult:
        credential_ref = asset.credential_ref
        self.policy_engine.require(
            asset,
            capability="snmpv3_read",
            effect="network_read",
            target_host=asset.management_host,
            credential_ref=credential_ref,
        )
        assert credential_ref is not None
        timestamp = observed_at or datetime.now(timezone.utc).isoformat()
        try:
            rows = self.backend.read_interface_counters(
                target_host=asset.management_host,
                credential_ref=credential_ref,
                timeout_seconds=self.policy_engine.policy.timeout_seconds,
            )
        except TimeoutError:
            return CollectorResult((), "SNMPV3_TIMEOUT")
        except OSError:
            return CollectorResult((), "SNMPV3_READ_FAILED")
        observations: list[ObservationRecord] = []
        for row in rows:
            interface = str(row.get("interface") or "unknown").replace(".", "_")
            for source_key, metric, unit in (
                ("rx_bytes", "rx_bytes", "bytes"),
                ("tx_bytes", "tx_bytes", "bytes"),
                ("rx_errors", "rx_errors", "count"),
                ("tx_errors", "tx_errors", "count"),
                ("rx_discards", "rx_discards", "count"),
                ("tx_discards", "tx_discards", "count"),
                ("speed_bps", "speed_bps", "bps"),
            ):
                if source_key not in row:
                    continue
                observations.append(
                    ObservationRecord(
                        run_id=run_id,
                        asset_id=asset.asset_id,
                        collector="snmpv3_read",
                        observed_at=timestamp,
                        metric=f"if_{interface}_{metric}",
                        status="ok",
                        value=int(row[source_key]),
                        unit=unit,
                    ).validate()
                )
        return CollectorResult(tuple(observations), None if observations else "SNMPV3_EMPTY")
