from __future__ import annotations

import subprocess

import pytest

from three_agent.security_monitoring.collectors import IcmpCollector
from three_agent.security_monitoring.contracts import AssetInventoryRecord
from three_agent.security_monitoring.policy import MonitoringPolicy, MonitoringPolicyEngine


def _policy_engine(timeout_seconds: float = 2.0) -> MonitoringPolicyEngine:
    return MonitoringPolicyEngine(
        MonitoringPolicy(
            profile_id="icmp-cross-platform-test",
            read_only=True,
            allow_active_liveness=True,
            timeout_seconds=timeout_seconds,
            max_retries=0,
            max_catch_up_runs=0,
            allowed_capabilities=("icmp_echo",),
        ).validate()
    )


def _asset() -> AssetInventoryRecord:
    return AssetInventoryRecord(
        asset_id="test-lan-device",
        role="network-device",
        management_host="192.0.2.10",
        collector_capabilities=("icmp_echo",),
        data_class="internal",
        enabled=True,
    ).validate()


def test_linux_ping_argv_is_bounded_and_native() -> None:
    collector = IcmpCollector(_policy_engine(), platform_name="posix")
    assert collector._argv("192.0.2.10") == [
        "ping",
        "-n",
        "-c",
        "1",
        "-W",
        "2",
        "192.0.2.10",
    ]


def test_windows_ping_argv_is_bounded_and_native() -> None:
    collector = IcmpCollector(_policy_engine(), platform_name="nt")
    assert collector._argv("192.0.2.10") == [
        "ping",
        "-n",
        "1",
        "-w",
        "2000",
        "192.0.2.10",
    ]


@pytest.mark.parametrize(
    ("stdout", "expected"),
    [
        ("64 bytes from 192.0.2.10: icmp_seq=1 ttl=64 time=0.996 ms", 0.996),
        ("Reply from 192.0.2.10: bytes=32 time<1ms TTL=128", 1.0),
        ("192.0.2.10 からの応答: バイト数 =32 時間 <1ms TTL=128", 1.0),
    ],
)
def test_rtt_parser_supports_linux_and_windows_reply_lines(stdout: str, expected: float) -> None:
    assert IcmpCollector._parse_rtt_ms(stdout) == expected


@pytest.mark.parametrize(
    "stdout",
    [
        "Minimum = 0ms, Maximum = 0ms, Average = 0ms",
        "最小 = 0ms、最大 = 0ms、平均 = 0ms",
        "rtt min/avg/max/mdev = 0.100/0.200/0.300/0.010 ms",
    ],
)
def test_rtt_parser_does_not_invent_reply_rtt_from_summary(stdout: str) -> None:
    assert IcmpCollector._parse_rtt_ms(stdout) is None


def test_collect_uses_shell_false_and_windows_native_argv() -> None:
    captured: dict[str, object] = {}

    def executor(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured["argv"] = argv
        captured.update(kwargs)
        return subprocess.CompletedProcess(
            argv,
            0,
            stdout="Reply from 192.0.2.10: bytes=32 time<1ms TTL=128\n",
            stderr="",
        )

    collector = IcmpCollector(_policy_engine(), executor=executor, platform_name="nt")
    result = collector.collect(
        asset=_asset(),
        run_id="run:icmp-windows-test",
        observed_at="2026-09-01T00:00:00+00:00",
    )

    assert captured["argv"] == ["ping", "-n", "1", "-w", "2000", "192.0.2.10"]
    assert captured["shell"] is False
    assert captured["check"] is False
    assert captured["capture_output"] is True
    assert captured["text"] is True
    assert captured["timeout"] == 3.0
    assert result.failure_code is None
    assert [(item.metric, item.status, item.value) for item in result.observations] == [
        ("icmp_reachable", "ok", True),
        ("icmp_rtt_ms", "ok", 1.0),
    ]


def test_collect_unreachable_does_not_emit_rtt_without_reply_line() -> None:
    def executor(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            argv,
            1,
            stdout="Request timed out.\nMinimum = 0ms, Maximum = 0ms, Average = 0ms\n",
            stderr="",
        )

    collector = IcmpCollector(_policy_engine(), executor=executor, platform_name="nt")
    result = collector.collect(
        asset=_asset(),
        run_id="run:icmp-unreachable-test",
        observed_at="2026-09-01T00:00:00+00:00",
    )

    assert result.failure_code == "ICMP_UNREACHABLE"
    assert len(result.observations) == 1
    assert result.observations[0].metric == "icmp_reachable"
    assert result.observations[0].status == "unreachable"
    assert result.observations[0].value is False


def test_collect_missing_ping_binary_fails_closed() -> None:
    def executor(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise FileNotFoundError("ping")

    collector = IcmpCollector(_policy_engine(), executor=executor, platform_name="posix")
    result = collector.collect(
        asset=_asset(),
        run_id="run:icmp-no-binary-test",
        observed_at="2026-09-01T00:00:00+00:00",
    )

    assert result.failure_code == "PING_BINARY_UNAVAILABLE"
    assert len(result.observations) == 1
    assert result.observations[0].status == "unsupported"
    assert result.observations[0].value is None
