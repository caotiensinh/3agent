from __future__ import annotations

import inspect
from types import SimpleNamespace

from three_agent.diagnostics.vpn_tools import (
    VPN_PROFILE_LIMIT,
    VPN_STATUS_TOOL_ID,
    VPN_STATUS_TOOL_METADATA,
    build_vpn_status_plan,
    read_vpn_status,
)


class RecordingAuthority:
    def __init__(self, events: list[tuple] | None = None) -> None:
        self.calls: list[tuple[str, str, str, str]] = []
        self.events = events

    def require(self, capability: str, *, resource_kind: str, resource_ref: str, effect: str):
        self.calls.append((capability, resource_kind, resource_ref, effect))
        if self.events is not None:
            self.events.append(("authority", capability))
        return object()


def test_vpn_status_metadata_is_local_sensitive_read_only() -> None:
    assert len(VPN_STATUS_TOOL_METADATA) == 1
    metadata = VPN_STATUS_TOOL_METADATA[0]
    assert metadata.id == VPN_STATUS_TOOL_ID
    assert metadata.cost == "C0"
    assert metadata.risk == "sensitive_read"
    assert metadata.requires_admin is False
    assert metadata.network_access == "none"
    assert metadata.sensitive_outputs is True
    assert metadata.effect == "read"


def test_vpn_status_has_no_remote_target_or_credential_input_surface() -> None:
    parameters = set(inspect.signature(read_vpn_status).parameters)
    assert parameters == {"authority", "platform_name", "timeout"}
    assert not parameters & {"host", "url", "username", "password", "token", "secret", "path", "command"}


def test_windows_plan_is_fixed_and_noninteractive() -> None:
    plan = build_vpn_status_plan(platform_name="Windows")
    assert plan[:4] == ("powershell.exe", "-NoProfile", "-NonInteractive", "-Command")
    assert "Get-VpnConnection" in plan[4]
    assert str(VPN_PROFILE_LIMIT) in plan[4]
    assert "Credential" not in plan[4]


def test_linux_plan_is_fixed_local_link_inventory() -> None:
    assert build_vpn_status_plan(platform_name="Linux") == ("ip", "-details", "link", "show")


def test_windows_collection_requires_authority_before_subprocess(monkeypatch) -> None:
    events: list[tuple] = []
    authority = RecordingAuthority(events)

    def fake_run(argv, **kwargs):
        events.append(("subprocess", tuple(argv)))
        assert kwargs["shell"] is False
        assert kwargs["check"] is False
        assert kwargs["capture_output"] is True
        assert kwargs["text"] is True
        return SimpleNamespace(
            returncode=0,
            stdout='[{"Name":"Corp VPN","ConnectionStatus":"Connected","TunnelType":"Ikev2","SplitTunneling":true}]',
            stderr="",
        )

    monkeypatch.setattr("three_agent.diagnostics.vpn_tools.subprocess.run", fake_run)
    result = read_vpn_status(authority=authority, platform_name="Windows", timeout=3.0)

    assert events[0] == ("authority", VPN_STATUS_TOOL_ID)
    assert events[1][0] == "subprocess"
    assert authority.calls == [
        (VPN_STATUS_TOOL_ID, "vpn_status", "local:vpn:status", "read")
    ]
    assert result["observed_count"] == 1
    assert result["observations"] == [
        {
            "profile_name": "Corp VPN",
            "connection_status": "Connected",
            "tunnel_type": "Ikev2",
            "split_tunneling": True,
        }
    ]
    assert result["vpn_health_claimed"] is False
    assert result["connectivity_claimed"] is False
    assert result["root_cause_claimed"] is False
    assert result["interpretation"] == "evidence_only"


def test_linux_collection_only_reports_bounded_tunnel_candidates(monkeypatch) -> None:
    authority = RecordingAuthority()
    stdout = "\n".join(
        (
            "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN mode DEFAULT group default",
            "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP mode DEFAULT group default",
            "7: tun0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1500 state UNKNOWN mode DEFAULT group default",
            "8: wg-office: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 state UNKNOWN mode DEFAULT group default",
        )
    )

    def fake_run(argv, **kwargs):
        assert tuple(argv) == ("ip", "-details", "link", "show")
        assert kwargs["shell"] is False
        return SimpleNamespace(returncode=0, stdout=stdout, stderr="")

    monkeypatch.setattr("three_agent.diagnostics.vpn_tools.subprocess.run", fake_run)
    result = read_vpn_status(authority=authority, platform_name="Linux")

    assert authority.calls == [
        (VPN_STATUS_TOOL_ID, "vpn_status", "local:vpn:status", "read")
    ]
    assert [row["interface_name"] for row in result["observations"]] == ["tun0", "wg-office"]
    assert all(row["classification"] == "vpn_candidate_by_interface_name" for row in result["observations"])
    assert result["observation_semantics"] == "tunnel_candidate_interfaces_only"
    assert result["interpretation"] == "evidence_only"


def test_empty_collection_is_not_interpreted_as_vpn_down(monkeypatch) -> None:
    authority = RecordingAuthority()

    monkeypatch.setattr(
        "three_agent.diagnostics.vpn_tools.subprocess.run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout="", stderr=""),
    )
    result = read_vpn_status(authority=authority, platform_name="Linux")

    assert result["observed_count"] == 0
    assert result["collection_succeeded"] is True
    assert result["vpn_health_claimed"] is False
    assert result["connectivity_claimed"] is False
    assert result["root_cause_claimed"] is False
