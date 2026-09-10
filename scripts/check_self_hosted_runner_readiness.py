#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

SCHEMA = "workspace-ci/self-hosted-runner-readiness-v1"
_GITHUB_ENDPOINTS = ("https://github.com/", "https://api.github.com/")


def _runner_listener_count(proc_root: Path = Path("/proc")) -> int:
    count = 0
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return 0
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            raw = (entry / "cmdline").read_bytes().replace(b"\x00", b" ")
        except OSError:
            continue
        if b"Runner.Listener" in raw:
            count += 1
    return count


def _runner_service_counts() -> tuple[bool, int, int]:
    if shutil.which("systemctl") is None:
        return False, 0, 0
    listed = subprocess.run(
        ["systemctl", "list-unit-files", "--type=service", "--no-legend", "--no-pager"],
        check=False,
        capture_output=True,
        text=True,
    )
    if listed.returncode != 0:
        return True, 0, 0
    units = []
    for line in listed.stdout.splitlines():
        token = line.strip().split(maxsplit=1)[0] if line.strip() else ""
        if token.startswith("actions.runner.") and token.endswith(".service"):
            units.append(token)
    active = 0
    for unit in units:
        state = subprocess.run(
            ["systemctl", "is-active", unit],
            check=False,
            capture_output=True,
            text=True,
        )
        if state.stdout.strip() == "active":
            active += 1
    return True, len(units), active


def _endpoint_reachable(url: str, *, timeout_seconds: float = 5.0) -> bool:
    request = urllib.request.Request(
        url,
        method="HEAD",
        headers={"User-Agent": "workspace-runner-readiness/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
            return 100 <= int(response.status) < 500
    except urllib.error.HTTPError:
        # An HTTP response proves that DNS/TLS/outbound routing reached GitHub.
        return True
    except (OSError, urllib.error.URLError):
        return False


def evaluate_readiness(
    *,
    system_name: str,
    machine: str,
    systemd_available: bool,
    service_count: int,
    active_service_count: int,
    listener_count: int,
    github_reachable: bool,
    api_github_reachable: bool,
) -> dict[str, Any]:
    linux = system_name.lower() == "linux"
    x64 = machine.lower() in {"x86_64", "amd64"}
    network_ok = github_reachable and api_github_reachable

    if not linux or not x64:
        status = "UNSUPPORTED_HOST"
    elif listener_count > 0 and network_ok:
        status = "READY"
    elif listener_count <= 0 and service_count <= 0:
        status = "RUNNER_SERVICE_MISSING"
    elif listener_count <= 0 and active_service_count <= 0:
        status = "RUNNER_SERVICE_INACTIVE"
    elif listener_count <= 0:
        status = "RUNNER_PROCESS_MISSING"
    else:
        status = "NETWORK_UNREACHABLE"

    return {
        "schema": SCHEMA,
        "status": status,
        "linux": linux,
        "x64": x64,
        "systemd_available": bool(systemd_available),
        "runner_service_count": max(0, int(service_count)),
        "active_runner_service_count": max(0, int(active_service_count)),
        "runner_listener_count": max(0, int(listener_count)),
        "github_reachable": bool(github_reachable),
        "api_github_reachable": bool(api_github_reachable),
        "labels_server_side_verification_required": True,
        "mutations_performed": False,
        "secrets_read": False,
        "host_identity_included": False,
    }


def collect_readiness(*, check_network: bool = True) -> dict[str, Any]:
    systemd_available, service_count, active_service_count = _runner_service_counts()
    listener_count = _runner_listener_count()
    if check_network:
        github_reachable = _endpoint_reachable(_GITHUB_ENDPOINTS[0])
        api_github_reachable = _endpoint_reachable(_GITHUB_ENDPOINTS[1])
    else:
        github_reachable = True
        api_github_reachable = True
    payload = evaluate_readiness(
        system_name=platform.system(),
        machine=platform.machine(),
        systemd_available=systemd_available,
        service_count=service_count,
        active_service_count=active_service_count,
        listener_count=listener_count,
        github_reachable=github_reachable,
        api_github_reachable=api_github_reachable,
    )
    payload["network_check_skipped"] = not check_network
    return payload


def _self_test() -> None:
    ready = evaluate_readiness(
        system_name="Linux",
        machine="x86_64",
        systemd_available=True,
        service_count=1,
        active_service_count=1,
        listener_count=1,
        github_reachable=True,
        api_github_reachable=True,
    )
    assert ready["status"] == "READY"
    assert ready["mutations_performed"] is False
    assert ready["secrets_read"] is False


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Read-only GitHub self-hosted runner readiness diagnostic."
    )
    parser.add_argument(
        "--skip-network",
        action="store_true",
        help="Skip outbound GitHub reachability checks; useful for offline unit diagnostics.",
    )
    parser.add_argument("--self-test", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.self_test:
        _self_test()
        print("self-hosted runner readiness self-test PASS")
        return 0
    payload = collect_readiness(check_network=not args.skip_network)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["status"] == "READY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
