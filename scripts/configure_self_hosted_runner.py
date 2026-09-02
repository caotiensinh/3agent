#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

SCHEMA = "workspace-ci/self-hosted-runner-bootstrap-v1"
MARKER_SCHEMA = "workspace-ci/self-hosted-runner-bootstrap-marker-v1"
REPO_URL = "https://github.com/caotiensinh/3agent"
CUSTOM_LABEL = "r9"
DEFAULT_RUNNER_NAME = "workspace-r9"
_REQUIRED_SERVER_LABELS = ("self-hosted", "Linux", "X64", CUSTOM_LABEL)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")

RunProcess = Callable[[Sequence[str], Path, Mapping[str, str]], int]
ReadinessProbe = Callable[[], Mapping[str, Any]]


def _run_process(argv: Sequence[str], cwd: Path, env: Mapping[str, str]) -> int:
    try:
        completed = subprocess.run(
            list(argv),
            cwd=str(cwd),
            env=dict(env),
            check=False,
            capture_output=True,
            text=True,
            timeout=180,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 125
    return int(completed.returncode)


def _probe_readiness() -> Mapping[str, Any]:
    script = Path(__file__).with_name("check_self_hosted_runner_readiness.py")
    try:
        completed = subprocess.run(
            [sys.executable, str(script)],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "READINESS_PROBE_FAILED"}
    try:
        payload = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError):
        return {"status": "READINESS_PROBE_FAILED"}
    if not isinstance(payload, dict):
        return {"status": "READINESS_PROBE_FAILED"}
    allowed = {
        "status",
        "linux",
        "x64",
        "systemd_available",
        "runner_service_count",
        "active_runner_service_count",
        "runner_listener_count",
        "github_reachable",
        "api_github_reachable",
        "labels_server_side_verification_required",
        "mutations_performed",
        "secrets_read",
        "host_identity_included",
        "network_check_skipped",
    }
    return {key: payload[key] for key in allowed if key in payload}


def _safe_payload(status: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "repository_url": REPO_URL,
        "required_server_labels": list(_REQUIRED_SERVER_LABELS),
        "registration_token_source": "ACTIONS_RUNNER_TOKEN",
        "registration_token_in_command_line": False,
        "registration_token_logged": False,
        "replace_existing_runner": False,
        "host_identity_included": False,
        "server_job_assignment_required": True,
        "helper_requires_unprivileged_user": True,
        "service_privilege_mode": "sudo-noninteractive",
    }
    payload.update(extra)
    return payload


def _marker_path(runner_dir: Path) -> Path:
    return runner_dir / ".workspace-r9-bootstrap.json"


def _load_marker(runner_dir: Path) -> bool:
    path = _marker_path(runner_dir)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        isinstance(payload, dict)
        and payload.get("schema") == MARKER_SCHEMA
        and payload.get("repository_url") == REPO_URL
        and payload.get("custom_label") == CUSTOM_LABEL
    )


def _write_marker(runner_dir: Path) -> None:
    path = _marker_path(runner_dir)
    payload = {
        "schema": MARKER_SCHEMA,
        "repository_url": REPO_URL,
        "custom_label": CUSTOM_LABEL,
        "managed_by": "scripts/configure_self_hosted_runner.py",
        "contains_secret": False,
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _sanitized_runtime_env(environ: Mapping[str, str]) -> dict[str, str]:
    env = dict(environ)
    env.pop("ACTIONS_RUNNER_TOKEN", None)
    env.pop("ACTIONS_RUNNER_INPUT_TOKEN", None)
    return env


def _child_env(environ: Mapping[str, str], token: str) -> dict[str, str]:
    env = _sanitized_runtime_env(environ)
    env["ACTIONS_RUNNER_INPUT_TOKEN"] = token
    return env


def _sudo_svc_command(svc_sh: Path, action: str) -> list[str]:
    return ["sudo", "-n", str(svc_sh), action]


def bootstrap_runner(
    *,
    runner_dir: Path,
    token: str,
    runner_name: str = DEFAULT_RUNNER_NAME,
    install_service: bool = False,
    system_name: str | None = None,
    machine: str | None = None,
    effective_uid: int | None = None,
    environ: Mapping[str, str] | None = None,
    run_process: RunProcess = _run_process,
    readiness_probe: ReadinessProbe = _probe_readiness,
) -> tuple[dict[str, Any], int]:
    system_name = system_name or platform.system()
    machine = machine or platform.machine()
    linux = system_name.lower() == "linux"
    x64 = machine.lower() in {"x86_64", "amd64"}
    if not linux or not x64:
        return _safe_payload("UNSUPPORTED_HOST", linux=linux, x64=x64), 2

    if effective_uid is None:
        effective_uid = os.geteuid() if hasattr(os, "geteuid") else -1
    if effective_uid == 0:
        return _safe_payload("HELPER_MUST_RUN_UNPRIVILEGED"), 2

    runner_dir = runner_dir.expanduser().resolve()
    config_sh = runner_dir / "config.sh"
    if not runner_dir.is_dir() or not config_sh.is_file() or not os.access(config_sh, os.X_OK):
        return _safe_payload("RUNNER_DIR_INVALID"), 2
    if not _SAFE_NAME.fullmatch(runner_name):
        return _safe_payload("RUNNER_NAME_INVALID"), 2

    runner_config = runner_dir / ".runner"
    marker_valid = _load_marker(runner_dir)
    configured_now = False

    if runner_config.exists() and not marker_valid:
        return _safe_payload("EXISTING_CONFIGURATION_UNVERIFIED"), 2

    raw_env = dict(os.environ if environ is None else environ)
    runtime_env = _sanitized_runtime_env(raw_env)

    if not runner_config.exists():
        if not token.strip():
            return _safe_payload("TOKEN_MISSING"), 2
        command = [
            str(config_sh),
            "--unattended",
            "--url",
            REPO_URL,
            "--labels",
            CUSTOM_LABEL,
            "--name",
            runner_name,
            "--work",
            "_work",
        ]
        rc = run_process(command, runner_dir, _child_env(raw_env, token))
        if rc != 0:
            return _safe_payload("CONFIGURATION_FAILED", configuration_return_code=rc), 2
        if not runner_config.exists():
            return _safe_payload("CONFIGURATION_NOT_PERSISTED"), 2
        _write_marker(runner_dir)
        configured_now = True

    if not install_service:
        return _safe_payload(
            "CONFIGURED",
            configuration_performed=configured_now,
            service_install_requested=False,
            service_mutation_performed=False,
        ), 0

    svc_sh = runner_dir / "svc.sh"
    if not svc_sh.is_file() or not os.access(svc_sh, os.X_OK):
        return _safe_payload(
            "SERVICE_SCRIPT_MISSING",
            configuration_performed=configured_now,
            service_install_requested=True,
            service_mutation_performed=False,
        ), 2

    privilege_rc = run_process(["sudo", "-n", "true"], runner_dir, runtime_env)
    if privilege_rc != 0:
        return _safe_payload(
            "SERVICE_PRIVILEGE_REQUIRED",
            configuration_performed=configured_now,
            service_install_requested=True,
            service_mutation_performed=False,
        ), 4

    service_config = runner_dir / ".service"
    installed_now = False
    if not service_config.is_file():
        install_rc = run_process(
            _sudo_svc_command(svc_sh, "install"),
            runner_dir,
            runtime_env,
        )
        if install_rc != 0:
            return _safe_payload(
                "SERVICE_INSTALL_FAILED",
                configuration_performed=configured_now,
                service_install_requested=True,
                service_mutation_performed=True,
                service_install_return_code=install_rc,
            ), 2
        installed_now = True

    start_rc = run_process(
        _sudo_svc_command(svc_sh, "start"),
        runner_dir,
        runtime_env,
    )
    if start_rc != 0:
        return _safe_payload(
            "SERVICE_START_FAILED",
            configuration_performed=configured_now,
            service_install_requested=True,
            service_mutation_performed=True,
            service_start_return_code=start_rc,
        ), 2

    status_rc = run_process(
        _sudo_svc_command(svc_sh, "status"),
        runner_dir,
        runtime_env,
    )
    if status_rc != 0:
        return _safe_payload(
            "SERVICE_STATUS_FAILED",
            configuration_performed=configured_now,
            service_install_requested=True,
            service_mutation_performed=True,
            service_status_return_code=status_rc,
        ), 2

    readiness = dict(readiness_probe())
    ready = readiness.get("status") == "READY"
    return _safe_payload(
        "READY" if ready else "BOOTSTRAPPED_NOT_READY",
        configuration_performed=configured_now,
        service_install_requested=True,
        service_installed_now=installed_now,
        service_mutation_performed=True,
        readiness=readiness,
    ), 0 if ready else 3


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Safely configure an already-downloaded Linux x64 GitHub Actions runner "
            "for the WorkSpace trusted R9 lane."
        )
    )
    parser.add_argument("--runner-dir", required=True, type=Path)
    parser.add_argument("--runner-name", default=DEFAULT_RUNNER_NAME)
    parser.add_argument(
        "--install-service",
        action="store_true",
        help=(
            "Explicitly install/start the runner systemd service via non-interactive sudo. "
            "Run 'sudo -v' first if the current user requires an interactive sudo grant."
        ),
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload, rc = bootstrap_runner(
        runner_dir=args.runner_dir,
        runner_name=args.runner_name,
        install_service=args.install_service,
        token=os.environ.get("ACTIONS_RUNNER_TOKEN", ""),
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
