#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

SCHEMA = "workspace-ci/self-hosted-r9-installer-v1"
REPO = "caotiensinh/3agent"
REPO_URL = f"https://github.com/{REPO}"
RUNNER_RELEASE_API = "repos/actions/runner/releases/latest"
DEFAULT_RUNNER_DIR = Path.home() / ".local" / "share" / "workspace" / "actions-runner"
MANAGED_MARKER = ".workspace-r9-bootstrap.json"
MANAGED_MARKER_SCHEMA = "workspace-ci/self-hosted-runner-bootstrap-marker-v1"
PACKAGE_MARKER = ".workspace-r9-package.json"
PACKAGE_MARKER_SCHEMA = "workspace-ci/self-hosted-runner-package-v1"
RUNNER_ASSET_PREFIX = "actions-runner-linux-x64-"
RUNNER_ASSET_SUFFIX = ".tar.gz"
BASE_CUSTOM_LABELS = ("r9",)
RTX5090_LABEL = "rtx5090"

CommandRunner = Callable[[Sequence[str], Mapping[str, str] | None, bool], subprocess.CompletedProcess[str]]


def _run_command(
    argv: Sequence[str],
    env: Mapping[str, str] | None = None,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        list(argv),
        env=None if env is None else dict(env),
        check=False,
        text=True,
        capture_output=capture_output,
        timeout=180,
    )


def _safe_payload(status: str, **extra: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "repository_url": REPO_URL,
        "required_r9_labels": ["self-hosted", "Linux", "X64", "r9"],
        "registration_token_logged": False,
        "registration_token_persisted": False,
        "host_identity_included": False,
        "runner_path_included": False,
        "driver_mutation_executed": False,
        "network_policy_mutation_executed": False,
        "application_mutation_executed": False,
        "runner_metadata_mutation_scope": "custom_labels_only",
    }
    payload.update(extra)
    return payload


def _gh_env(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    env = dict(os.environ if environ is None else environ)
    for key in (
        "GH_DEBUG",
        "GH_TRACE",
        "ACTIONS_STEP_DEBUG",
        "ACTIONS_RUNNER_DEBUG",
        "ACTIONS_RUNNER_TOKEN",
        "ACTIONS_RUNNER_INPUT_TOKEN",
    ):
        env.pop(key, None)
    return env


def _gh_json(
    args: Sequence[str],
    *,
    command_runner: CommandRunner = _run_command,
    environ: Mapping[str, str] | None = None,
) -> Any:
    completed = command_runner(
        ["gh", "api", "-H", "Accept: application/vnd.github+json", "-H", "X-GitHub-Api-Version: 2022-11-28", *args],
        _gh_env(environ),
        True,
    )
    if completed.returncode != 0:
        raise RuntimeError("gh api request failed")
    try:
        return json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError("gh api returned invalid JSON") from exc


def _select_linux_x64_asset(release: Mapping[str, Any]) -> dict[str, str]:
    tag = release.get("tag_name")
    if not isinstance(tag, str) or not tag.startswith("v"):
        raise ValueError("invalid release tag")
    version = tag[1:]
    expected_name = f"{RUNNER_ASSET_PREFIX}{version}{RUNNER_ASSET_SUFFIX}"
    assets = release.get("assets")
    if not isinstance(assets, list):
        raise ValueError("release assets missing")
    matches = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == expected_name]
    if len(matches) != 1:
        raise ValueError("runner asset missing or ambiguous")
    asset = matches[0]
    url = asset.get("browser_download_url")
    digest = asset.get("digest")
    if not isinstance(url, str) or not url.startswith("https://github.com/actions/runner/releases/download/"):
        raise ValueError("runner asset URL is not official")
    if not isinstance(digest, str) or not digest.startswith("sha256:"):
        raise ValueError("runner asset digest missing")
    hexdigest = digest.split(":", 1)[1].lower()
    if len(hexdigest) != 64 or any(ch not in "0123456789abcdef" for ch in hexdigest):
        raise ValueError("runner asset digest invalid")
    return {"version": version, "name": expected_name, "url": url, "sha256": hexdigest}


def _download(url: str, destination: Path, *, timeout: int = 120) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": "WorkSpace-R9-Runner-Installer/1"})
    with urllib.request.urlopen(request, timeout=timeout) as response, destination.open("wb") as output:
        shutil.copyfileobj(response, output)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_extract_runner_archive(archive: Path, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    root = destination.resolve()
    with tarfile.open(archive, mode="r:gz") as bundle:
        members = bundle.getmembers()
        if not members:
            raise ValueError("empty runner archive")
        for member in members:
            member_path = Path(member.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError("unsafe runner archive path")
            target = (destination / member_path).resolve()
            if root != target and root not in target.parents:
                raise ValueError("unsafe runner archive target")
            if not (member.isdir() or member.isreg()):
                raise ValueError("unsupported runner archive member")
        for member in members:
            target = destination / member.name
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                target.chmod(member.mode & 0o777)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            source = bundle.extractfile(member)
            if source is None:
                raise ValueError("runner archive member unreadable")
            with source, target.open("wb") as output:
                shutil.copyfileobj(source, output)
            target.chmod(member.mode & 0o777)


def _managed_marker_valid(runner_dir: Path) -> bool:
    try:
        marker = json.loads((runner_dir / MANAGED_MARKER).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return (
        isinstance(marker, dict)
        and marker.get("schema") == MANAGED_MARKER_SCHEMA
        and marker.get("repository_url") == REPO_URL
        and marker.get("custom_label") == "r9"
    )


def _write_package_marker(runner_dir: Path, asset: Mapping[str, str]) -> None:
    payload = {
        "schema": PACKAGE_MARKER_SCHEMA,
        "source_repository": "actions/runner",
        "version": asset["version"],
        "asset_name": asset["name"],
        "asset_sha256": asset["sha256"],
        "digest_verified": True,
        "contains_secret": False,
    }
    path = runner_dir / PACKAGE_MARKER
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(path)


def _package_marker_valid(runner_dir: Path) -> bool:
    try:
        marker = json.loads((runner_dir / PACKAGE_MARKER).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    digest = marker.get("asset_sha256") if isinstance(marker, dict) else None
    return (
        isinstance(marker, dict)
        and marker.get("schema") == PACKAGE_MARKER_SCHEMA
        and marker.get("source_repository") == "actions/runner"
        and marker.get("digest_verified") is True
        and isinstance(digest, str)
        and len(digest) == 64
        and all(ch in "0123456789abcdef" for ch in digest.lower())
    )


def _load_managed_runner_id(runner_dir: Path) -> int:
    if not _managed_marker_valid(runner_dir):
        raise ValueError("managed runner marker invalid")
    try:
        runner = json.loads((runner_dir / ".runner").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("managed runner metadata unavailable") from exc
    runner_id = runner.get("agentId") if isinstance(runner, dict) else None
    if not isinstance(runner_id, int) or runner_id <= 0:
        raise ValueError("runner id invalid")
    return runner_id


def _count_rtx5090(
    *,
    command_runner: CommandRunner = _run_command,
    environ: Mapping[str, str] | None = None,
) -> int:
    if shutil.which("nvidia-smi") is None:
        return 0
    completed = command_runner(
        ["nvidia-smi", "--query-gpu=name", "--format=csv,noheader"],
        _gh_env(environ),
        True,
    )
    if completed.returncode != 0:
        return 0
    return sum(1 for line in completed.stdout.splitlines() if "RTX 5090" in line)


def _desired_custom_labels(rtx5090_count: int) -> list[str]:
    labels = list(BASE_CUSTOM_LABELS)
    if rtx5090_count >= 2:
        labels.append(RTX5090_LABEL)
    return labels


def _sync_runner_labels_live(
    runner_id: int,
    labels: Sequence[str],
    *,
    environ: Mapping[str, str] | None = None,
) -> None:
    payload = json.dumps({"labels": list(labels)}, separators=(",", ":"))
    completed = subprocess.run(
        [
            "gh", "api", "--method", "POST",
            "-H", "Accept: application/vnd.github+json",
            "-H", "X-GitHub-Api-Version: 2022-11-28",
            f"repos/{REPO}/actions/runners/{runner_id}/labels",
            "--input", "-",
        ],
        input=payload,
        env=_gh_env(environ),
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise RuntimeError("runner label sync failed")


def _verify_server_runner(
    runner_id: int,
    required_custom_labels: Sequence[str],
    *,
    command_runner: CommandRunner = _run_command,
    environ: Mapping[str, str] | None = None,
) -> bool:
    payload = _gh_json(
        [f"repos/{REPO}/actions/runners/{runner_id}"],
        command_runner=command_runner,
        environ=environ,
    )
    if not isinstance(payload, dict) or payload.get("status") != "online":
        return False
    labels = payload.get("labels")
    if not isinstance(labels, list):
        return False
    names = {
        label.get("name")
        for label in labels
        if isinstance(label, dict) and isinstance(label.get("name"), str)
    }
    return all(label in names for label in required_custom_labels)


def _registration_token(
    *,
    command_runner: CommandRunner = _run_command,
    environ: Mapping[str, str] | None = None,
) -> str:
    payload = _gh_json(
        ["--method", "POST", f"repos/{REPO}/actions/runners/registration-token"],
        command_runner=command_runner,
        environ=environ,
    )
    token = payload.get("token") if isinstance(payload, dict) else None
    if not isinstance(token, str) or not token.strip():
        raise RuntimeError("registration token missing")
    return token


def _load_bootstrap_module() -> Any:
    path = Path(__file__).with_name("configure_self_hosted_runner.py")
    spec = importlib.util.spec_from_file_location("configure_self_hosted_runner", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("runner bootstrap module unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _prepare_runner_package(
    runner_dir: Path,
    *,
    command_runner: CommandRunner = _run_command,
    environ: Mapping[str, str] | None = None,
) -> tuple[bool, bool, str]:
    if (runner_dir / "config.sh").is_file():
        if _package_marker_valid(runner_dir):
            marker = json.loads((runner_dir / PACKAGE_MARKER).read_text(encoding="utf-8"))
            return False, True, str(marker.get("version", "existing-verified"))
        if _managed_marker_valid(runner_dir):
            return False, False, "existing-managed"
        raise FileExistsError("existing runner package is unverified")
    if runner_dir.exists() and any(runner_dir.iterdir()):
        raise FileExistsError("runner directory is not empty")

    release = _gh_json([RUNNER_RELEASE_API], command_runner=command_runner, environ=environ)
    if not isinstance(release, dict):
        raise ValueError("runner release invalid")
    asset = _select_linux_x64_asset(release)
    runner_dir.mkdir(parents=True, exist_ok=True)
    try:
        with tempfile.TemporaryDirectory(prefix="workspace-r9-runner-") as tmp:
            archive = Path(tmp) / asset["name"]
            _download(asset["url"], archive)
            if _sha256(archive) != asset["sha256"]:
                raise RuntimeError("runner digest mismatch")
            _safe_extract_runner_archive(archive, runner_dir)
        if not (runner_dir / "config.sh").is_file():
            raise RuntimeError("runner package incomplete")
        _write_package_marker(runner_dir, asset)
    except Exception:
        if not _managed_marker_valid(runner_dir):
            shutil.rmtree(runner_dir, ignore_errors=True)
        raise
    return True, True, asset["version"]


def install_runner(
    *,
    runner_dir: Path,
    runner_name: str,
    system_name: str | None = None,
    machine: str | None = None,
    effective_uid: int | None = None,
    environ: Mapping[str, str] | None = None,
    command_runner: CommandRunner = _run_command,
    bootstrap_module: Any | None = None,
    label_sync: Callable[[int, Sequence[str]], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> tuple[dict[str, Any], int]:
    system_name = system_name or platform.system()
    machine = machine or platform.machine()
    if system_name.lower() != "linux" or machine.lower() not in {"x86_64", "amd64"}:
        return _safe_payload("UNSUPPORTED_HOST"), 2

    if effective_uid is None:
        effective_uid = os.geteuid() if hasattr(os, "geteuid") else -1
    if effective_uid == 0:
        return _safe_payload("HELPER_MUST_RUN_UNPRIVILEGED"), 2

    if shutil.which("gh") is None:
        return _safe_payload("GH_CLI_MISSING"), 2

    auth = command_runner(["gh", "auth", "status"], _gh_env(environ), True)
    if auth.returncode != 0:
        return _safe_payload("GH_AUTH_REQUIRED"), 2

    sudo = command_runner(["sudo", "-v"], _gh_env(environ), False)
    if sudo.returncode != 0:
        return _safe_payload("SUDO_AUTH_REQUIRED"), 4

    try:
        package_downloaded, asset_digest_verified, version = _prepare_runner_package(
            runner_dir,
            command_runner=command_runner,
            environ=environ,
        )
    except FileExistsError:
        return _safe_payload("RUNNER_DIR_CONFLICT"), 2
    except ValueError:
        return _safe_payload("RUNNER_RELEASE_INVALID"), 2
    except (urllib.error.URLError, TimeoutError):
        return _safe_payload("RUNNER_DOWNLOAD_FAILED"), 2
    except (tarfile.TarError, OSError):
        return _safe_payload("RUNNER_PACKAGE_FAILED"), 2
    except RuntimeError as exc:
        status = "RUNNER_DIGEST_MISMATCH" if "digest mismatch" in str(exc) else "RUNNER_PACKAGE_FAILED"
        return _safe_payload(status), 2

    token = ""
    if not (runner_dir / ".runner").is_file():
        try:
            token = _registration_token(command_runner=command_runner, environ=environ)
        except RuntimeError:
            return _safe_payload(
                "REGISTRATION_TOKEN_FAILED",
                package_downloaded=package_downloaded,
                asset_digest_verified=asset_digest_verified,
                runner_version=version,
            ), 2

    bootstrap_module = bootstrap_module or _load_bootstrap_module()
    try:
        bootstrap_payload, bootstrap_rc = bootstrap_module.bootstrap_runner(
            runner_dir=runner_dir,
            token=token,
            runner_name=runner_name,
            install_service=True,
            environ=_gh_env(environ),
        )
    except Exception:
        token = ""
        return _safe_payload(
            "CONFIGURATION_FAILED",
            package_downloaded=package_downloaded,
            asset_digest_verified=asset_digest_verified,
            runner_version=version,
            bootstrap_status="EXCEPTION",
        ), 3
    finally:
        token = ""

    if bootstrap_rc != 0 or bootstrap_payload.get("status") != "READY":
        return _safe_payload(
            "CONFIGURATION_FAILED",
            package_downloaded=package_downloaded,
            asset_digest_verified=asset_digest_verified,
            runner_version=version,
            bootstrap_status=str(bootstrap_payload.get("status", "UNKNOWN")),
        ), 3

    try:
        runner_id = _load_managed_runner_id(runner_dir)
    except ValueError:
        return _safe_payload(
            "MANAGED_RUNNER_ID_INVALID",
            package_downloaded=package_downloaded,
            asset_digest_verified=asset_digest_verified,
            runner_version=version,
        ), 3

    rtx5090_count = _count_rtx5090(command_runner=command_runner, environ=environ)
    desired_labels = _desired_custom_labels(rtx5090_count)
    try:
        if label_sync is None:
            _sync_runner_labels_live(runner_id, desired_labels, environ=environ)
        else:
            label_sync(runner_id, desired_labels)
    except (RuntimeError, OSError, subprocess.TimeoutExpired):
        return _safe_payload(
            "LABEL_SYNC_FAILED",
            package_downloaded=package_downloaded,
            asset_digest_verified=asset_digest_verified,
            runner_version=version,
            rtx5090_count=rtx5090_count,
            desired_custom_labels=desired_labels,
        ), 3

    server_verified = False
    for _ in range(6):
        try:
            if _verify_server_runner(
                runner_id,
                desired_labels,
                command_runner=command_runner,
                environ=environ,
            ):
                server_verified = True
                break
        except (RuntimeError, OSError, subprocess.TimeoutExpired):
            pass
        sleep(2.0)

    if not server_verified:
        return _safe_payload(
            "SERVER_VERIFICATION_FAILED",
            package_downloaded=package_downloaded,
            asset_digest_verified=asset_digest_verified,
            runner_version=version,
            rtx5090_count=rtx5090_count,
            desired_custom_labels=desired_labels,
        ), 3

    return _safe_payload(
        "READY",
        package_downloaded=package_downloaded,
        asset_digest_verified=asset_digest_verified,
        runner_version=version,
        rtx5090_count=rtx5090_count,
        desired_custom_labels=desired_labels,
        server_registration_verified=True,
        local_readiness_verified=True,
        runner_label_sync_executed=True,
    ), 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "One-command, fail-closed installer for the WorkSpace trusted R9 GitHub Actions runner. "
            "Requires an authenticated gh CLI and never prints or persists the registration token."
        )
    )
    parser.add_argument("--runner-dir", type=Path, default=DEFAULT_RUNNER_DIR)
    parser.add_argument("--runner-name", default="workspace-r9")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    payload, rc = install_runner(
        runner_dir=args.runner_dir.expanduser().resolve(),
        runner_name=args.runner_name,
    )
    print(json.dumps(payload, indent=2, sort_keys=True))
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
