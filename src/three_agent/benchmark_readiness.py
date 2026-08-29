from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

READINESS_SCHEMA = "workspace-benchmark-readiness/v1"
_REQUIRED_GPU_SUBSTRING = "RTX 5090"
_MIN_MATCHING_GPUS = 2
_SOURCE_REF_RE = re.compile(r"^[0-9a-f]{40}$")
_MODEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+\-]{0,127}$")
_REASON_RE = re.compile(r"^[A-Z0-9][A-Z0-9_]{0,95}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class BenchmarkReadinessError(ValueError):
    """Benchmark environment evidence is invalid or cannot be trusted."""


CommandRunner = Callable[[tuple[str, ...], Path], str]
Clock = Callable[[], datetime]


def _canonical_sha256(payload: Any) -> str:
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _default_runner(argv: tuple[str, ...], cwd: Path) -> str:
    completed = subprocess.run(
        list(argv),
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return completed.stdout


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _compact_model(value: str) -> str:
    model = str(value or "").strip()
    if not _MODEL_RE.fullmatch(model):
        raise BenchmarkReadinessError("model must be a compact local model identifier")
    return model


def _source_ref(value: str) -> str:
    source = str(value or "").strip().lower()
    if not _SOURCE_REF_RE.fullmatch(source):
        raise BenchmarkReadinessError("source_ref must be an exact 40-hex Git commit SHA")
    return source


def _normalize_display(value: str, *, max_len: int = 160) -> str:
    text = " ".join(str(value or "").split())
    if not text or len(text) > max_len or any(ord(ch) < 32 for ch in text):
        raise BenchmarkReadinessError("runtime metadata contains an invalid display value")
    return text


def _parse_gpu_rows(raw: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in str(raw or "").splitlines():
        if not line.strip():
            continue
        parts = [part.strip() for part in line.split(",")]
        if len(parts) != 3:
            raise BenchmarkReadinessError("nvidia-smi GPU query returned an unexpected row shape")
        name = _normalize_display(parts[0])
        driver = _normalize_display(parts[1], max_len=64)
        try:
            memory_mib = int(parts[2])
        except ValueError as exc:
            raise BenchmarkReadinessError("nvidia-smi GPU memory value is not an integer") from exc
        if memory_mib <= 0:
            raise BenchmarkReadinessError("nvidia-smi GPU memory value must be positive")
        rows.append(
            {
                "name": name,
                "driver_version": driver,
                "memory_total_mib": memory_mib,
            }
        )
    if not rows:
        raise BenchmarkReadinessError("nvidia-smi GPU query returned no GPUs")
    return rows


class BenchmarkReadinessProbe:
    """Collect metadata-only evidence that the fixed RTX5090 benchmark can run.

    This probe never installs a model, driver or dependency. It also intentionally
    excludes hostnames, usernames, IP addresses, GPU UUID/serial identifiers and
    the raw output of ``ollama show`` from the receipt.
    """

    def __init__(
        self,
        repo_root: Path,
        *,
        runner: CommandRunner | None = None,
        clock: Clock | None = None,
    ):
        self.repo_root = Path(repo_root).expanduser().resolve()
        self.runner = runner or _default_runner
        self.clock = clock or _utc_now

    def _try(self, argv: tuple[str, ...], failure_code: str) -> tuple[str | None, str | None]:
        try:
            return self.runner(argv, self.repo_root), None
        except (OSError, subprocess.SubprocessError):
            return None, failure_code

    def collect(self, *, source_ref: str, model: str) -> dict[str, Any]:
        source = _source_ref(source_ref)
        model_id = _compact_model(model)
        failures: list[str] = []

        head_raw, head_error = self._try(("git", "rev-parse", "HEAD"), "GIT_HEAD_UNAVAILABLE")
        head = str(head_raw or "").strip().lower()
        exact_source = head_error is None and head == source
        if head_error:
            failures.append(head_error)
        elif not exact_source:
            failures.append("SOURCE_REF_MISMATCH")

        status_raw, status_error = self._try(
            ("git", "status", "--porcelain", "--untracked-files=no"),
            "GIT_STATUS_UNAVAILABLE",
        )
        clean_checkout = status_error is None and not str(status_raw or "").strip()
        if status_error:
            failures.append(status_error)
        elif not clean_checkout:
            failures.append("TRACKED_WORKTREE_DIRTY")

        gpu_raw, gpu_error = self._try(
            (
                "nvidia-smi",
                "--query-gpu=name,driver_version,memory.total",
                "--format=csv,noheader,nounits",
            ),
            "NVIDIA_SMI_UNAVAILABLE",
        )
        gpus: list[dict[str, Any]] = []
        if gpu_error:
            failures.append(gpu_error)
        else:
            try:
                gpus = _parse_gpu_rows(str(gpu_raw or ""))
            except BenchmarkReadinessError:
                failures.append("NVIDIA_SMI_QUERY_INVALID")

        matching = [
            gpu for gpu in gpus if _REQUIRED_GPU_SUBSTRING.casefold() in str(gpu["name"]).casefold()
        ]
        enough_matching = len(matching) >= _MIN_MATCHING_GPUS
        if gpus and not enough_matching:
            failures.append("DUAL_RTX5090_REQUIRED")
        driver_versions = {str(gpu["driver_version"]) for gpu in matching}
        uniform_driver = bool(matching) and len(driver_versions) == 1
        if enough_matching and not uniform_driver:
            failures.append("GPU_DRIVER_VERSION_MISMATCH")

        ollama_version_raw, ollama_version_error = self._try(
            ("ollama", "--version"),
            "OLLAMA_UNAVAILABLE",
        )
        ollama_version = ""
        if ollama_version_error:
            failures.append(ollama_version_error)
        else:
            try:
                ollama_version = _normalize_display(str(ollama_version_raw or ""), max_len=160)
            except BenchmarkReadinessError:
                failures.append("OLLAMA_VERSION_INVALID")

        _, model_error = self._try(("ollama", "show", model_id), "OLLAMA_MODEL_NOT_AVAILABLE")
        model_available = model_error is None
        if model_error:
            failures.append(model_error)

        failures = list(dict.fromkeys(failures))
        environment = {
            "gpu_count": len(gpus),
            "matching_rtx5090_count": len(matching),
            "gpus": gpus,
            "ollama_version": ollama_version,
            "model": model_id,
            "model_preinstalled": model_available,
        }
        environment_sha = _canonical_sha256(environment)
        checks = {
            "exact_source_ref": exact_source,
            "clean_tracked_checkout": clean_checkout,
            "nvidia_smi_available": gpu_error is None,
            "dual_rtx5090_available": enough_matching,
            "uniform_matching_gpu_driver": uniform_driver,
            "ollama_available": ollama_version_error is None,
            "model_preinstalled": model_available,
        }
        ready = not failures and all(checks.values())
        captured = self.clock().astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
        payload: dict[str, Any] = {
            "schema_version": READINESS_SCHEMA,
            "source_ref": source,
            "captured_at_utc": captured,
            "ready": ready,
            "required_hardware": {
                "gpu_name_contains": _REQUIRED_GPU_SUBSTRING,
                "min_matching_gpus": _MIN_MATCHING_GPUS,
            },
            "checks": checks,
            "failures": failures,
            "environment": environment,
            "environment_sha256": environment_sha,
            "privacy": {
                "hostname_recorded": False,
                "username_recorded": False,
                "ip_address_recorded": False,
                "gpu_uuid_or_serial_recorded": False,
                "raw_ollama_show_recorded": False,
            },
        }
        payload["receipt_sha256"] = _canonical_sha256(payload)
        return payload


def validate_readiness_receipt(
    payload: Any,
    *,
    expected_source_ref: str | None = None,
    require_ready: bool = True,
) -> dict[str, Any]:
    if not isinstance(payload, dict) or payload.get("schema_version") != READINESS_SCHEMA:
        raise BenchmarkReadinessError(f"readiness schema must be {READINESS_SCHEMA}")
    required_keys = {
        "schema_version",
        "source_ref",
        "captured_at_utc",
        "ready",
        "required_hardware",
        "checks",
        "failures",
        "environment",
        "environment_sha256",
        "privacy",
        "receipt_sha256",
    }
    if set(payload) != required_keys:
        raise BenchmarkReadinessError("readiness receipt contains unsupported or missing fields")

    source = _source_ref(payload.get("source_ref"))
    if expected_source_ref is not None and source != _source_ref(expected_source_ref):
        raise BenchmarkReadinessError("readiness source_ref does not match benchmark source_ref")
    if not isinstance(payload.get("ready"), bool):
        raise BenchmarkReadinessError("readiness ready flag must be boolean")
    checks = payload.get("checks")
    if not isinstance(checks, dict) or not checks or not all(isinstance(v, bool) for v in checks.values()):
        raise BenchmarkReadinessError("readiness checks must be a non-empty boolean object")
    failures = payload.get("failures")
    if not isinstance(failures, list) or any(not _REASON_RE.fullmatch(str(v or "")) for v in failures):
        raise BenchmarkReadinessError("readiness failures must contain compact reason codes")
    environment = payload.get("environment")
    if not isinstance(environment, dict):
        raise BenchmarkReadinessError("readiness environment must be an object")
    expected_environment_sha = _canonical_sha256(environment)
    if payload.get("environment_sha256") != expected_environment_sha:
        raise BenchmarkReadinessError("readiness environment fingerprint mismatch")
    receipt_claim = str(payload.get("receipt_sha256") or "").lower()
    if not _SHA256_RE.fullmatch(receipt_claim):
        raise BenchmarkReadinessError("readiness receipt_sha256 is invalid")
    unsigned = dict(payload)
    unsigned.pop("receipt_sha256", None)
    if _canonical_sha256(unsigned) != receipt_claim:
        raise BenchmarkReadinessError("readiness receipt fingerprint mismatch")

    privacy = payload.get("privacy")
    if not isinstance(privacy, dict) or not privacy or any(value is not False for value in privacy.values()):
        raise BenchmarkReadinessError("readiness privacy boundary is invalid")
    if require_ready and payload["ready"] is not True:
        raise BenchmarkReadinessError("benchmark environment is not ready")
    return payload


def load_readiness_receipt(
    path: Path,
    *,
    expected_source_ref: str | None = None,
    require_ready: bool = True,
) -> dict[str, Any]:
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    return validate_readiness_receipt(
        payload,
        expected_source_ref=expected_source_ref,
        require_ready=require_ready,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="workspace-benchmark-readiness",
        description="Create a metadata-only dual-RTX5090 benchmark environment receipt.",
    )
    parser.add_argument("--source-ref", required=True, help="Exact 40-hex Git SHA")
    parser.add_argument("--model", required=True, help="Preinstalled local Ollama model ID")
    parser.add_argument("--repo-root", default=".", help="Exact benchmark Git checkout root")
    parser.add_argument("--output", required=True, help="Receipt JSON output path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output = Path(args.output)
    try:
        receipt = BenchmarkReadinessProbe(Path(args.repo_root)).collect(
            source_ref=args.source_ref,
            model=args.model,
        )
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except (OSError, json.JSONDecodeError, BenchmarkReadinessError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": READINESS_SCHEMA,
                    "ready": False,
                    "error": f"{type(exc).__name__}: {exc}",
                },
                ensure_ascii=False,
                indent=2,
            )
        )
        return 3
    print(json.dumps(receipt, ensure_ascii=False, indent=2))
    return 0 if receipt["ready"] else 3


if __name__ == "__main__":
    raise SystemExit(main())
