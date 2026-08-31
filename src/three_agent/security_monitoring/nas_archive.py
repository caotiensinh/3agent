from __future__ import annotations

import hashlib
import os
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo

from .contracts import MonitoringContractError
from .receipts import ArchiveReceipt
from .reporting import ReportBundle

TOKYO = ZoneInfo("Asia/Tokyo")


@dataclass(frozen=True)
class NasArchiveConfig:
    nas_root: Path
    max_files_per_archive: int = 16
    max_bundle_bytes: int = 128 * 1024 * 1024

    def validate(self) -> "NasArchiveConfig":
        root = Path(self.nas_root)
        if not root.is_absolute() or root.is_symlink():
            raise MonitoringContractError("NAS root must be an absolute non-symlink path")
        if not 1 <= self.max_files_per_archive <= 64:
            raise MonitoringContractError("max_files_per_archive must be within 1..64")
        if not 1024 <= self.max_bundle_bytes <= 1024 * 1024 * 1024:
            raise MonitoringContractError("max_bundle_bytes must be within 1KiB..1GiB")
        return self


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def _manifest_entries(bundle_path: Path) -> tuple[tuple[str, str], ...]:
    manifest = bundle_path / "manifest.sha256"
    if not manifest.is_file() or manifest.is_symlink():
        raise MonitoringContractError("report manifest is missing or unsafe")
    entries = []
    for line in manifest.read_text(encoding="ascii").splitlines():
        parts = line.split("  ", 1)
        if len(parts) != 2 or len(parts[0]) != 64:
            raise MonitoringContractError("invalid report manifest entry")
        digest, name = parts
        if any(ch not in "0123456789abcdef" for ch in digest.lower()):
            raise MonitoringContractError("invalid report manifest digest")
        if Path(name).name != name or name.startswith("."):
            raise MonitoringContractError("unsafe report manifest path")
        entries.append((name, "sha256:" + digest.lower()))
    return tuple(entries)


def verify_report_bundle(bundle: ReportBundle, config: NasArchiveConfig) -> tuple[tuple[str, str], ...]:
    config.validate()
    root = Path(bundle.path)
    if not root.is_dir() or root.is_symlink():
        raise MonitoringContractError("report bundle path is missing or unsafe")
    entries = _manifest_entries(root)
    if not entries or len(entries) > config.max_files_per_archive:
        raise MonitoringContractError("report bundle file count exceeds archive policy")
    total_bytes = 0
    for name, expected in entries:
        path = root / name
        if not path.is_file() or path.is_symlink():
            raise MonitoringContractError("report bundle contains missing/unsafe file")
        total_bytes += path.stat().st_size
        if total_bytes > config.max_bundle_bytes:
            raise MonitoringContractError("report bundle exceeds archive byte budget")
        if _sha256_file(path) != expected:
            raise MonitoringContractError("report bundle hash verification failed")
    manifest_digest = _sha256_file(root / "manifest.sha256")
    if manifest_digest != bundle.manifest_sha256:
        raise MonitoringContractError("manifest digest mismatch")
    return entries


def _nas_mount_ready(nas_root: Path) -> bool:
    """Filesystem-only readiness check; never opens a network socket or probes a host."""

    return (
        nas_root.exists()
        and nas_root.is_dir()
        and not nas_root.is_symlink()
        and os.path.ismount(nas_root)
    )


def archive_existing_bundle(
    bundle: ReportBundle,
    *,
    config: NasArchiveConfig,
    period_kind: str,
    period_key: str,
    attempt: int = 1,
) -> ArchiveReceipt:
    """Copy an already-validated local bundle to a pre-mounted NAS path.

    This function never mounts SMB/NFS and never accepts NAS credentials. A missing
    mount becomes PENDING_NAS so the exact existing bundle can be retried later.
    The local bundle is always verified before NAS readiness is considered.
    """

    config.validate()
    entries = verify_report_bundle(bundle, config)
    now = datetime.now(TOKYO).isoformat()
    archive_id = f"archive-{period_kind}-{period_key}-{attempt}"
    nas_root = Path(config.nas_root)
    if not _nas_mount_ready(nas_root):
        return ArchiveReceipt(
            archive_id=archive_id,
            period_kind=period_kind,
            period_key=period_key,
            status="pending_nas",
            bundle_ref=f"spool/{bundle.report_id}",
            manifest_sha256=bundle.manifest_sha256,
            attempt=attempt,
            updated_at=now,
            failure_code="NAS_UNAVAILABLE",
        ).validate()

    period_dir = nas_root / period_kind / period_key
    final = period_dir / bundle.report_id
    temp = period_dir / f".{bundle.report_id}.{os.getpid()}.tmp"
    if final.exists():
        # Idempotent success is allowed only when every archived file still matches.
        if not final.is_dir() or final.is_symlink():
            raise MonitoringContractError("existing NAS archive path is unsafe")
        for name, expected in entries:
            candidate = final / name
            if not candidate.is_file() or candidate.is_symlink() or _sha256_file(candidate) != expected:
                raise MonitoringContractError("existing NAS archive does not match validated bundle")
        if _sha256_file(final / "manifest.sha256") != bundle.manifest_sha256:
            raise MonitoringContractError("existing NAS manifest does not match validated bundle")
        return ArchiveReceipt(
            archive_id=archive_id,
            period_kind=period_kind,
            period_key=period_key,
            status="archived",
            bundle_ref=f"nas/{period_kind}/{period_key}/{bundle.report_id}",
            manifest_sha256=bundle.manifest_sha256,
            attempt=attempt,
            updated_at=now,
        ).validate()

    period_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    if temp.exists():
        shutil.rmtree(temp)
    temp.mkdir(mode=0o750)
    try:
        for name, expected in entries:
            source = bundle.path / name
            destination = temp / name
            shutil.copyfile(source, destination)
            if _sha256_file(destination) != expected:
                raise MonitoringContractError("NAS copied file hash mismatch")
        shutil.copyfile(bundle.path / "manifest.sha256", temp / "manifest.sha256")
        if _sha256_file(temp / "manifest.sha256") != bundle.manifest_sha256:
            raise MonitoringContractError("NAS manifest copy hash mismatch")
        os.replace(temp, final)
    except Exception:
        shutil.rmtree(temp, ignore_errors=True)
        raise

    return ArchiveReceipt(
        archive_id=archive_id,
        period_kind=period_kind,
        period_key=period_key,
        status="archived",
        bundle_ref=f"nas/{period_kind}/{period_key}/{bundle.report_id}",
        manifest_sha256=bundle.manifest_sha256,
        attempt=attempt,
        updated_at=now,
    ).validate()
