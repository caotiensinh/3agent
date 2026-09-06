#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Sequence


CANDIDATE_SCHEMA = "workspace.model-candidate-evidence/v1"
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_REPO_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:/")
SnapshotDownloader = Callable[..., str]


class CandidateAuditError(RuntimeError):
    """Candidate evidence cannot be produced safely or deterministically."""


def _safe_artifact_path(value: str) -> str:
    raw = str(value).strip().replace("\\", "/")
    path = Path(raw)
    if (
        not raw
        or "\x00" in raw
        or raw.startswith(("/", "~"))
        or _WINDOWS_DRIVE_RE.match(raw)
        or ":" in raw
        or path.is_absolute()
    ):
        raise CandidateAuditError(f"unsafe artifact path: {raw or '<empty>'}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise CandidateAuditError(f"unsafe artifact path: {raw}")
    normalized = Path(*path.parts).as_posix()
    if normalized != raw:
        raise CandidateAuditError(f"artifact path must be normalized: {raw}")
    return normalized


def _validate_source(repo_id: str, revision: str) -> tuple[str, str]:
    repo = str(repo_id).strip()
    rev = str(revision).strip().lower()
    if not _REPO_ID_RE.fullmatch(repo):
        raise CandidateAuditError("repo_id must be a canonical owner/name identifier")
    if not _HEX40_RE.fullmatch(rev):
        raise CandidateAuditError("revision must be an exact 40-character commit hash")
    return repo, rev


def _sha256(path: Path, *, chunk_size: int = 4 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _remove_hub_metadata(root: Path) -> None:
    metadata = root / ".cache" / "huggingface"
    if metadata.exists():
        shutil.rmtree(metadata)
    cache_root = root / ".cache"
    if cache_root.exists() and not any(cache_root.iterdir()):
        cache_root.rmdir()


def _assert_exact_regular_file_set(root: Path, expected: set[str]) -> None:
    actual: set[str] = set()
    root_resolved = root.resolve()
    for path in root.rglob("*"):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            raise CandidateAuditError(f"symlinked candidate content is forbidden: {relative}")
        if not path.is_file():
            continue
        resolved = path.resolve()
        try:
            resolved.relative_to(root_resolved)
        except ValueError as exc:
            raise CandidateAuditError(f"candidate file escaped staging root: {relative}") from exc
        actual.add(relative)
    unexpected = sorted(actual - expected)
    missing = sorted(expected - actual)
    if unexpected:
        raise CandidateAuditError(
            "downloaded candidate contains unrequested files: " + ", ".join(unexpected)
        )
    if missing:
        raise CandidateAuditError(
            "downloaded candidate is missing requested files: " + ", ".join(missing)
        )


def _default_downloader() -> SnapshotDownloader:
    try:
        from huggingface_hub import snapshot_download
    except ImportError as exc:
        raise CandidateAuditError(
            "candidate audit requires the optional model-provisioning dependency"
        ) from exc
    return snapshot_download


def audit_candidate(
    *,
    repo_id: str,
    revision: str,
    artifacts: Sequence[str],
    token: str | None = None,
    downloader: SnapshotDownloader | None = None,
    staging_parent: str | Path | None = None,
) -> dict[str, Any]:
    """Download an explicit immutable candidate set and return hash evidence.

    This function produces evidence only. It never edits the approved manifest,
    installs a runtime model, or grants model authority.
    """

    repo, rev = _validate_source(repo_id, revision)
    normalized = tuple(_safe_artifact_path(item) for item in artifacts)
    if not normalized:
        raise CandidateAuditError("at least one explicit artifact path is required")
    if len(normalized) != len(set(normalized)):
        raise CandidateAuditError("artifact allowlist contains duplicates")

    parent = Path(staging_parent) if staging_parent is not None else None
    if parent is not None:
        parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="workspace-hf-audit-", dir=parent) as tmp:
        staging = Path(tmp)
        source = downloader or _default_downloader()
        try:
            result = source(
                repo_id=repo,
                revision=rev,
                local_dir=str(staging),
                allow_patterns=list(normalized),
                token=token,
            )
        except CandidateAuditError:
            raise
        except Exception as exc:
            raise CandidateAuditError(f"candidate download failed: {exc}") from exc

        if result:
            returned = Path(result).resolve()
            if returned != staging.resolve():
                raise CandidateAuditError(
                    "snapshot downloader returned a path outside controlled staging"
                )

        _remove_hub_metadata(staging)
        expected = set(normalized)
        _assert_exact_regular_file_set(staging, expected)

        evidence = []
        for relative in sorted(normalized):
            path = staging / relative
            evidence.append(
                {
                    "path": relative,
                    "sha256": _sha256(path),
                    "size_bytes": path.stat().st_size,
                }
            )

    return {
        "schema": CANDIDATE_SCHEMA,
        "status": "candidate_only",
        "source": "huggingface",
        "repo_id": repo,
        "revision": rev,
        "runtime_download": False,
        "artifacts": evidence,
        "audited_at": datetime.now(timezone.utc).isoformat(),
        "approval": {
            "approved": False,
            "reason": "candidate evidence requires human/license/runtime review before manifest admission",
        },
    }


def _read_artifact_file(path: str | Path) -> list[str]:
    source = Path(path)
    try:
        lines = source.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise CandidateAuditError(f"cannot read artifact list: {source}: {exc}") from exc
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Audit an immutable Hugging Face model candidate without approving it"
    )
    parser.add_argument("--repo-id", required=True, help="Canonical Hugging Face owner/name")
    parser.add_argument("--revision", required=True, help="Exact 40-character Hub commit hash")
    parser.add_argument(
        "--artifact",
        action="append",
        default=[],
        help="Exact candidate artifact path; repeat for every required runtime file",
    )
    parser.add_argument(
        "--artifact-file",
        help="UTF-8 file containing one exact artifact path per line",
    )
    parser.add_argument(
        "--token-env",
        default="HF_TOKEN",
        help="Environment variable holding a deployment/review-only Hugging Face token",
    )
    parser.add_argument("--output", help="Optional JSON evidence output path")
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _build_parser().parse_args(list(argv) if argv is not None else None)
    artifacts = list(args.artifact)
    if args.artifact_file:
        artifacts.extend(_read_artifact_file(args.artifact_file))
    token = os.getenv(args.token_env) if args.token_env else None
    payload = audit_candidate(
        repo_id=args.repo_id,
        revision=args.revision,
        artifacts=artifacts,
        token=token,
    )
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    if args.output:
        destination = Path(args.output)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CandidateAuditError as exc:
        print(f"[workspace-model-candidate-audit][ERROR] {exc}", file=sys.stderr)
        raise SystemExit(2)
