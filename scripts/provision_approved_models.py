#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import uuid
from pathlib import Path
from typing import Callable, Iterable

from three_agent.model_artifacts import (
    MANIFEST_SCHEMA,
    ApprovedModelManifest,
    ModelArtifactError,
    ModelManifestError,
    ModelProvisioningError,
    RuntimeModelResolver,
    write_provision_receipt,
)


SnapshotDownloader = Callable[..., str]


class HuggingFaceModelProvisioner:
    """Explicit deployment-only acquisition for approved Hugging Face snapshots.

    This module lives under ``scripts/`` on purpose. Runtime package code has no
    Hub downloader. Network access occurs only when an operator invokes this
    deployment command and only for a model already present in the approved
    manifest.
    """

    def __init__(
        self,
        manifest: ApprovedModelManifest,
        store_root: str | Path,
        *,
        snapshot_downloader: SnapshotDownloader | None = None,
    ):
        self.manifest = manifest
        self.store_root = Path(store_root)
        self._snapshot_downloader = snapshot_downloader

    def _downloader(self) -> SnapshotDownloader:
        if self._snapshot_downloader is not None:
            return self._snapshot_downloader
        try:
            from huggingface_hub import snapshot_download
        except ImportError as exc:
            raise ModelProvisioningError(
                "deployment provisioning requires the optional huggingface_hub package"
            ) from exc
        return snapshot_download

    @staticmethod
    def _remove_hub_metadata(staging: Path) -> None:
        metadata = staging / ".cache" / "huggingface"
        if metadata.exists():
            shutil.rmtree(metadata)
        cache_root = staging / ".cache"
        if cache_root.exists() and not any(cache_root.iterdir()):
            cache_root.rmdir()

    def provision(self, model_id: str, *, token: str | None = None) -> Path:
        model = self.manifest.require(model_id)
        self.store_root.mkdir(parents=True, exist_ok=True)
        staging_parent = self.store_root / ".staging"
        backup_parent = self.store_root / ".backup"
        staging_parent.mkdir(parents=True, exist_ok=True)
        backup_parent.mkdir(parents=True, exist_ok=True)
        staging = staging_parent / f"{model.model_id}-{uuid.uuid4().hex}"
        staging.mkdir(mode=0o700)
        target = self.store_root / model.local_subdir
        backup: Path | None = None

        try:
            downloader = self._downloader()
            result = downloader(
                repo_id=model.repo_id,
                revision=model.revision,
                local_dir=str(staging),
                allow_patterns=[artifact.path for artifact in model.artifacts],
                token=token,
            )
            if result:
                resolved = Path(result).resolve()
                if resolved != staging.resolve():
                    raise ModelProvisioningError(
                        "snapshot downloader returned a path outside the controlled staging directory"
                    )

            self._remove_hub_metadata(staging)
            write_provision_receipt(self.manifest, model, staging)

            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                backup = backup_parent / f"{model.model_id}-{uuid.uuid4().hex}"
                os.replace(target, backup)
            try:
                os.replace(staging, target)
            except Exception:
                if backup is not None and backup.exists() and not target.exists():
                    os.replace(backup, target)
                raise
            if backup is not None and backup.exists():
                shutil.rmtree(backup)
            return target
        except ModelArtifactError:
            raise
        except Exception as exc:
            raise ModelProvisioningError(
                f"failed to provision {model.model_id}: {exc}"
            ) from exc
        finally:
            if staging.exists():
                shutil.rmtree(staging, ignore_errors=True)

    def verify_installed(self, model_id: str) -> Path:
        return RuntimeModelResolver(self.manifest, self.store_root).resolve(model_id)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Provision manifest-approved local Hugging Face model artifacts"
    )
    parser.add_argument("--manifest", required=True, help="Approved model manifest JSON")
    parser.add_argument("--store", required=True, help="Local model store root")
    parser.add_argument(
        "--model",
        action="append",
        default=[],
        help="Approved model id to operate on; repeat for multiple models",
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate manifest without importing a network-capable dependency",
    )
    parser.add_argument(
        "--verify-installed",
        action="store_true",
        help="Verify local receipt and artifact integrity without network access",
    )
    parser.add_argument(
        "--token-env",
        default="HF_TOKEN",
        help="Environment variable containing a deployment-only Hugging Face token",
    )
    return parser


def main(argv: Iterable[str] | None = None) -> int:
    args = _build_parser().parse_args(list(argv) if argv is not None else None)
    manifest = ApprovedModelManifest.load(args.manifest)

    if args.validate_only:
        print(
            json.dumps(
                {
                    "status": "valid",
                    "schema": MANIFEST_SCHEMA,
                    "models": len(manifest.models),
                    "manifest_sha256": manifest.manifest_digest,
                    "runtime_download": False,
                },
                sort_keys=True,
            )
        )
        return 0

    model_ids = args.model or [model.model_id for model in manifest.models]
    if not model_ids:
        raise ModelManifestError("manifest contains no approved models to operate on")

    if args.verify_installed:
        resolver = RuntimeModelResolver(manifest, args.store)
        for model_id in model_ids:
            print(f"VERIFIED {model_id} {resolver.resolve(model_id)}")
        return 0

    token = os.getenv(args.token_env) if args.token_env else None
    provisioner = HuggingFaceModelProvisioner(manifest, args.store)
    for model_id in model_ids:
        print(f"PROVISIONED {model_id} {provisioner.provision(model_id, token=token)}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ModelArtifactError as exc:
        print(f"[workspace-model-provision][ERROR] {exc}", file=sys.stderr)
        raise SystemExit(2)
