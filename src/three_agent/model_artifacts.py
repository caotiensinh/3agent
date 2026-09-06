from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


MANIFEST_SCHEMA = "workspace.model-manifest/v1"
RECEIPT_SCHEMA = "workspace.model-provision-receipt/v1"
_HEX40_RE = re.compile(r"^[0-9a-f]{40}$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_REPO_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*$")
_MODEL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,95}$")
_WINDOWS_DRIVE_RE = re.compile(r"^[A-Za-z]:/")


class ModelArtifactError(RuntimeError):
    """Base failure for model artifact governance."""


class ModelManifestError(ModelArtifactError):
    """Raised when an approved model manifest is malformed or unsafe."""


class ModelProvisioningError(ModelArtifactError):
    """Raised when deployment-time provisioning cannot prove artifact integrity."""


class ModelResolutionError(ModelArtifactError):
    """Raised when runtime cannot resolve an approved local-only model."""


def _safe_relative_path(value: str, *, field: str) -> str:
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
        raise ModelManifestError(f"{field} must be a safe non-empty relative path")
    parts = path.parts
    if any(part in {"", ".", ".."} for part in parts):
        raise ModelManifestError(f"{field} contains an unsafe path segment")
    normalized = Path(*parts).as_posix()
    if normalized != raw:
        raise ModelManifestError(f"{field} must be normalized")
    return normalized


def sha256_file(path: Path, *, chunk_size: int = 4 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(chunk_size)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_digest(payload: Mapping[str, Any]) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def apply_runtime_offline_environment(environment: dict[str, str] | None = None) -> dict[str, str]:
    """Force Hugging Face/Transformers runtime into local-only mode.

    Deployment-time provisioning is a separate explicit script. Runtime code
    must never interpret a missing model as permission to reach the Internet.
    """

    target = environment if environment is not None else os.environ
    target["HF_HUB_OFFLINE"] = "1"
    target["TRANSFORMERS_OFFLINE"] = "1"
    target["HF_HUB_DISABLE_TELEMETRY"] = "1"
    return target


@dataclass(frozen=True)
class ApprovedArtifact:
    path: str
    sha256: str
    size_bytes: int | None = None

    @classmethod
    def from_raw(cls, raw: Mapping[str, Any]) -> "ApprovedArtifact":
        path = _safe_relative_path(str(raw.get("path", "")), field="artifact.path")
        sha256 = str(raw.get("sha256", "")).strip().lower()
        if not _SHA256_RE.fullmatch(sha256):
            raise ModelManifestError(f"artifact {path} requires an exact SHA-256 digest")
        size_raw = raw.get("size_bytes")
        size_bytes: int | None = None
        if size_raw is not None:
            try:
                size_bytes = int(size_raw)
            except (TypeError, ValueError) as exc:
                raise ModelManifestError(f"artifact {path} size_bytes must be an integer") from exc
            if size_bytes <= 0:
                raise ModelManifestError(f"artifact {path} size_bytes must be > 0")
        return cls(path=path, sha256=sha256, size_bytes=size_bytes)


@dataclass(frozen=True)
class ApprovedModel:
    model_id: str
    provider: str
    repo_id: str
    revision: str
    local_subdir: str
    capabilities: tuple[str, ...]
    license_id: str
    artifacts: tuple[ApprovedArtifact, ...]

    @classmethod
    def from_raw(cls, raw: Mapping[str, Any]) -> "ApprovedModel":
        model_id = str(raw.get("id", "")).strip()
        if not _MODEL_ID_RE.fullmatch(model_id):
            raise ModelManifestError(f"invalid model id: {model_id or '<empty>'}")

        provider = str(raw.get("provider", "")).strip().lower()
        if provider != "huggingface":
            raise ModelManifestError(
                f"model {model_id} provider must be huggingface in manifest v1"
            )

        repo_id = str(raw.get("repo_id", "")).strip()
        if not _REPO_ID_RE.fullmatch(repo_id):
            raise ModelManifestError(
                f"model {model_id} repo_id must be a canonical owner/name identifier"
            )

        revision = str(raw.get("revision", "")).strip().lower()
        if not _HEX40_RE.fullmatch(revision):
            raise ModelManifestError(
                f"model {model_id} revision must be an exact 40-character commit hash"
            )

        local_subdir = _safe_relative_path(
            str(raw.get("local_subdir", "")), field=f"model {model_id} local_subdir"
        )

        capabilities_raw = raw.get("capabilities", [])
        if not isinstance(capabilities_raw, list) or not capabilities_raw:
            raise ModelManifestError(f"model {model_id} requires at least one capability")
        capabilities = tuple(
            sorted({str(item).strip() for item in capabilities_raw if str(item).strip()})
        )
        if not capabilities:
            raise ModelManifestError(f"model {model_id} requires at least one capability")

        license_id = str(raw.get("license", "")).strip()
        if not license_id:
            raise ModelManifestError(f"model {model_id} requires an approved license identifier")

        artifacts_raw = raw.get("artifacts", [])
        if not isinstance(artifacts_raw, list) or not artifacts_raw:
            raise ModelManifestError(f"model {model_id} requires an integrity artifact set")
        artifacts = tuple(
            ApprovedArtifact.from_raw(item)
            for item in artifacts_raw
            if isinstance(item, Mapping)
        )
        if len(artifacts) != len(artifacts_raw):
            raise ModelManifestError(f"model {model_id} contains an invalid artifact entry")
        paths = [item.path for item in artifacts]
        if len(paths) != len(set(paths)):
            raise ModelManifestError(f"model {model_id} contains duplicate artifact paths")

        return cls(
            model_id=model_id,
            provider=provider,
            repo_id=repo_id,
            revision=revision,
            local_subdir=local_subdir,
            capabilities=capabilities,
            license_id=license_id,
            artifacts=artifacts,
        )


@dataclass(frozen=True)
class ApprovedModelManifest:
    source_path: Path
    models: tuple[ApprovedModel, ...]
    manifest_digest: str

    @classmethod
    def load(cls, path: str | Path) -> "ApprovedModelManifest":
        source = Path(path)
        try:
            raw = json.loads(source.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ModelManifestError(
                f"cannot read approved model manifest: {source}: {exc}"
            ) from exc
        if not isinstance(raw, dict):
            raise ModelManifestError("approved model manifest must be a JSON object")
        if raw.get("schema") != MANIFEST_SCHEMA:
            raise ModelManifestError(f"manifest schema must be {MANIFEST_SCHEMA}")
        if raw.get("runtime_download") is not False:
            raise ModelManifestError("runtime_download must be explicitly false")

        models_raw = raw.get("models")
        if not isinstance(models_raw, list):
            raise ModelManifestError("manifest models must be a list")
        models = tuple(
            ApprovedModel.from_raw(item)
            for item in models_raw
            if isinstance(item, Mapping)
        )
        if len(models) != len(models_raw):
            raise ModelManifestError("manifest contains an invalid model entry")
        model_ids = [item.model_id for item in models]
        if len(model_ids) != len(set(model_ids)):
            raise ModelManifestError("manifest contains duplicate model ids")
        local_subdirs = [item.local_subdir for item in models]
        if len(local_subdirs) != len(set(local_subdirs)):
            raise ModelManifestError("manifest contains duplicate local_subdir targets")
        return cls(
            source_path=source,
            models=models,
            manifest_digest=_canonical_digest(raw),
        )

    def require(self, model_id: str) -> ApprovedModel:
        requested = str(model_id).strip()
        for model in self.models:
            if model.model_id == requested:
                return model
        raise ModelManifestError(
            f"model is not approved by manifest: {requested or '<empty>'}"
        )

    def for_capability(self, capability: str) -> tuple[ApprovedModel, ...]:
        target = str(capability).strip()
        return tuple(model for model in self.models if target in model.capabilities)


def receipt_path(model_root: Path) -> Path:
    return model_root / ".workspace-model-receipt.json"


def validate_artifacts(
    model: ApprovedModel,
    model_root: Path,
) -> dict[str, dict[str, Any]]:
    """Verify every approved file stays under the model root and matches integrity metadata."""

    evidence: dict[str, dict[str, Any]] = {}
    root_resolved = model_root.resolve()
    for artifact in model.artifacts:
        path = (model_root / artifact.path).resolve()
        try:
            path.relative_to(root_resolved)
        except ValueError as exc:
            raise ModelProvisioningError(
                f"artifact escaped model root: {artifact.path}"
            ) from exc
        if not path.is_file():
            raise ModelProvisioningError(f"required artifact is missing: {artifact.path}")
        size = path.stat().st_size
        if artifact.size_bytes is not None and size != artifact.size_bytes:
            raise ModelProvisioningError(
                f"artifact size mismatch for {artifact.path}: "
                f"expected {artifact.size_bytes}, got {size}"
            )
        digest = sha256_file(path)
        if digest != artifact.sha256:
            raise ModelProvisioningError(
                f"artifact SHA-256 mismatch for {artifact.path}: "
                f"expected {artifact.sha256}, got {digest}"
            )
        evidence[artifact.path] = {"sha256": digest, "size_bytes": size}
    return evidence


def build_provision_receipt(
    manifest: ApprovedModelManifest,
    model: ApprovedModel,
    artifacts: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "model_id": model.model_id,
        "provider": model.provider,
        "repo_id": model.repo_id,
        "revision": model.revision,
        "manifest_sha256": manifest.manifest_digest,
        "license": model.license_id,
        "artifacts": dict(sorted(artifacts.items())),
        "provisioned_at": datetime.now(timezone.utc).isoformat(),
    }


def write_provision_receipt(
    manifest: ApprovedModelManifest,
    model: ApprovedModel,
    model_root: Path,
) -> Path:
    artifacts = validate_artifacts(model, model_root)
    payload = build_provision_receipt(manifest, model, artifacts)
    path = receipt_path(model_root)
    path.write_text(
        json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
    )
    return path


class RuntimeModelResolver:
    """Resolve only manifest-approved, integrity-verified local model snapshots.

    This runtime class contains no downloader and no network-capable dependency.
    A missing local model is an authoritative provisioning failure.
    """

    def __init__(self, manifest: ApprovedModelManifest, store_root: str | Path):
        self.manifest = manifest
        self.store_root = Path(store_root)
        self._verified: dict[str, Path] = {}
        apply_runtime_offline_environment()

    def resolve(self, model_id: str) -> Path:
        model = self.manifest.require(model_id)
        cached = self._verified.get(model.model_id)
        if cached is not None and cached.is_dir():
            return cached

        target = self.store_root / model.local_subdir
        if not target.is_dir():
            raise ModelResolutionError(
                f"approved model is not provisioned locally: {model.model_id}; "
                "runtime download is forbidden"
            )

        target_resolved = target.resolve()
        store_resolved = self.store_root.resolve()
        try:
            target_resolved.relative_to(store_resolved)
        except ValueError as exc:
            raise ModelResolutionError(
                "resolved model escaped configured model store"
            ) from exc

        receipt_file = receipt_path(target_resolved)
        try:
            receipt = json.loads(receipt_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ModelResolutionError(
                f"model receipt is missing or invalid for {model.model_id}"
            ) from exc

        expected_identity = {
            "schema": RECEIPT_SCHEMA,
            "model_id": model.model_id,
            "provider": model.provider,
            "repo_id": model.repo_id,
            "revision": model.revision,
            "manifest_sha256": self.manifest.manifest_digest,
        }
        for key, expected in expected_identity.items():
            if receipt.get(key) != expected:
                raise ModelResolutionError(
                    f"model receipt mismatch for {model.model_id}: {key} is not approved"
                )
        try:
            validate_artifacts(model, target_resolved)
        except ModelProvisioningError as exc:
            raise ModelResolutionError(str(exc)) from exc

        self._verified[model.model_id] = target_resolved
        return target_resolved
