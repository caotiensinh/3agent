from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

RUNTIME_V3_DISPATCH_DESCRIPTOR_SCHEMA = "workspace-runtime-v3-dispatch-descriptor/v1"
RUNTIME_V3_DISPATCH_MANIFEST_SCHEMA = "workspace-runtime-v3-dispatch-manifest/v1"
RUNTIME_V3_DISPATCH_STORE_SCHEMA = "workspace-runtime-v3-dispatch-store/v1"
_COMPACT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/#@+\-=]{0,255}$")
_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_MANIFEST_BYTES = 64 * 1024


class RuntimeV3DispatchError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


def _canonical(payload: object) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def _canonical_sha256(payload: object) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _compact(value: object, field: str) -> str:
    text = str(value or "").strip()
    if not text or not _COMPACT_RE.fullmatch(text) or "://" in text:
        raise RuntimeV3DispatchError(f"RUNTIME_V3_{field.upper()}_INVALID")
    return text


def _digest(value: object, field: str, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    text = str(value or "").strip().lower()
    if not _SHA256_RE.fullmatch(text):
        raise RuntimeV3DispatchError(f"RUNTIME_V3_{field.upper()}_INVALID")
    return text


@dataclass(frozen=True)
class RuntimeV3DispatchDescriptor:
    """Durable, content-free description of one reviewed Runtime V3 package."""

    task_id: str
    runtime_ref: str
    compiled_plan_fingerprint: str
    invocation_bundle_fingerprint: str
    authority_fingerprint: str
    source_binding_bundle_fingerprint: str | None = None
    query_bundle_fingerprint: str | None = None
    schema_version: str = RUNTIME_V3_DISPATCH_DESCRIPTOR_SCHEMA

    def validate(self) -> "RuntimeV3DispatchDescriptor":
        if self.schema_version != RUNTIME_V3_DISPATCH_DESCRIPTOR_SCHEMA:
            raise RuntimeV3DispatchError("RUNTIME_V3_DESCRIPTOR_SCHEMA_UNSUPPORTED")
        _compact(self.task_id, "task_id")
        _compact(self.runtime_ref, "runtime_ref")
        _digest(self.compiled_plan_fingerprint, "compiled_plan_fingerprint")
        _digest(self.invocation_bundle_fingerprint, "invocation_bundle_fingerprint")
        _digest(self.authority_fingerprint, "authority_fingerprint")
        _digest(
            self.source_binding_bundle_fingerprint,
            "source_binding_bundle_fingerprint",
            optional=True,
        )
        _digest(
            self.query_bundle_fingerprint,
            "query_bundle_fingerprint",
            optional=True,
        )
        return self

    @property
    def fingerprint(self) -> str:
        return _canonical_sha256(self.metadata())

    def metadata(self) -> dict[str, str | None]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "runtime_ref": self.runtime_ref,
            "compiled_plan_fingerprint": self.compiled_plan_fingerprint,
            "invocation_bundle_fingerprint": self.invocation_bundle_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
            "source_binding_bundle_fingerprint": self.source_binding_bundle_fingerprint,
            "query_bundle_fingerprint": self.query_bundle_fingerprint,
        }

    @classmethod
    def from_metadata(cls, payload: object) -> "RuntimeV3DispatchDescriptor":
        if not isinstance(payload, dict):
            raise RuntimeV3DispatchError("RUNTIME_V3_DESCRIPTOR_PAYLOAD_INVALID")
        expected = {
            "schema_version",
            "task_id",
            "runtime_ref",
            "compiled_plan_fingerprint",
            "invocation_bundle_fingerprint",
            "authority_fingerprint",
            "source_binding_bundle_fingerprint",
            "query_bundle_fingerprint",
        }
        if set(payload) != expected:
            raise RuntimeV3DispatchError("RUNTIME_V3_DESCRIPTOR_PAYLOAD_SHAPE_INVALID")
        return cls(
            task_id=str(payload["task_id"]),
            runtime_ref=str(payload["runtime_ref"]),
            compiled_plan_fingerprint=str(payload["compiled_plan_fingerprint"]),
            invocation_bundle_fingerprint=str(payload["invocation_bundle_fingerprint"]),
            authority_fingerprint=str(payload["authority_fingerprint"]),
            source_binding_bundle_fingerprint=(
                None
                if payload["source_binding_bundle_fingerprint"] is None
                else str(payload["source_binding_bundle_fingerprint"])
            ),
            query_bundle_fingerprint=(
                None
                if payload["query_bundle_fingerprint"] is None
                else str(payload["query_bundle_fingerprint"])
            ),
            schema_version=str(payload["schema_version"]),
        ).validate()


class RuntimeV3DispatchExecutor(Protocol):
    def describe(self, runtime_ref: str) -> RuntimeV3DispatchDescriptor: ...

    def execute(
        self,
        runtime_ref: str,
        *,
        expected_descriptor_fingerprint: str,
        approval_fingerprint: str,
        approver_ref: str,
    ) -> Any: ...


class RuntimeV3PackageProvider(Protocol):
    """Domain-owned durable package backend used by the canonical dispatcher.

    Providers own all raw package semantics and reviewed boundary reconstruction.
    The canonical dispatcher stores only opaque package references and fingerprints.
    A provider must remain reconstructable after process restart and must revalidate
    the expected descriptor before any side effect.
    """

    durable: bool

    def describe_package(self, package_ref: str) -> RuntimeV3DispatchDescriptor: ...

    def execute_package(
        self,
        package_ref: str,
        *,
        expected_descriptor_fingerprint: str,
        approval_fingerprint: str,
        approver_ref: str,
    ) -> Any: ...


def validate_runtime_v3_executor(executor: object) -> RuntimeV3DispatchExecutor:
    if executor is None:
        raise RuntimeV3DispatchError("RUNTIME_V3_EXECUTOR_REQUIRED")
    if not callable(getattr(executor, "describe", None)):
        raise RuntimeV3DispatchError("RUNTIME_V3_EXECUTOR_DESCRIBE_REQUIRED")
    if not callable(getattr(executor, "execute", None)):
        raise RuntimeV3DispatchError("RUNTIME_V3_EXECUTOR_EXECUTE_REQUIRED")
    return executor  # type: ignore[return-value]


def _validate_provider(provider: object) -> RuntimeV3PackageProvider:
    if provider is None or not bool(getattr(provider, "durable", False)):
        raise RuntimeV3DispatchError("RUNTIME_V3_DURABLE_PROVIDER_REQUIRED")
    if not callable(getattr(provider, "describe_package", None)):
        raise RuntimeV3DispatchError("RUNTIME_V3_PROVIDER_DESCRIBE_REQUIRED")
    if not callable(getattr(provider, "execute_package", None)):
        raise RuntimeV3DispatchError("RUNTIME_V3_PROVIDER_EXECUTE_REQUIRED")
    return provider  # type: ignore[return-value]


@dataclass(frozen=True)
class RuntimeV3DispatchManifest:
    runtime_ref: str
    provider_id: str
    package_ref: str
    descriptor: RuntimeV3DispatchDescriptor
    descriptor_fingerprint: str
    schema_version: str = RUNTIME_V3_DISPATCH_MANIFEST_SCHEMA

    def validate(self) -> "RuntimeV3DispatchManifest":
        if self.schema_version != RUNTIME_V3_DISPATCH_MANIFEST_SCHEMA:
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_SCHEMA_UNSUPPORTED")
        _compact(self.runtime_ref, "runtime_ref")
        _compact(self.provider_id, "provider_id")
        _compact(self.package_ref, "package_ref")
        self.descriptor.validate()
        if self.runtime_ref != self.descriptor.runtime_ref:
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_RUNTIME_REF_MISMATCH")
        if self.descriptor_fingerprint != self.descriptor.fingerprint:
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_DESCRIPTOR_INTEGRITY_MISMATCH")
        _digest(self.descriptor_fingerprint, "descriptor_fingerprint")
        return self

    def metadata(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "runtime_ref": self.runtime_ref,
            "provider_id": self.provider_id,
            "package_ref": self.package_ref,
            "descriptor": self.descriptor.metadata(),
            "descriptor_fingerprint": self.descriptor_fingerprint,
        }

    @classmethod
    def from_metadata(cls, payload: object) -> "RuntimeV3DispatchManifest":
        if not isinstance(payload, dict):
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_PAYLOAD_INVALID")
        expected = {
            "schema_version",
            "runtime_ref",
            "provider_id",
            "package_ref",
            "descriptor",
            "descriptor_fingerprint",
        }
        if set(payload) != expected:
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_PAYLOAD_SHAPE_INVALID")
        return cls(
            runtime_ref=str(payload["runtime_ref"]),
            provider_id=str(payload["provider_id"]),
            package_ref=str(payload["package_ref"]),
            descriptor=RuntimeV3DispatchDescriptor.from_metadata(payload["descriptor"]),
            descriptor_fingerprint=str(payload["descriptor_fingerprint"]),
            schema_version=str(payload["schema_version"]),
        ).validate()


class DurableRuntimeV3DispatchExecutor:
    """Canonical restart-safe Runtime V3 executor/router.

    The manifest is create-only and contains no raw plan, invocation, source root,
    SQL, patch bytes, credentials, or live Python object. A durable domain provider
    owns package persistence and reviewed boundary reconstruction. Every describe
    and execute replays the provider descriptor and rejects semantic drift.
    """

    durable = True

    def __init__(
        self,
        root: Path,
        *,
        providers: dict[str, RuntimeV3PackageProvider] | None = None,
    ):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass
        self._providers: dict[str, RuntimeV3PackageProvider] = {}
        for provider_id, provider in (providers or {}).items():
            self.register_provider(provider_id, provider)

    @staticmethod
    def _key(runtime_ref: str) -> str:
        return hashlib.sha256(runtime_ref.encode("utf-8")).hexdigest()[:40]

    def _path(self, runtime_ref: str) -> Path:
        ref = _compact(runtime_ref, "runtime_ref")
        return self.root / f"{self._key(ref)}.json"

    @staticmethod
    def _fsync_dir(path: Path) -> None:
        try:
            fd = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(fd)
        except OSError:
            pass
        finally:
            os.close(fd)

    def register_provider(self, provider_id: str, provider: RuntimeV3PackageProvider) -> None:
        key = _compact(provider_id, "provider_id")
        checked = _validate_provider(provider)
        current = self._providers.get(key)
        if current is not None and current is not checked:
            raise RuntimeV3DispatchError("RUNTIME_V3_PROVIDER_ID_ALREADY_REGISTERED")
        self._providers[key] = checked

    def _provider(self, provider_id: str) -> RuntimeV3PackageProvider:
        key = _compact(provider_id, "provider_id")
        try:
            return self._providers[key]
        except KeyError as exc:
            raise RuntimeV3DispatchError("RUNTIME_V3_PROVIDER_NOT_REGISTERED") from exc

    def _write_create_only(self, path: Path, envelope: dict[str, object]) -> None:
        encoded = (_canonical(envelope) + "\n").encode("utf-8")
        if not encoded or len(encoded) > _MAX_MANIFEST_BYTES:
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_TOO_LARGE")
        tmp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                "wb",
                dir=path.parent,
                prefix=path.name + ".",
                suffix=".tmp",
                delete=False,
            ) as handle:
                tmp_name = handle.name
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            try:
                os.chmod(tmp_name, 0o600)
            except OSError:
                pass
            try:
                os.link(tmp_name, path)
            except FileExistsError:
                raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_ALREADY_EXISTS")
            finally:
                if tmp_name is not None:
                    try:
                        os.unlink(tmp_name)
                    except FileNotFoundError:
                        pass
                    tmp_name = None
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass
            self._fsync_dir(path.parent)
        finally:
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass

    def register_package(
        self,
        *,
        provider_id: str,
        package_ref: str,
    ) -> RuntimeV3DispatchDescriptor:
        provider_key = _compact(provider_id, "provider_id")
        package_key = _compact(package_ref, "package_ref")
        provider = self._provider(provider_key)
        try:
            descriptor = provider.describe_package(package_key)
        except RuntimeV3DispatchError:
            raise
        except Exception as exc:
            raise RuntimeV3DispatchError("RUNTIME_V3_PROVIDER_DESCRIBE_FAILED") from exc
        if not isinstance(descriptor, RuntimeV3DispatchDescriptor):
            raise RuntimeV3DispatchError("RUNTIME_V3_PROVIDER_DESCRIPTOR_TYPE_INVALID")
        descriptor.validate()
        manifest = RuntimeV3DispatchManifest(
            runtime_ref=descriptor.runtime_ref,
            provider_id=provider_key,
            package_ref=package_key,
            descriptor=descriptor,
            descriptor_fingerprint=descriptor.fingerprint,
        ).validate()
        path = self._path(descriptor.runtime_ref)
        if path.exists():
            existing = self._load_manifest(descriptor.runtime_ref)
            if existing.metadata() != manifest.metadata():
                raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_IMMUTABLE_MISMATCH")
            return self.describe(descriptor.runtime_ref)
        payload = manifest.metadata()
        envelope = {
            "schema_version": RUNTIME_V3_DISPATCH_STORE_SCHEMA,
            "payload_sha256": _canonical_sha256(payload),
            "manifest": payload,
        }
        try:
            self._write_create_only(path, envelope)
        except RuntimeV3DispatchError as exc:
            if exc.reason_code != "RUNTIME_V3_MANIFEST_ALREADY_EXISTS":
                raise
            existing = self._load_manifest(descriptor.runtime_ref)
            if existing.metadata() != manifest.metadata():
                raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_IMMUTABLE_MISMATCH")
        return self.describe(descriptor.runtime_ref)

    def _load_manifest(self, runtime_ref: str) -> RuntimeV3DispatchManifest:
        path = self._path(runtime_ref)
        if not path.is_file():
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_NOT_FOUND")
        raw = path.read_bytes()
        if not raw or len(raw) > _MAX_MANIFEST_BYTES:
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_FILE_INVALID")
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_FILE_INVALID") from exc
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema_version") != RUNTIME_V3_DISPATCH_STORE_SCHEMA
        ):
            raise RuntimeV3DispatchError("RUNTIME_V3_DISPATCH_STORE_SCHEMA_UNSUPPORTED")
        payload = envelope.get("manifest")
        if not isinstance(payload, dict):
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_PAYLOAD_INVALID")
        if str(envelope.get("payload_sha256") or "") != _canonical_sha256(payload):
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_PAYLOAD_INTEGRITY_MISMATCH")
        manifest = RuntimeV3DispatchManifest.from_metadata(payload)
        if manifest.runtime_ref != _compact(runtime_ref, "runtime_ref"):
            raise RuntimeV3DispatchError("RUNTIME_V3_MANIFEST_RUNTIME_REF_MISMATCH")
        return manifest

    def describe(self, runtime_ref: str) -> RuntimeV3DispatchDescriptor:
        manifest = self._load_manifest(runtime_ref)
        provider = self._provider(manifest.provider_id)
        try:
            current = provider.describe_package(manifest.package_ref)
        except RuntimeV3DispatchError:
            raise
        except Exception as exc:
            raise RuntimeV3DispatchError("RUNTIME_V3_PROVIDER_DESCRIBE_FAILED") from exc
        if not isinstance(current, RuntimeV3DispatchDescriptor):
            raise RuntimeV3DispatchError("RUNTIME_V3_PROVIDER_DESCRIPTOR_TYPE_INVALID")
        current.validate()
        if current.runtime_ref != manifest.runtime_ref:
            raise RuntimeV3DispatchError("RUNTIME_V3_PROVIDER_RUNTIME_REF_CHANGED")
        if current.fingerprint != manifest.descriptor_fingerprint:
            raise RuntimeV3DispatchError("RUNTIME_V3_PROVIDER_DESCRIPTOR_CHANGED")
        return current

    def execute(
        self,
        runtime_ref: str,
        *,
        expected_descriptor_fingerprint: str,
        approval_fingerprint: str,
        approver_ref: str,
    ) -> Any:
        expected = _digest(expected_descriptor_fingerprint, "expected_descriptor_fingerprint")
        approval = _digest(approval_fingerprint, "approval_fingerprint")
        approver = _digest(approver_ref, "approver_ref")
        manifest = self._load_manifest(runtime_ref)
        current = self.describe(runtime_ref)
        if current.fingerprint != expected:
            raise RuntimeV3DispatchError("RUNTIME_V3_EXPECTED_DESCRIPTOR_MISMATCH")
        provider = self._provider(manifest.provider_id)
        try:
            return provider.execute_package(
                manifest.package_ref,
                expected_descriptor_fingerprint=str(expected),
                approval_fingerprint=str(approval),
                approver_ref=str(approver),
            )
        except RuntimeV3DispatchError:
            raise
        except Exception as exc:
            raise RuntimeV3DispatchError("RUNTIME_V3_PROVIDER_EXECUTION_FAILED") from exc
