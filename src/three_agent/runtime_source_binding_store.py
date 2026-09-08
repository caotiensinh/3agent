from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .capability_registry import CapabilityRegistry
from .runtime_plan_compiler import CompiledRuntimePlan
from .runtime_source_authority import RuntimeSourceBindingBundle
from .task_contract import TaskContract

RUNTIME_SOURCE_RECOVERY_BINDING_SCHEMA = "workspace-runtime-source-recovery-binding/v1"
RUNTIME_SOURCE_RECOVERY_STORE_SCHEMA = "workspace-runtime-source-recovery-store/v1"
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_BYTES = 64 * 1024


class RuntimeSourceBindingStoreError(RuntimeError):
    pass


def _canonical(payload: Any) -> str:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )


def _sha(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RuntimeSourceRecoveryBinding:
    task_id: str
    plan_id: str
    plan_fingerprint: str
    compiled_plan_fingerprint: str
    source_binding_bundle_fingerprint: str
    binding_id: str
    schema_version: str = RUNTIME_SOURCE_RECOVERY_BINDING_SCHEMA

    @classmethod
    def capture(
        cls,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        source_binding_bundle: RuntimeSourceBindingBundle,
        registry: CapabilityRegistry | None = None,
    ) -> "RuntimeSourceRecoveryBinding":
        source_binding_bundle.validate(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
            registry=registry,
        )
        identity = {
            "schema_version": RUNTIME_SOURCE_RECOVERY_BINDING_SCHEMA,
            "task_id": compiled_plan.plan.task_id,
            "plan_id": compiled_plan.plan.plan_id,
            "plan_fingerprint": compiled_plan.plan.fingerprint,
            "compiled_plan_fingerprint": compiled_plan.fingerprint,
            "source_binding_bundle_fingerprint": source_binding_bundle.fingerprint,
        }
        binding = cls(
            task_id=compiled_plan.plan.task_id,
            plan_id=compiled_plan.plan.plan_id,
            plan_fingerprint=compiled_plan.plan.fingerprint,
            compiled_plan_fingerprint=compiled_plan.fingerprint,
            source_binding_bundle_fingerprint=source_binding_bundle.fingerprint,
            binding_id="srcbind:" + _sha(identity).split(":", 1)[1][:32],
        )
        return binding.validate(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
            source_binding_bundle=source_binding_bundle,
            registry=registry,
        )

    def _identity(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "plan_fingerprint": self.plan_fingerprint,
            "compiled_plan_fingerprint": self.compiled_plan_fingerprint,
            "source_binding_bundle_fingerprint": self.source_binding_bundle_fingerprint,
        }

    def validate(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        source_binding_bundle: RuntimeSourceBindingBundle,
        registry: CapabilityRegistry | None = None,
    ) -> "RuntimeSourceRecoveryBinding":
        source_binding_bundle.validate(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
            registry=registry,
        )
        checks = (
            (
                self.schema_version == RUNTIME_SOURCE_RECOVERY_BINDING_SCHEMA,
                "SOURCE_RECOVERY_BINDING_SCHEMA_UNSUPPORTED",
            ),
            (
                self.task_id == compiled_plan.plan.task_id,
                "SOURCE_RECOVERY_BINDING_TASK_MISMATCH",
            ),
            (
                self.plan_id == compiled_plan.plan.plan_id,
                "SOURCE_RECOVERY_BINDING_PLAN_ID_MISMATCH",
            ),
            (
                self.plan_fingerprint == compiled_plan.plan.fingerprint,
                "SOURCE_RECOVERY_BINDING_PLAN_CHANGED",
            ),
            (
                self.compiled_plan_fingerprint == compiled_plan.fingerprint,
                "SOURCE_RECOVERY_BINDING_COMPILED_PLAN_CHANGED",
            ),
            (
                self.source_binding_bundle_fingerprint
                == source_binding_bundle.fingerprint,
                "SOURCE_RECOVERY_BUNDLE_CHANGED",
            ),
        )
        for valid, code in checks:
            if not valid:
                raise RuntimeSourceBindingStoreError(code)
        for digest in (
            self.plan_fingerprint,
            self.compiled_plan_fingerprint,
            self.source_binding_bundle_fingerprint,
        ):
            if not _SHA_RE.fullmatch(str(digest)):
                raise RuntimeSourceBindingStoreError(
                    "SOURCE_RECOVERY_BINDING_DIGEST_INVALID"
                )
        expected = "srcbind:" + _sha(self._identity()).split(":", 1)[1][:32]
        if self.binding_id != expected:
            raise RuntimeSourceBindingStoreError(
                "SOURCE_RECOVERY_BINDING_ID_INTEGRITY_MISMATCH"
            )
        return self

    def metadata(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_metadata(cls, payload: Any) -> "RuntimeSourceRecoveryBinding":
        if not isinstance(payload, dict):
            raise RuntimeSourceBindingStoreError(
                "SOURCE_RECOVERY_BINDING_PAYLOAD_INVALID"
            )
        expected = {
            "task_id",
            "plan_id",
            "plan_fingerprint",
            "compiled_plan_fingerprint",
            "source_binding_bundle_fingerprint",
            "binding_id",
            "schema_version",
        }
        if set(payload) != expected:
            raise RuntimeSourceBindingStoreError(
                "SOURCE_RECOVERY_BINDING_PAYLOAD_SHAPE_INVALID"
            )
        try:
            return cls(
                task_id=str(payload["task_id"]),
                plan_id=str(payload["plan_id"]),
                plan_fingerprint=str(payload["plan_fingerprint"]),
                compiled_plan_fingerprint=str(payload["compiled_plan_fingerprint"]),
                source_binding_bundle_fingerprint=str(
                    payload["source_binding_bundle_fingerprint"]
                ),
                binding_id=str(payload["binding_id"]),
                schema_version=str(payload["schema_version"]),
            )
        except (KeyError, TypeError) as exc:
            raise RuntimeSourceBindingStoreError(
                "SOURCE_RECOVERY_BINDING_PAYLOAD_INVALID"
            ) from exc


class RuntimeSourceBindingStore:
    """Create-only durable binding for runtime-reviewed source semantics.

    Only compact fingerprints are persisted. Raw local roots remain runtime-owned
    configuration and are revalidated against their hash on every execution.
    """

    durable = True

    def __init__(self, root: Path):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _key(value: str) -> str:
        return hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:32]

    def _path(self, task_id: str, plan_id: str) -> Path:
        return self.root / self._key(task_id) / f"{self._key(plan_id)}.json"

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

    def bind(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        source_binding_bundle: RuntimeSourceBindingBundle,
        registry: CapabilityRegistry | None = None,
    ) -> RuntimeSourceRecoveryBinding:
        candidate = RuntimeSourceRecoveryBinding.capture(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
            source_binding_bundle=source_binding_bundle,
            registry=registry,
        )
        path = self._path(candidate.task_id, candidate.plan_id)
        if path.exists():
            existing = self.load(
                compiled_plan=compiled_plan,
                task_contract=task_contract,
                source_binding_bundle=source_binding_bundle,
                registry=registry,
            )
            if existing.binding_id != candidate.binding_id:
                raise RuntimeSourceBindingStoreError(
                    "SOURCE_RECOVERY_BINDING_IMMUTABLE_MISMATCH"
                )
            return existing

        payload = candidate.metadata()
        envelope = {
            "schema_version": RUNTIME_SOURCE_RECOVERY_STORE_SCHEMA,
            "payload_sha256": _sha(payload),
            "binding": payload,
        }
        encoded = (_canonical(envelope) + "\n").encode("utf-8")
        if not encoded or len(encoded) > _MAX_BYTES:
            raise RuntimeSourceBindingStoreError("SOURCE_RECOVERY_BINDING_TOO_LARGE")
        path.parent.mkdir(parents=True, exist_ok=True)
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
                os.link(tmp_name, path)
            except FileExistsError:
                existing = self.load(
                    compiled_plan=compiled_plan,
                    task_contract=task_contract,
                    source_binding_bundle=source_binding_bundle,
                    registry=registry,
                )
                if existing.binding_id != candidate.binding_id:
                    raise RuntimeSourceBindingStoreError(
                        "SOURCE_RECOVERY_BINDING_IMMUTABLE_MISMATCH"
                    )
                return existing
            finally:
                if tmp_name is not None:
                    try:
                        os.unlink(tmp_name)
                    except FileNotFoundError:
                        pass
                    tmp_name = None
            self._fsync_dir(path.parent)
        finally:
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass
        return candidate

    def load(
        self,
        *,
        compiled_plan: CompiledRuntimePlan,
        task_contract: TaskContract,
        source_binding_bundle: RuntimeSourceBindingBundle,
        registry: CapabilityRegistry | None = None,
    ) -> RuntimeSourceRecoveryBinding:
        path = self._path(compiled_plan.plan.task_id, compiled_plan.plan.plan_id)
        if not path.is_file():
            raise RuntimeSourceBindingStoreError("SOURCE_RECOVERY_BINDING_NOT_FOUND")
        raw = path.read_bytes()
        if not raw or len(raw) > _MAX_BYTES:
            raise RuntimeSourceBindingStoreError("SOURCE_RECOVERY_BINDING_FILE_INVALID")
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeSourceBindingStoreError(
                "SOURCE_RECOVERY_BINDING_FILE_INVALID"
            ) from exc
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema_version") != RUNTIME_SOURCE_RECOVERY_STORE_SCHEMA
        ):
            raise RuntimeSourceBindingStoreError(
                "SOURCE_RECOVERY_STORE_SCHEMA_UNSUPPORTED"
            )
        payload = envelope.get("binding")
        if (
            not isinstance(payload, dict)
            or str(envelope.get("payload_sha256")) != _sha(payload)
        ):
            raise RuntimeSourceBindingStoreError(
                "SOURCE_RECOVERY_BINDING_PAYLOAD_INTEGRITY_MISMATCH"
            )
        return RuntimeSourceRecoveryBinding.from_metadata(payload).validate(
            compiled_plan=compiled_plan,
            task_contract=task_contract,
            source_binding_bundle=source_binding_bundle,
            registry=registry,
        )
