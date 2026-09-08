from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .runtime_invocation import RuntimeInvocationBundle
from .runtime_plan_compiler import CompiledRuntimePlan

RUNTIME_INVOCATION_BINDING_SCHEMA = "workspace-runtime-invocation-binding/v1"
RUNTIME_INVOCATION_BINDING_STORE_SCHEMA = "workspace-runtime-invocation-binding-store/v1"
_SHA_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_BYTES = 64 * 1024


class RuntimeInvocationBindingError(RuntimeError):
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
class RuntimeInvocationBinding:
    task_id: str
    plan_id: str
    plan_fingerprint: str
    compiled_plan_fingerprint: str
    invocation_bundle_fingerprint: str
    binding_id: str
    schema_version: str = RUNTIME_INVOCATION_BINDING_SCHEMA

    @classmethod
    def capture(
        cls,
        *,
        compiled_plan: CompiledRuntimePlan,
        invocation_bundle: RuntimeInvocationBundle,
    ) -> "RuntimeInvocationBinding":
        invocation_bundle.validate(compiled_plan)
        identity = {
            "schema_version": RUNTIME_INVOCATION_BINDING_SCHEMA,
            "task_id": compiled_plan.plan.task_id,
            "plan_id": compiled_plan.plan.plan_id,
            "plan_fingerprint": compiled_plan.plan.fingerprint,
            "compiled_plan_fingerprint": compiled_plan.fingerprint,
            "invocation_bundle_fingerprint": invocation_bundle.fingerprint,
        }
        binding = cls(
            task_id=compiled_plan.plan.task_id,
            plan_id=compiled_plan.plan.plan_id,
            plan_fingerprint=compiled_plan.plan.fingerprint,
            compiled_plan_fingerprint=compiled_plan.fingerprint,
            invocation_bundle_fingerprint=invocation_bundle.fingerprint,
            binding_id="invbind:" + _sha(identity).split(":", 1)[1][:32],
        )
        return binding.validate(compiled_plan, invocation_bundle)

    def _identity(self) -> dict[str, str]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "plan_id": self.plan_id,
            "plan_fingerprint": self.plan_fingerprint,
            "compiled_plan_fingerprint": self.compiled_plan_fingerprint,
            "invocation_bundle_fingerprint": self.invocation_bundle_fingerprint,
        }

    def validate(
        self,
        compiled_plan: CompiledRuntimePlan,
        invocation_bundle: RuntimeInvocationBundle,
    ) -> "RuntimeInvocationBinding":
        invocation_bundle.validate(compiled_plan)
        checks = (
            (self.schema_version == RUNTIME_INVOCATION_BINDING_SCHEMA, "INVOCATION_BINDING_SCHEMA_UNSUPPORTED"),
            (self.task_id == compiled_plan.plan.task_id, "INVOCATION_BINDING_TASK_MISMATCH"),
            (self.plan_id == compiled_plan.plan.plan_id, "INVOCATION_BINDING_PLAN_ID_MISMATCH"),
            (self.plan_fingerprint == compiled_plan.plan.fingerprint, "INVOCATION_BINDING_PLAN_CHANGED"),
            (self.compiled_plan_fingerprint == compiled_plan.fingerprint, "INVOCATION_BINDING_COMPILED_PLAN_CHANGED"),
            (self.invocation_bundle_fingerprint == invocation_bundle.fingerprint, "INVOCATION_BINDING_BUNDLE_CHANGED"),
        )
        for valid, code in checks:
            if not valid:
                raise RuntimeInvocationBindingError(code)
        for digest in (
            self.plan_fingerprint,
            self.compiled_plan_fingerprint,
            self.invocation_bundle_fingerprint,
        ):
            if not _SHA_RE.fullmatch(str(digest)):
                raise RuntimeInvocationBindingError("INVOCATION_BINDING_DIGEST_INVALID")
        expected = "invbind:" + _sha(self._identity()).split(":", 1)[1][:32]
        if self.binding_id != expected:
            raise RuntimeInvocationBindingError("INVOCATION_BINDING_ID_INTEGRITY_MISMATCH")
        return self

    def metadata(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_metadata(cls, payload: Any) -> "RuntimeInvocationBinding":
        if not isinstance(payload, dict):
            raise RuntimeInvocationBindingError("INVOCATION_BINDING_PAYLOAD_INVALID")
        expected = {
            "task_id",
            "plan_id",
            "plan_fingerprint",
            "compiled_plan_fingerprint",
            "invocation_bundle_fingerprint",
            "binding_id",
            "schema_version",
        }
        if set(payload) != expected:
            raise RuntimeInvocationBindingError("INVOCATION_BINDING_PAYLOAD_SHAPE_INVALID")
        try:
            return cls(
                task_id=str(payload["task_id"]),
                plan_id=str(payload["plan_id"]),
                plan_fingerprint=str(payload["plan_fingerprint"]),
                compiled_plan_fingerprint=str(payload["compiled_plan_fingerprint"]),
                invocation_bundle_fingerprint=str(payload["invocation_bundle_fingerprint"]),
                binding_id=str(payload["binding_id"]),
                schema_version=str(payload["schema_version"]),
            )
        except (KeyError, TypeError) as exc:
            raise RuntimeInvocationBindingError("INVOCATION_BINDING_PAYLOAD_INVALID") from exc


class RuntimeInvocationBindingStore:
    """Atomic immutable sidecar binding typed invocations to a compiled plan.

    RuntimeCheckpoint v2 remains unchanged. This separate binding is written once
    before production execution and must match exactly on every restart. A caller
    cannot resume the same DAG with changed typed tool parameters.
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
        invocation_bundle: RuntimeInvocationBundle,
    ) -> RuntimeInvocationBinding:
        candidate = RuntimeInvocationBinding.capture(
            compiled_plan=compiled_plan,
            invocation_bundle=invocation_bundle,
        )
        path = self._path(candidate.task_id, candidate.plan_id)
        if path.exists():
            existing = self.load(
                compiled_plan=compiled_plan,
                invocation_bundle=invocation_bundle,
            )
            if existing.binding_id != candidate.binding_id:
                raise RuntimeInvocationBindingError("INVOCATION_BINDING_IMMUTABLE_MISMATCH")
            return existing

        payload = candidate.metadata()
        envelope = {
            "schema_version": RUNTIME_INVOCATION_BINDING_STORE_SCHEMA,
            "payload_sha256": _sha(payload),
            "binding": payload,
        }
        encoded = (_canonical(envelope) + "\n").encode("utf-8")
        if not encoded or len(encoded) > _MAX_BYTES:
            raise RuntimeInvocationBindingError("INVOCATION_BINDING_TOO_LARGE")
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
            # Race-safe create-only semantics. Do not overwrite a binding that may
            # have been created concurrently with a different invocation bundle.
            try:
                os.link(tmp_name, path)
            except FileExistsError:
                existing = self.load(
                    compiled_plan=compiled_plan,
                    invocation_bundle=invocation_bundle,
                )
                if existing.binding_id != candidate.binding_id:
                    raise RuntimeInvocationBindingError("INVOCATION_BINDING_IMMUTABLE_MISMATCH")
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
        invocation_bundle: RuntimeInvocationBundle,
    ) -> RuntimeInvocationBinding:
        path = self._path(compiled_plan.plan.task_id, compiled_plan.plan.plan_id)
        if not path.is_file():
            raise RuntimeInvocationBindingError("INVOCATION_BINDING_NOT_FOUND")
        raw = path.read_bytes()
        if not raw or len(raw) > _MAX_BYTES:
            raise RuntimeInvocationBindingError("INVOCATION_BINDING_FILE_INVALID")
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeInvocationBindingError("INVOCATION_BINDING_FILE_INVALID") from exc
        if (
            not isinstance(envelope, dict)
            or envelope.get("schema_version") != RUNTIME_INVOCATION_BINDING_STORE_SCHEMA
        ):
            raise RuntimeInvocationBindingError("INVOCATION_BINDING_STORE_SCHEMA_UNSUPPORTED")
        payload = envelope.get("binding")
        if not isinstance(payload, dict) or str(envelope.get("payload_sha256")) != _sha(payload):
            raise RuntimeInvocationBindingError("INVOCATION_BINDING_PAYLOAD_INTEGRITY_MISMATCH")
        return RuntimeInvocationBinding.from_metadata(payload).validate(
            compiled_plan,
            invocation_bundle,
        )
