from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Iterable

from .runtime_execution_plan import ExecutionObservation
from .runtime_plan_compiler import CompiledRuntimePlan

RUNTIME_CHECKPOINT_SCHEMA = "workspace-runtime-checkpoint/v2"
RUNTIME_CHECKPOINT_STORE_SCHEMA = "workspace-runtime-checkpoint-store/v1"
_STATUSES = {"ready", "running", "blocked", "failed", "completed"}
_OBS_ID_RE = re.compile(r"^obs:[0-9a-f]{32}$")
_MAX_BYTES = 128 * 1024


class RuntimeCheckpointError(RuntimeError):
    pass


def _canonical(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)


def _sha(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()


def _ids(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(str(v).strip() for v in values if str(v).strip()))


def _payload_ids(payload: dict[str, Any], field: str) -> tuple[str, ...]:
    raw = payload.get(field, [])
    if not isinstance(raw, list) or not all(isinstance(v, str) for v in raw):
        raise RuntimeCheckpointError("CHECKPOINT_PAYLOAD_INVALID")
    return _ids(raw)


@dataclass(frozen=True)
class RuntimeCheckpoint:
    checkpoint_id: str
    status: str
    task_id: str
    plan_id: str
    plan_fingerprint: str
    compiled_plan_fingerprint: str
    authority_fingerprint: str
    registry_fingerprint: str
    completed_node_ids: tuple[str, ...]
    running_node_ids: tuple[str, ...]
    failed_node_ids: tuple[str, ...]
    observation_ids: tuple[str, ...]
    schema_version: str = RUNTIME_CHECKPOINT_SCHEMA

    @classmethod
    def capture(
        cls,
        *,
        compiled_plan: CompiledRuntimePlan,
        status: str,
        completed_node_ids: Iterable[str] = (),
        running_node_ids: Iterable[str] = (),
        failed_node_ids: Iterable[str] = (),
        observations: Iterable[ExecutionObservation] = (),
        prior_observation_ids: Iterable[str] = (),
    ) -> "RuntimeCheckpoint":
        plan = compiled_plan.plan
        normalized = str(status).strip().lower()
        if normalized not in _STATUSES:
            raise RuntimeCheckpointError("CHECKPOINT_STATUS_INVALID")
        completed = tuple(sorted(set(_ids(completed_node_ids))))
        running = tuple(sorted(set(_ids(running_node_ids))))
        failed = tuple(sorted(set(_ids(failed_node_ids))))
        observation_ids = _ids((*tuple(prior_observation_ids), *(o.observation_id for o in observations)))
        identity = {
            "schema_version": RUNTIME_CHECKPOINT_SCHEMA,
            "status": normalized,
            "task_id": plan.task_id,
            "plan_id": plan.plan_id,
            "plan_fingerprint": plan.fingerprint,
            "compiled_plan_fingerprint": compiled_plan.fingerprint,
            "authority_fingerprint": plan.authority_fingerprint,
            "registry_fingerprint": compiled_plan.registry_fingerprint,
            "completed_node_ids": completed,
            "running_node_ids": running,
            "failed_node_ids": failed,
            "observation_ids": observation_ids,
        }
        checkpoint = cls(
            checkpoint_id="ckpt:" + _sha(identity).split(":", 1)[1][:32],
            status=normalized,
            task_id=plan.task_id,
            plan_id=plan.plan_id,
            plan_fingerprint=plan.fingerprint,
            compiled_plan_fingerprint=compiled_plan.fingerprint,
            authority_fingerprint=plan.authority_fingerprint,
            registry_fingerprint=compiled_plan.registry_fingerprint,
            completed_node_ids=completed,
            running_node_ids=running,
            failed_node_ids=failed,
            observation_ids=observation_ids,
        )
        return checkpoint.validate(compiled_plan)

    @classmethod
    def from_metadata(cls, payload: Any) -> "RuntimeCheckpoint":
        if not isinstance(payload, dict) or payload.get("schema_version") != RUNTIME_CHECKPOINT_SCHEMA:
            raise RuntimeCheckpointError("CHECKPOINT_PAYLOAD_INVALID")
        try:
            return cls(
                checkpoint_id=str(payload["checkpoint_id"]),
                status=str(payload["status"]),
                task_id=str(payload["task_id"]),
                plan_id=str(payload["plan_id"]),
                plan_fingerprint=str(payload["plan_fingerprint"]),
                compiled_plan_fingerprint=str(payload["compiled_plan_fingerprint"]),
                authority_fingerprint=str(payload["authority_fingerprint"]),
                registry_fingerprint=str(payload["registry_fingerprint"]),
                completed_node_ids=_payload_ids(payload, "completed_node_ids"),
                running_node_ids=_payload_ids(payload, "running_node_ids"),
                failed_node_ids=_payload_ids(payload, "failed_node_ids"),
                observation_ids=_payload_ids(payload, "observation_ids"),
            )
        except (KeyError, TypeError) as exc:
            raise RuntimeCheckpointError("CHECKPOINT_PAYLOAD_INVALID") from exc

    def _identity(self) -> dict[str, object]:
        data = self.metadata()
        data.pop("checkpoint_id", None)
        return data

    def validate(self, compiled_plan: CompiledRuntimePlan) -> "RuntimeCheckpoint":
        plan = compiled_plan.plan
        checks = (
            (self.schema_version == RUNTIME_CHECKPOINT_SCHEMA, "CHECKPOINT_SCHEMA_UNSUPPORTED"),
            (self.status in _STATUSES, "CHECKPOINT_STATUS_INVALID"),
            (self.task_id == plan.task_id, "CHECKPOINT_TASK_MISMATCH"),
            (self.plan_id == plan.plan_id, "CHECKPOINT_PLAN_ID_MISMATCH"),
            (self.plan_fingerprint == plan.fingerprint, "CHECKPOINT_PLAN_CHANGED"),
            (self.compiled_plan_fingerprint == compiled_plan.fingerprint, "CHECKPOINT_COMPILED_PLAN_CHANGED"),
            (self.authority_fingerprint == plan.authority_fingerprint, "CHECKPOINT_AUTHORITY_CHANGED"),
            (self.registry_fingerprint == compiled_plan.registry_fingerprint, "CHECKPOINT_REGISTRY_CHANGED"),
        )
        for valid, code in checks:
            if not valid:
                raise RuntimeCheckpointError(code)
        expected = "ckpt:" + _sha(self._identity()).split(":", 1)[1][:32]
        if self.checkpoint_id != expected:
            raise RuntimeCheckpointError("CHECKPOINT_ID_INTEGRITY_MISMATCH")

        by_id = {n.node_id: n for n in plan.nodes}
        known = set(by_id)
        completed = set(self.completed_node_ids)
        running = set(self.running_node_ids)
        failed = set(self.failed_node_ids)
        if not completed.issubset(known) or not running.issubset(known) or not failed.issubset(known):
            raise RuntimeCheckpointError("CHECKPOINT_CONTAINS_UNKNOWN_NODE")
        if completed & running or completed & failed or running & failed:
            raise RuntimeCheckpointError("CHECKPOINT_NODE_STATE_CONFLICT")
        if any(not _OBS_ID_RE.fullmatch(v) for v in self.observation_ids):
            raise RuntimeCheckpointError("CHECKPOINT_OBSERVATION_ID_INVALID")
        for node_id in completed | running | failed:
            if not set(by_id[node_id].depends_on).issubset(completed):
                raise RuntimeCheckpointError("CHECKPOINT_DEPENDENCY_STATE_INVALID")
        if self.status == "completed" and (completed != known or running or failed):
            raise RuntimeCheckpointError("CHECKPOINT_COMPLETED_STATE_INVALID")
        if self.status == "failed" and (not failed or running):
            raise RuntimeCheckpointError("CHECKPOINT_FAILED_STATE_INVALID")
        if self.status == "running" and (not running or failed):
            raise RuntimeCheckpointError("CHECKPOINT_RUNNING_STATE_INVALID")
        if self.status in {"ready", "blocked"} and (running or failed):
            raise RuntimeCheckpointError("CHECKPOINT_QUIESCENT_STATE_INVALID")
        if self.status == "blocked" and completed == known:
            raise RuntimeCheckpointError("CHECKPOINT_BLOCKED_STATE_INVALID")
        return self

    def metadata(self) -> dict[str, object]:
        payload = asdict(self)
        for field in ("completed_node_ids", "running_node_ids", "failed_node_ids", "observation_ids"):
            payload[field] = list(payload[field])
        return payload


class RuntimeCheckpointStore:
    """Atomic metadata-only checkpoint store for crash-safe recovery decisions."""

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

    def save(self, checkpoint: RuntimeCheckpoint) -> Path:
        payload = checkpoint.metadata()
        envelope = {
            "schema_version": RUNTIME_CHECKPOINT_STORE_SCHEMA,
            "payload_sha256": _sha(payload),
            "checkpoint": payload,
        }
        encoded = (_canonical(envelope) + "\n").encode("utf-8")
        if len(encoded) > _MAX_BYTES:
            raise RuntimeCheckpointError("CHECKPOINT_TOO_LARGE")
        path = self._path(checkpoint.task_id, checkpoint.plan_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp_name: str | None = None
        try:
            with tempfile.NamedTemporaryFile("wb", dir=path.parent, prefix=path.name + ".", suffix=".tmp", delete=False) as handle:
                tmp_name = handle.name
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, path)
            tmp_name = None
            self._fsync_dir(path.parent)
        finally:
            if tmp_name is not None:
                try:
                    os.unlink(tmp_name)
                except FileNotFoundError:
                    pass
        return path

    def load(self, *, compiled_plan: CompiledRuntimePlan) -> RuntimeCheckpoint:
        path = self._path(compiled_plan.plan.task_id, compiled_plan.plan.plan_id)
        if not path.is_file():
            raise RuntimeCheckpointError("CHECKPOINT_NOT_FOUND")
        raw = path.read_bytes()
        if not raw or len(raw) > _MAX_BYTES:
            raise RuntimeCheckpointError("CHECKPOINT_FILE_INVALID")
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeCheckpointError("CHECKPOINT_FILE_INVALID") from exc
        if not isinstance(envelope, dict) or envelope.get("schema_version") != RUNTIME_CHECKPOINT_STORE_SCHEMA:
            raise RuntimeCheckpointError("CHECKPOINT_STORE_SCHEMA_UNSUPPORTED")
        payload = envelope.get("checkpoint")
        if not isinstance(payload, dict) or envelope.get("payload_sha256") != _sha(payload):
            raise RuntimeCheckpointError("CHECKPOINT_FILE_INTEGRITY_MISMATCH")
        return RuntimeCheckpoint.from_metadata(payload).validate(compiled_plan)
