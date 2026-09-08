from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from .capability_authority import TaskCapabilityAuthority
from .execution_observation import ExecutionObservation, ExecutionObservationError
from .execution_plan import ExecutionPlan, ExecutionPlanError
from .runtime_scheduler import RuntimeScheduler, RuntimeSchedulerError, SchedulingDecision
from .task_context import TaskContext, TaskContextError

RUNTIME_CHECKPOINT_SCHEMA = "workspace-runtime-checkpoint/v1"
RUNTIME_CHECKPOINT_OBSERVATION_REF_SCHEMA = "workspace-runtime-checkpoint-observation-ref/v1"
RUNTIME_CHECKPOINT_ENVELOPE_SCHEMA = "workspace-runtime-checkpoint-envelope/v1"

MAX_CHECKPOINT_OBSERVATIONS = 512
MAX_CHECKPOINT_BYTES = 1024 * 1024

_SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_CHECKPOINT_ID_RE = re.compile(r"^checkpoint:[0-9a-f]{24}$")
_OBSERVATION_ID_RE = re.compile(r"^observation:[0-9a-f]{24}$")
_TERMINAL_OR_PARTIAL = frozenset({"SUCCEEDED", "FAILED", "PARTIAL", "CANCELLED"})


class RuntimeCheckpointError(ValueError):
    """A checkpoint is malformed, stale, corrupted, or not recoverable safely."""


def _canonical_json(payload: Any) -> str:
    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise RuntimeCheckpointError("CHECKPOINT_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _require_sha256(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not _SHA256_RE.fullmatch(value):
        raise RuntimeCheckpointError(f"INVALID_{field_name.upper()}")
    return value


def _timestamp(value: Any, *, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RuntimeCheckpointError(f"INVALID_{field_name.upper()}")
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeCheckpointError(f"INVALID_{field_name.upper()}") from exc
    if parsed.tzinfo is None:
        raise RuntimeCheckpointError(f"INVALID_{field_name.upper()}")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _checkpoint_id(identity: Mapping[str, Any]) -> str:
    return "checkpoint:" + _digest(dict(identity)).split(":", 1)[1][:24]


@dataclass(frozen=True)
class CheckpointObservationRef:
    """Metadata-only pointer to an immutable canonical ExecutionObservation."""

    observation_id: str
    observation_fingerprint: str
    node_id: str
    status: str
    schema_version: str = RUNTIME_CHECKPOINT_OBSERVATION_REF_SCHEMA

    @classmethod
    def from_observation(cls, observation: ExecutionObservation) -> "CheckpointObservationRef":
        if not isinstance(observation, ExecutionObservation):
            raise RuntimeCheckpointError("INVALID_EXECUTION_OBSERVATION")
        observation.validate()
        return cls(
            observation_id=observation.observation_id,
            observation_fingerprint=observation.fingerprint,
            node_id=observation.node_id,
            status=observation.status,
        ).validate()

    @classmethod
    def from_dict(cls, payload: Any) -> "CheckpointObservationRef":
        if not isinstance(payload, dict):
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_OBSERVATION_REF")
        expected = {
            "schema_version",
            "observation_id",
            "observation_fingerprint",
            "node_id",
            "status",
        }
        if set(payload) != expected:
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_OBSERVATION_REF")
        try:
            ref = cls(
                schema_version=payload["schema_version"],
                observation_id=payload["observation_id"],
                observation_fingerprint=payload["observation_fingerprint"],
                node_id=payload["node_id"],
                status=payload["status"],
            )
        except TypeError as exc:
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_OBSERVATION_REF") from exc
        return ref.validate()

    def validate(self) -> "CheckpointObservationRef":
        if self.schema_version != RUNTIME_CHECKPOINT_OBSERVATION_REF_SCHEMA:
            raise RuntimeCheckpointError("CHECKPOINT_OBSERVATION_REF_SCHEMA_MISMATCH")
        if not isinstance(self.observation_id, str) or not _OBSERVATION_ID_RE.fullmatch(
            self.observation_id
        ):
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_OBSERVATION_ID")
        _require_sha256(
            self.observation_fingerprint,
            field_name="observation_fingerprint",
        )
        if (
            not isinstance(self.node_id, str)
            or not self.node_id
            or self.node_id != self.node_id.strip()
            or len(self.node_id) > 256
            or "\n" in self.node_id
            or "\r" in self.node_id
        ):
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_NODE_ID")
        if self.status not in _TERMINAL_OR_PARTIAL:
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_OBSERVATION_STATUS")
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate()
        return {
            "schema_version": self.schema_version,
            "observation_id": self.observation_id,
            "observation_fingerprint": self.observation_fingerprint,
            "node_id": self.node_id,
            "status": self.status,
        }


@dataclass(frozen=True)
class RuntimeCheckpoint:
    """Immutable metadata snapshot pinned to one exact canonical runtime graph."""

    checkpoint_id: str
    task_id: str
    task_context_fingerprint: str
    task_context_identity_fingerprint: str
    plan_fingerprint: str
    authority_fingerprint: str
    observation_refs: tuple[CheckpointObservationRef, ...]
    created_at: str
    previous_checkpoint_fingerprint: str | None = None
    schema_version: str = RUNTIME_CHECKPOINT_SCHEMA

    def _identity_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "task_context_fingerprint": self.task_context_fingerprint,
            "task_context_identity_fingerprint": self.task_context_identity_fingerprint,
            "plan_fingerprint": self.plan_fingerprint,
            "authority_fingerprint": self.authority_fingerprint,
            "observation_refs": [ref.canonical_dict() for ref in self.observation_refs],
            "created_at": self.created_at,
            "previous_checkpoint_fingerprint": self.previous_checkpoint_fingerprint,
        }

    @property
    def fingerprint(self) -> str:
        return _digest(self.canonical_dict())

    def validate(self) -> "RuntimeCheckpoint":
        if self.schema_version != RUNTIME_CHECKPOINT_SCHEMA:
            raise RuntimeCheckpointError("CHECKPOINT_SCHEMA_VERSION_MISMATCH")
        if not isinstance(self.checkpoint_id, str) or not _CHECKPOINT_ID_RE.fullmatch(
            self.checkpoint_id
        ):
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_ID")
        if (
            not isinstance(self.task_id, str)
            or not self.task_id
            or self.task_id != self.task_id.strip()
            or len(self.task_id) > 256
        ):
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_TASK_ID")
        _require_sha256(
            self.task_context_fingerprint,
            field_name="task_context_fingerprint",
        )
        _require_sha256(
            self.task_context_identity_fingerprint,
            field_name="task_context_identity_fingerprint",
        )
        _require_sha256(self.plan_fingerprint, field_name="plan_fingerprint")
        _require_sha256(self.authority_fingerprint, field_name="authority_fingerprint")
        if self.previous_checkpoint_fingerprint is not None:
            _require_sha256(
                self.previous_checkpoint_fingerprint,
                field_name="previous_checkpoint_fingerprint",
            )
        normalized_time = _timestamp(self.created_at, field_name="created_at")
        if normalized_time != self.created_at:
            raise RuntimeCheckpointError("CHECKPOINT_TIMESTAMP_NOT_NORMALIZED")
        if not isinstance(self.observation_refs, tuple):
            raise RuntimeCheckpointError("CHECKPOINT_OBSERVATION_REFS_MUST_BE_TUPLE")
        if len(self.observation_refs) > MAX_CHECKPOINT_OBSERVATIONS:
            raise RuntimeCheckpointError("CHECKPOINT_OBSERVATION_BOUND_EXCEEDED")

        seen_ids: set[str] = set()
        seen_nodes: set[str] = set()
        previous_key: tuple[str, str] | None = None
        for ref in self.observation_refs:
            if not isinstance(ref, CheckpointObservationRef):
                raise RuntimeCheckpointError("INVALID_CHECKPOINT_OBSERVATION_REF")
            ref.validate()
            if ref.observation_id in seen_ids:
                raise RuntimeCheckpointError("DUPLICATE_CHECKPOINT_OBSERVATION_ID")
            if ref.node_id in seen_nodes:
                raise RuntimeCheckpointError("MULTIPLE_CHECKPOINT_OBSERVATIONS_FOR_NODE")
            seen_ids.add(ref.observation_id)
            seen_nodes.add(ref.node_id)
            current_key = (ref.node_id, ref.observation_id)
            if previous_key is not None and current_key < previous_key:
                raise RuntimeCheckpointError("CHECKPOINT_OBSERVATION_REFS_NOT_NORMALIZED")
            previous_key = current_key

        expected_id = _checkpoint_id(self._identity_dict())
        if self.checkpoint_id != expected_id:
            raise RuntimeCheckpointError("CHECKPOINT_IDENTITY_MISMATCH")
        return self

    def validate_bindings(
        self,
        *,
        task_context: TaskContext,
        plan: ExecutionPlan,
        parent_authority: TaskCapabilityAuthority,
    ) -> "RuntimeCheckpoint":
        self.validate()
        if not isinstance(task_context, TaskContext):
            raise RuntimeCheckpointError("INVALID_TASK_CONTEXT")
        if not isinstance(plan, ExecutionPlan):
            raise RuntimeCheckpointError("INVALID_EXECUTION_PLAN")
        if not isinstance(parent_authority, TaskCapabilityAuthority):
            raise RuntimeCheckpointError("INVALID_PARENT_AUTHORITY")
        try:
            task_context.validate()
            plan.validate(parent_authority=parent_authority)
        except (TaskContextError, ExecutionPlanError, ValueError) as exc:
            raise RuntimeCheckpointError("CHECKPOINT_CANONICAL_REVALIDATION_FAILED") from exc

        if self.task_id != task_context.task_id or self.task_id != plan.task_id:
            raise RuntimeCheckpointError("CHECKPOINT_TASK_MISMATCH")
        if self.task_context_fingerprint != task_context.fingerprint:
            raise RuntimeCheckpointError("CHECKPOINT_TASK_CONTEXT_CHANGED")
        if self.task_context_identity_fingerprint != task_context.identity_fingerprint:
            raise RuntimeCheckpointError("CHECKPOINT_TASK_CONTEXT_IDENTITY_CHANGED")
        if self.plan_fingerprint != plan.fingerprint:
            raise RuntimeCheckpointError("CHECKPOINT_PLAN_CHANGED")
        if self.authority_fingerprint != parent_authority.fingerprint:
            raise RuntimeCheckpointError("CHECKPOINT_AUTHORITY_CHANGED")
        if plan.parent_authority_fingerprint != parent_authority.fingerprint:
            raise RuntimeCheckpointError("CHECKPOINT_PLAN_AUTHORITY_CHANGED")

        known_nodes = {node.node_id for node in plan.nodes}
        unknown_nodes = sorted(
            ref.node_id for ref in self.observation_refs if ref.node_id not in known_nodes
        )
        if unknown_nodes:
            raise RuntimeCheckpointError(
                "CHECKPOINT_UNKNOWN_NODE:" + ",".join(unknown_nodes)
            )
        return self

    def canonical_dict(self) -> dict[str, Any]:
        self.validate_shallow_identity_fields()
        return {"checkpoint_id": self.checkpoint_id, **self._identity_dict()}

    def validate_shallow_identity_fields(self) -> None:
        """Validate fields needed to serialize without recursively checking the ID."""
        if self.schema_version != RUNTIME_CHECKPOINT_SCHEMA:
            raise RuntimeCheckpointError("CHECKPOINT_SCHEMA_VERSION_MISMATCH")
        if not isinstance(self.checkpoint_id, str) or not _CHECKPOINT_ID_RE.fullmatch(
            self.checkpoint_id
        ):
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_ID")
        for ref in self.observation_refs:
            if not isinstance(ref, CheckpointObservationRef):
                raise RuntimeCheckpointError("INVALID_CHECKPOINT_OBSERVATION_REF")
            ref.validate()

    @classmethod
    def from_dict(cls, payload: Any) -> "RuntimeCheckpoint":
        if not isinstance(payload, dict):
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_PAYLOAD")
        expected = {
            "schema_version",
            "checkpoint_id",
            "task_id",
            "task_context_fingerprint",
            "task_context_identity_fingerprint",
            "plan_fingerprint",
            "authority_fingerprint",
            "observation_refs",
            "created_at",
            "previous_checkpoint_fingerprint",
        }
        if set(payload) != expected:
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_PAYLOAD")
        raw_refs = payload.get("observation_refs")
        if not isinstance(raw_refs, list):
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_OBSERVATION_REFS")
        try:
            checkpoint = cls(
                schema_version=payload["schema_version"],
                checkpoint_id=payload["checkpoint_id"],
                task_id=payload["task_id"],
                task_context_fingerprint=payload["task_context_fingerprint"],
                task_context_identity_fingerprint=payload[
                    "task_context_identity_fingerprint"
                ],
                plan_fingerprint=payload["plan_fingerprint"],
                authority_fingerprint=payload["authority_fingerprint"],
                observation_refs=tuple(
                    CheckpointObservationRef.from_dict(item) for item in raw_refs
                ),
                created_at=payload["created_at"],
                previous_checkpoint_fingerprint=payload[
                    "previous_checkpoint_fingerprint"
                ],
            )
        except (KeyError, TypeError) as exc:
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_PAYLOAD") from exc
        return checkpoint.validate()


class RuntimeCheckpointBuilder:
    """Capture metadata only; approval input is validated but never persisted."""

    @staticmethod
    def build(
        *,
        task_context: TaskContext,
        plan: ExecutionPlan,
        parent_authority: TaskCapabilityAuthority,
        observations: tuple[ExecutionObservation, ...] = (),
        approved_node_ids: Iterable[str] = (),
        created_at: str,
        previous_checkpoint: RuntimeCheckpoint | None = None,
    ) -> RuntimeCheckpoint:
        if not isinstance(observations, tuple):
            raise RuntimeCheckpointError("OBSERVATIONS_MUST_BE_TUPLE")
        if len(observations) > MAX_CHECKPOINT_OBSERVATIONS:
            raise RuntimeCheckpointError("CHECKPOINT_OBSERVATION_BOUND_EXCEEDED")

        try:
            RuntimeScheduler.evaluate(
                task_context=task_context,
                plan=plan,
                parent_authority=parent_authority,
                observations=observations,
                approved_node_ids=approved_node_ids,
            )
        except RuntimeSchedulerError as exc:
            raise RuntimeCheckpointError("CHECKPOINT_SCHEDULER_REVALIDATION_FAILED") from exc

        refs_by_id: dict[str, CheckpointObservationRef] = {}
        nodes: set[str] = set()
        for observation in observations:
            try:
                observation.validate(plan=plan, parent_authority=parent_authority)
            except ExecutionObservationError as exc:
                raise RuntimeCheckpointError("CHECKPOINT_OBSERVATION_REVALIDATION_FAILED") from exc
            ref = CheckpointObservationRef.from_observation(observation)
            existing = refs_by_id.get(ref.observation_id)
            if existing is not None:
                if existing != ref:
                    raise RuntimeCheckpointError("CHECKPOINT_OBSERVATION_ID_COLLISION")
                continue
            if ref.node_id in nodes:
                raise RuntimeCheckpointError("MULTIPLE_CHECKPOINT_OBSERVATIONS_FOR_NODE")
            refs_by_id[ref.observation_id] = ref
            nodes.add(ref.node_id)

        refs = tuple(sorted(refs_by_id.values(), key=lambda item: (item.node_id, item.observation_id)))
        normalized_created_at = _timestamp(created_at, field_name="created_at")
        previous_fingerprint = None
        if previous_checkpoint is not None:
            if not isinstance(previous_checkpoint, RuntimeCheckpoint):
                raise RuntimeCheckpointError("INVALID_PREVIOUS_CHECKPOINT")
            previous_checkpoint.validate_bindings(
                task_context=task_context,
                plan=plan,
                parent_authority=parent_authority,
            )
            previous_fingerprint = previous_checkpoint.fingerprint

        identity = {
            "schema_version": RUNTIME_CHECKPOINT_SCHEMA,
            "task_id": plan.task_id,
            "task_context_fingerprint": task_context.fingerprint,
            "task_context_identity_fingerprint": task_context.identity_fingerprint,
            "plan_fingerprint": plan.fingerprint,
            "authority_fingerprint": parent_authority.fingerprint,
            "observation_refs": [ref.canonical_dict() for ref in refs],
            "created_at": normalized_created_at,
            "previous_checkpoint_fingerprint": previous_fingerprint,
        }
        checkpoint = RuntimeCheckpoint(
            checkpoint_id=_checkpoint_id(identity),
            task_id=plan.task_id,
            task_context_fingerprint=task_context.fingerprint,
            task_context_identity_fingerprint=task_context.identity_fingerprint,
            plan_fingerprint=plan.fingerprint,
            authority_fingerprint=parent_authority.fingerprint,
            observation_refs=refs,
            created_at=normalized_created_at,
            previous_checkpoint_fingerprint=previous_fingerprint,
        )
        return checkpoint.validate_bindings(
            task_context=task_context,
            plan=plan,
            parent_authority=parent_authority,
        )


class RuntimeCheckpointRecovery:
    """Reconstruct a scheduling decision without replaying unverified work."""

    @staticmethod
    def recover(
        *,
        checkpoint: RuntimeCheckpoint,
        task_context: TaskContext,
        plan: ExecutionPlan,
        parent_authority: TaskCapabilityAuthority,
        observations: tuple[ExecutionObservation, ...],
        approved_node_ids: Iterable[str] = (),
    ) -> SchedulingDecision:
        if not isinstance(checkpoint, RuntimeCheckpoint):
            raise RuntimeCheckpointError("INVALID_RUNTIME_CHECKPOINT")
        checkpoint.validate_bindings(
            task_context=task_context,
            plan=plan,
            parent_authority=parent_authority,
        )
        if not isinstance(observations, tuple):
            raise RuntimeCheckpointError("OBSERVATIONS_MUST_BE_TUPLE")

        supplied: dict[str, ExecutionObservation] = {}
        for observation in observations:
            if not isinstance(observation, ExecutionObservation):
                raise RuntimeCheckpointError("INVALID_EXECUTION_OBSERVATION")
            try:
                observation.validate(plan=plan, parent_authority=parent_authority)
            except ExecutionObservationError as exc:
                raise RuntimeCheckpointError("RECOVERY_OBSERVATION_REVALIDATION_FAILED") from exc
            previous = supplied.get(observation.observation_id)
            if previous is not None and previous.fingerprint != observation.fingerprint:
                raise RuntimeCheckpointError("RECOVERY_OBSERVATION_ID_COLLISION")
            supplied[observation.observation_id] = observation

        recovered: list[ExecutionObservation] = []
        for ref in checkpoint.observation_refs:
            observation = supplied.get(ref.observation_id)
            if observation is None:
                raise RuntimeCheckpointError(
                    "RECOVERY_OBSERVATION_MISSING:" + ref.observation_id
                )
            if observation.fingerprint != ref.observation_fingerprint:
                raise RuntimeCheckpointError(
                    "RECOVERY_OBSERVATION_FINGERPRINT_MISMATCH:" + ref.observation_id
                )
            if observation.node_id != ref.node_id or observation.status != ref.status:
                raise RuntimeCheckpointError(
                    "RECOVERY_OBSERVATION_METADATA_MISMATCH:" + ref.observation_id
                )
            recovered.append(observation)

        try:
            return RuntimeScheduler.evaluate(
                task_context=task_context,
                plan=plan,
                parent_authority=parent_authority,
                observations=tuple(recovered),
                approved_node_ids=approved_node_ids,
            )
        except RuntimeSchedulerError as exc:
            raise RuntimeCheckpointError("RECOVERY_SCHEDULER_REVALIDATION_FAILED") from exc


class RuntimeCheckpointStore:
    """Local atomic integrity-checked checkpoint store with no network behavior."""

    def __init__(self, root: Path | str):
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _key(value: str) -> str:
        return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]

    def _path(self, *, task_id: str, checkpoint_id: str) -> Path:
        if not isinstance(task_id, str) or not task_id:
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_TASK_ID")
        if not isinstance(checkpoint_id, str) or not _CHECKPOINT_ID_RE.fullmatch(checkpoint_id):
            raise RuntimeCheckpointError("INVALID_CHECKPOINT_ID")
        task_dir = self.root / self._key(task_id)
        path = task_dir / (self._key(checkpoint_id) + ".json")
        root_resolved = self.root.resolve()
        parent_resolved = task_dir.resolve()
        if root_resolved != parent_resolved and root_resolved not in parent_resolved.parents:
            raise RuntimeCheckpointError("CHECKPOINT_PATH_ESCAPE")
        return path

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        try:
            descriptor = os.open(path, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    def save(self, checkpoint: RuntimeCheckpoint) -> Path:
        if not isinstance(checkpoint, RuntimeCheckpoint):
            raise RuntimeCheckpointError("INVALID_RUNTIME_CHECKPOINT")
        checkpoint.validate()
        payload = checkpoint.canonical_dict()
        envelope = {
            "schema_version": RUNTIME_CHECKPOINT_ENVELOPE_SCHEMA,
            "checkpoint_fingerprint": checkpoint.fingerprint,
            "checkpoint": payload,
        }
        encoded = (_canonical_json(envelope) + "\n").encode("utf-8")
        if len(encoded) > MAX_CHECKPOINT_BYTES:
            raise RuntimeCheckpointError("CHECKPOINT_TOO_LARGE")

        path = self._path(task_id=checkpoint.task_id, checkpoint_id=checkpoint.checkpoint_id)
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path: str | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                dir=path.parent,
                prefix=".checkpoint-",
                suffix=".tmp",
                delete=False,
            ) as handle:
                temporary_path = handle.name
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_path, path)
            temporary_path = None
            try:
                path.chmod(0o600)
            except OSError:
                pass
            self._fsync_directory(path.parent)
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except FileNotFoundError:
                    pass
        return path

    def load(self, *, task_id: str, checkpoint_id: str) -> RuntimeCheckpoint:
        path = self._path(task_id=task_id, checkpoint_id=checkpoint_id)
        if not path.is_file():
            raise RuntimeCheckpointError("CHECKPOINT_NOT_FOUND")
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise RuntimeCheckpointError("CHECKPOINT_FILE_UNREADABLE") from exc
        if size <= 0 or size > MAX_CHECKPOINT_BYTES:
            raise RuntimeCheckpointError("CHECKPOINT_FILE_INVALID")
        try:
            raw = path.read_bytes()
            envelope = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RuntimeCheckpointError("CHECKPOINT_FILE_INVALID") from exc
        if not isinstance(envelope, dict) or set(envelope) != {
            "schema_version",
            "checkpoint_fingerprint",
            "checkpoint",
        }:
            raise RuntimeCheckpointError("CHECKPOINT_ENVELOPE_INVALID")
        if envelope.get("schema_version") != RUNTIME_CHECKPOINT_ENVELOPE_SCHEMA:
            raise RuntimeCheckpointError("CHECKPOINT_ENVELOPE_SCHEMA_MISMATCH")
        checkpoint = RuntimeCheckpoint.from_dict(envelope.get("checkpoint"))
        if checkpoint.task_id != task_id or checkpoint.checkpoint_id != checkpoint_id:
            raise RuntimeCheckpointError("CHECKPOINT_LOOKUP_MISMATCH")
        if envelope.get("checkpoint_fingerprint") != checkpoint.fingerprint:
            raise RuntimeCheckpointError("CHECKPOINT_FILE_INTEGRITY_MISMATCH")
        return checkpoint
