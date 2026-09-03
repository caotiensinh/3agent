from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any

from .harness_checkpoint import HarnessCheckpoint, HarnessCheckpointError
from .harness_context_compiler import (
    CompiledContext,
    ContextCandidate,
    ContextCompilePolicy,
    ContextCompiler,
    ContextCompilerError,
)
from .harness_context_manifest import ContextSectionInput

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ContextRehydrationError(ValueError):
    """A rehydration source, scope, or reconstruction invariant failed."""


def _compact_id(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ContextRehydrationError(f"INVALID_{field_name.upper()}")
    if not _ID_RE.fullmatch(value):
        raise ContextRehydrationError(f"INVALID_{field_name.upper()}")
    return value


def _single_line(value: Any, field_name: str, *, max_len: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ContextRehydrationError(f"INVALID_{field_name.upper()}")
    if len(value) > max_len or "\n" in value or "\r" in value:
        raise ContextRehydrationError(f"INVALID_{field_name.upper()}")
    return value


def _positive_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ContextRehydrationError(f"INVALID_{field_name.upper()}")
    return value


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
        raise ContextRehydrationError("REHYDRATION_NOT_CANONICAL_JSON") from exc


def _anchor_id(checkpoint_id: str) -> str:
    suffix = hashlib.sha256(checkpoint_id.encode("utf-8")).hexdigest()[:24]
    return f"rehydration-anchor:{suffix}"


@dataclass(frozen=True)
class ScopedContextCandidate:
    """One context candidate plus the scope in which it was retrieved."""

    project_id: str
    candidate: ContextCandidate
    conversation_id: str | None = None
    task_id: str | None = None

    def validate(self) -> "ScopedContextCandidate":
        _compact_id(self.project_id, "project_id")
        if self.conversation_id is not None:
            _compact_id(self.conversation_id, "conversation_id")
        if self.task_id is not None:
            _compact_id(self.task_id, "task_id")
        if not isinstance(self.candidate, ContextCandidate):
            raise ContextRehydrationError("INVALID_SCOPED_CONTEXT_CANDIDATE")
        try:
            self.candidate.validate()
        except ContextCompilerError as exc:
            raise ContextRehydrationError("INVALID_SCOPED_CONTEXT_CANDIDATE") from exc
        return self

    def validate_for(self, checkpoint: HarnessCheckpoint) -> "ScopedContextCandidate":
        self.validate()
        if self.project_id != checkpoint.project_id:
            raise ContextRehydrationError("REHYDRATION_PROJECT_SCOPE_MISMATCH")
        if (
            self.conversation_id is not None
            and self.conversation_id != checkpoint.conversation_id
        ):
            raise ContextRehydrationError("REHYDRATION_CONVERSATION_SCOPE_MISMATCH")
        if self.task_id is not None and self.task_id != checkpoint.task_id:
            raise ContextRehydrationError("REHYDRATION_TASK_SCOPE_MISMATCH")
        return self


@dataclass(frozen=True)
class RehydratedContext:
    checkpoint_id: str
    compiled: CompiledContext
    resolved_source_refs: tuple[str, ...]
    checkpoint_source_ref_count: int

    def validate(self) -> "RehydratedContext":
        _compact_id(self.checkpoint_id, "checkpoint_id")
        if not isinstance(self.compiled, CompiledContext):
            raise ContextRehydrationError("INVALID_COMPILED_REHYDRATION_CONTEXT")
        try:
            self.compiled.validate()
        except ContextCompilerError as exc:
            raise ContextRehydrationError("INVALID_COMPILED_REHYDRATION_CONTEXT") from exc
        if not isinstance(self.resolved_source_refs, tuple):
            raise ContextRehydrationError("RESOLVED_SOURCE_REFS_MUST_BE_TUPLE")
        for ref in self.resolved_source_refs:
            _single_line(ref, "resolved_source_ref", max_len=2048)
        if len(set(self.resolved_source_refs)) != len(self.resolved_source_refs):
            raise ContextRehydrationError("DUPLICATE_RESOLVED_SOURCE_REF")
        if (
            not isinstance(self.checkpoint_source_ref_count, int)
            or isinstance(self.checkpoint_source_ref_count, bool)
            or self.checkpoint_source_ref_count <= 0
        ):
            raise ContextRehydrationError("INVALID_CHECKPOINT_SOURCE_REF_COUNT")
        return self

    @property
    def source_coverage(self) -> float:
        self.validate()
        return 1.0

    def manifest_sections(self) -> tuple[ContextSectionInput, ...]:
        self.validate()
        return self.compiled.manifest_sections()


class ContextRehydrator:
    """Rebuild a bounded working context from a verified checkpoint and scoped sources.

    Scope admission happens before token-budget compaction. Project scope is exact.
    Conversation/task scope may be broader only when the source explicitly declares
    itself project-wide by leaving the narrower field unset.
    """

    @staticmethod
    def rehydrate(
        *,
        checkpoint: HarnessCheckpoint,
        checkpoint_token_count: int,
        scoped_candidates: tuple[ScopedContextCandidate, ...],
        resolved_source_refs: tuple[str, ...],
        policy: ContextCompilePolicy,
    ) -> RehydratedContext:
        if not isinstance(checkpoint, HarnessCheckpoint):
            raise ContextRehydrationError("INVALID_REHYDRATION_CHECKPOINT")
        try:
            checkpoint.validate()
        except HarnessCheckpointError as exc:
            raise ContextRehydrationError("INVALID_REHYDRATION_CHECKPOINT") from exc
        checkpoint_tokens = _positive_int(
            checkpoint_token_count,
            "checkpoint_token_count",
        )
        if not isinstance(scoped_candidates, tuple):
            raise ContextRehydrationError("SCOPED_CONTEXT_CANDIDATES_MUST_BE_TUPLE")
        if not isinstance(resolved_source_refs, tuple):
            raise ContextRehydrationError("RESOLVED_SOURCE_REFS_MUST_BE_TUPLE")
        for ref in resolved_source_refs:
            _single_line(ref, "resolved_source_ref", max_len=2048)
        if len(set(resolved_source_refs)) != len(resolved_source_refs):
            raise ContextRehydrationError("DUPLICATE_RESOLVED_SOURCE_REF")

        required_refs = set(checkpoint.source_refs)
        resolved_refs = set(resolved_source_refs)
        missing = required_refs - resolved_refs
        if missing:
            raise ContextRehydrationError("REHYDRATION_SOURCE_POINTER_UNRESOLVED")

        admitted: list[ContextCandidate] = []
        for scoped in scoped_candidates:
            if not isinstance(scoped, ScopedContextCandidate):
                raise ContextRehydrationError("INVALID_SCOPED_CONTEXT_CANDIDATE")
            scoped.validate_for(checkpoint)
            admitted.append(scoped.candidate)

        checkpoint_payload = {
            "checkpoint_id": checkpoint.checkpoint_id,
            "goal": checkpoint.goal,
            "current_state": checkpoint.current_state,
            "completed": list(checkpoint.completed),
            "open_tasks": list(checkpoint.open_tasks),
            "decisions": list(checkpoint.decisions),
            "constraints": list(checkpoint.constraints),
            "known_failures": list(checkpoint.known_failures),
            "important_entities": list(checkpoint.important_entities),
            "latest_evidence": list(checkpoint.latest_evidence),
            "next_action": checkpoint.next_action,
            "source_refs": list(checkpoint.source_refs),
            "checkpoint_hash": checkpoint.fingerprint,
        }
        anchor = ContextCandidate(
            item_id=_anchor_id(checkpoint.checkpoint_id),
            section_type="checkpoint",
            content=_canonical_json(checkpoint_payload),
            token_count=checkpoint_tokens,
            source_refs=(
                f"checkpoint:{checkpoint.checkpoint_id}",
                *checkpoint.source_refs,
            ),
            priority=100,
            critical=True,
            exact_required=True,
        )

        candidate_ids = {candidate.item_id for candidate in admitted}
        if anchor.item_id in candidate_ids:
            raise ContextRehydrationError("REHYDRATION_ANCHOR_ID_CONFLICT")

        try:
            compiled = ContextCompiler.compile(
                policy=policy,
                candidates=(anchor, *admitted),
            )
        except ContextCompilerError as exc:
            raise ContextRehydrationError(f"REHYDRATION_COMPILE_FAILED:{exc}") from exc

        if anchor.item_id not in {item.item_id for item in compiled.items}:
            raise ContextRehydrationError("REHYDRATION_ANCHOR_DROPPED")

        result = RehydratedContext(
            checkpoint_id=checkpoint.checkpoint_id,
            compiled=compiled,
            resolved_source_refs=resolved_source_refs,
            checkpoint_source_ref_count=len(checkpoint.source_refs),
        )
        result.validate()
        return result
