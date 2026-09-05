from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from typing import Any

from .harness_context_manifest import CompactionState, ContextSectionInput


class ContextCompilerError(ValueError):
    """Deterministic context compilation or compaction invariant failed."""


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
        raise ContextCompilerError("CONTEXT_COMPILER_NOT_CANONICAL_JSON") from exc


def _digest(payload: Any) -> str:
    return "sha256:" + hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _single_line(value: Any, field_name: str, *, max_len: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ContextCompilerError(f"INVALID_{field_name.upper()}")
    if len(value) > max_len or "\n" in value or "\r" in value:
        raise ContextCompilerError(f"INVALID_{field_name.upper()}")
    return value


def _nonnegative_int(value: Any, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ContextCompilerError(f"INVALID_{field_name.upper()}")
    return value


@dataclass(frozen=True)
class ContextCompilePolicy:
    max_input: int
    reserved_output: int
    soft_threshold: float = 0.60
    hard_threshold: float = 0.80
    emergency_threshold: float = 0.92

    def validate(self) -> "ContextCompilePolicy":
        max_input = _nonnegative_int(self.max_input, "max_input")
        reserved = _nonnegative_int(self.reserved_output, "reserved_output")
        if max_input <= 0:
            raise ContextCompilerError("MAX_INPUT_MUST_BE_POSITIVE")
        if reserved >= max_input:
            raise ContextCompilerError("OUTPUT_RESERVE_EXHAUSTS_CONTEXT")
        for name, value in (
            ("soft_threshold", self.soft_threshold),
            ("hard_threshold", self.hard_threshold),
            ("emergency_threshold", self.emergency_threshold),
        ):
            if (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not 0.0 < float(value) < 1.0
            ):
                raise ContextCompilerError(f"INVALID_{name.upper()}")
        if not (
            float(self.soft_threshold)
            < float(self.hard_threshold)
            < float(self.emergency_threshold)
        ):
            raise ContextCompilerError("INVALID_COMPACTION_THRESHOLD_ORDER")
        return self

    @property
    def input_capacity(self) -> int:
        self.validate()
        return self.max_input - self.reserved_output


@dataclass(frozen=True)
class ContextCandidate:
    item_id: str
    section_type: str
    content: str
    token_count: int
    source_refs: tuple[str, ...]
    priority: int = 50
    critical: bool = False
    derived: bool = False
    obsolete: bool = False
    exact_required: bool = False
    structural_key: str | None = None
    extractive_content: str | None = None
    extractive_token_count: int | None = None

    def validate(self) -> "ContextCandidate":
        _single_line(self.item_id, "item_id", max_len=128)
        _single_line(self.section_type, "section_type", max_len=128)
        if not isinstance(self.content, str) or not self.content.strip():
            raise ContextCompilerError("CONTEXT_CONTENT_REQUIRED")
        tokens = _nonnegative_int(self.token_count, "token_count")
        if tokens <= 0:
            raise ContextCompilerError("TOKEN_COUNT_MUST_BE_POSITIVE")
        priority = _nonnegative_int(self.priority, "priority")
        if priority > 100:
            raise ContextCompilerError("CONTEXT_PRIORITY_OUT_OF_RANGE")
        if not isinstance(self.source_refs, tuple) or not self.source_refs:
            raise ContextCompilerError("CONTEXT_SOURCE_REFS_REQUIRED")
        if len(self.source_refs) > 512:
            raise ContextCompilerError("CONTEXT_SOURCE_REFS_TOO_MANY")
        for ref in self.source_refs:
            _single_line(ref, "source_ref", max_len=2048)
        if len(set(self.source_refs)) != len(self.source_refs):
            raise ContextCompilerError("DUPLICATE_CONTEXT_SOURCE_REF")
        for name, value in (
            ("critical", self.critical),
            ("derived", self.derived),
            ("obsolete", self.obsolete),
            ("exact_required", self.exact_required),
        ):
            if not isinstance(value, bool):
                raise ContextCompilerError(f"INVALID_{name.upper()}")
        if self.critical and self.obsolete:
            raise ContextCompilerError("CRITICAL_CONTEXT_CANNOT_BE_OBSOLETE")
        if self.structural_key is not None:
            _single_line(self.structural_key, "structural_key", max_len=256)
        if (self.extractive_content is None) != (self.extractive_token_count is None):
            raise ContextCompilerError("EXTRACTIVE_PROJECTION_INCOMPLETE")
        if self.extractive_content is not None:
            if not isinstance(self.extractive_content, str) or not self.extractive_content.strip():
                raise ContextCompilerError("EXTRACTIVE_CONTENT_REQUIRED")
            extractive_tokens = _nonnegative_int(
                self.extractive_token_count,
                "extractive_token_count",
            )
            if extractive_tokens <= 0 or extractive_tokens >= self.token_count:
                raise ContextCompilerError("EXTRACTIVE_TOKEN_COUNT_NOT_REDUCED")
        return self

    @property
    def content_hash(self) -> str:
        self.validate()
        return "sha256:" + hashlib.sha256(self.content.encode("utf-8")).hexdigest()

    @property
    def fingerprint(self) -> str:
        self.validate()
        return _digest(
            {
                "item_id": self.item_id,
                "section_type": self.section_type,
                "content_hash": self.content_hash,
                "tokens": self.token_count,
                "source_refs": list(self.source_refs),
                "priority": self.priority,
                "critical": self.critical,
                "derived": self.derived,
                "obsolete": self.obsolete,
                "exact_required": self.exact_required,
                "structural_key": self.structural_key,
            }
        )

    def extractive_projection(self) -> "ContextCandidate":
        self.validate()
        if (
            self.critical
            or self.exact_required
            or self.extractive_content is None
            or self.extractive_token_count is None
        ):
            return self
        return replace(
            self,
            content=self.extractive_content,
            token_count=self.extractive_token_count,
            extractive_content=None,
            extractive_token_count=None,
            derived=True,
        )


@dataclass(frozen=True)
class CompiledContext:
    items: tuple[ContextCandidate, ...]
    dropped_item_ids: tuple[str, ...]
    critical_item_ids: tuple[str, ...]
    raw_tokens: int
    compiled_tokens: int
    input_capacity: int
    compaction_modes: tuple[str, ...]
    checkpoint_required: bool
    rehydration_required: bool
    source_index: tuple[tuple[str, tuple[str, ...]], ...]

    def validate(self) -> "CompiledContext":
        selected_ids = {item.item_id for item in self.items}
        dropped_ids = set(self.dropped_item_ids)
        critical_ids = set(self.critical_item_ids)
        source_ids = {item_id for item_id, _ in self.source_index}
        if len(selected_ids) != len(self.items):
            raise ContextCompilerError("DUPLICATE_COMPILED_CONTEXT_ITEM_ID")
        if len(dropped_ids) != len(self.dropped_item_ids):
            raise ContextCompilerError("DUPLICATE_DROPPED_CONTEXT_ITEM_ID")
        if len(critical_ids) != len(self.critical_item_ids):
            raise ContextCompilerError("DUPLICATE_CRITICAL_CONTEXT_ITEM_ID")
        if selected_ids & dropped_ids:
            raise ContextCompilerError("SELECTED_CONTEXT_MARKED_DROPPED")
        if not critical_ids.issubset(source_ids):
            raise ContextCompilerError("CRITICAL_CONTEXT_SOURCE_MISSING")
        if critical_ids & dropped_ids:
            raise ContextCompilerError("CRITICAL_CONTEXT_DROPPED")
        if not critical_ids.issubset(selected_ids):
            raise ContextCompilerError("CRITICAL_CONTEXT_MISSING")
        if self.compiled_tokens != sum(item.token_count for item in self.items):
            raise ContextCompilerError("COMPILED_CONTEXT_TOKEN_MISMATCH")
        if self.compiled_tokens > self.input_capacity:
            raise ContextCompilerError("COMPILED_CONTEXT_EXCEEDS_CAPACITY")
        if len(set(self.compaction_modes)) != len(self.compaction_modes):
            raise ContextCompilerError("DUPLICATE_COMPACTION_MODE")
        return self

    @property
    def compaction_state(self) -> CompactionState:
        return CompactionState(
            applied=bool(self.compaction_modes),
            modes=self.compaction_modes,
        ).validate()

    def manifest_sections(self) -> tuple[ContextSectionInput, ...]:
        self.validate()
        grouped: dict[str, list[ContextCandidate]] = {}
        section_order: list[str] = []
        for item in self.items:
            if item.section_type not in grouped:
                grouped[item.section_type] = []
                section_order.append(item.section_type)
            grouped[item.section_type].append(item)

        result: list[ContextSectionInput] = []
        for section_type in section_order:
            members = grouped[section_type]
            source_refs: list[str] = []
            for member in members:
                for ref in member.source_refs:
                    if ref not in source_refs:
                        source_refs.append(ref)
            source_hash = _digest(
                [
                    {
                        "item_id": member.item_id,
                        "content_hash": member.content_hash,
                        "tokens": member.token_count,
                    }
                    for member in members
                ]
            )
            result.append(
                ContextSectionInput(
                    section_type=section_type,
                    item_count=len(members),
                    token_count=sum(member.token_count for member in members),
                    source_hash=source_hash,
                    source_refs=tuple(source_refs),
                    critical=any(member.critical for member in members),
                )
            )
        return tuple(result)


class ContextCompiler:
    """Compile caller-tokenized context with deterministic, source-preserving compaction."""

    @staticmethod
    def _structural_compact(
        candidates: tuple[ContextCandidate, ...],
    ) -> tuple[tuple[ContextCandidate, ...], set[str]]:
        dropped: set[str] = set()
        surviving: list[ContextCandidate] = []

        keyed: dict[str, ContextCandidate] = {}
        keyed_index: dict[str, int] = {}
        for index, item in enumerate(candidates):
            if item.derived and item.obsolete and not item.critical:
                dropped.add(item.item_id)
                continue
            if item.critical or item.structural_key is None:
                surviving.append(item)
                continue
            previous = keyed.get(item.structural_key)
            if previous is None:
                keyed[item.structural_key] = item
                keyed_index[item.structural_key] = index
                continue
            winner = sorted(
                (previous, item),
                key=lambda candidate: (
                    -candidate.priority,
                    candidate.token_count,
                    candidate.item_id,
                ),
            )[0]
            loser = item if winner is previous else previous
            dropped.add(loser.item_id)
            keyed[item.structural_key] = winner
            if winner is item:
                keyed_index[item.structural_key] = index

        keyed_items = sorted(
            ((keyed_index[key], candidate) for key, candidate in keyed.items()),
            key=lambda pair: pair[0],
        )
        survivors_with_index: list[tuple[int, ContextCandidate]] = []
        surviving_ids = {item.item_id for item in surviving}
        for index, item in enumerate(candidates):
            if item.item_id in surviving_ids:
                survivors_with_index.append((index, item))
        survivors_with_index.extend(keyed_items)
        survivors_with_index.sort(key=lambda pair: pair[0])
        return tuple(item for _, item in survivors_with_index), dropped

    @staticmethod
    def compile(
        *,
        policy: ContextCompilePolicy,
        candidates: tuple[ContextCandidate, ...],
    ) -> CompiledContext:
        policy.validate()
        if not isinstance(candidates, tuple) or not candidates:
            raise ContextCompilerError("CONTEXT_CANDIDATES_REQUIRED")
        for candidate in candidates:
            if not isinstance(candidate, ContextCandidate):
                raise ContextCompilerError("INVALID_CONTEXT_CANDIDATE")
            candidate.validate()
        ids = [candidate.item_id for candidate in candidates]
        if len(set(ids)) != len(ids):
            raise ContextCompilerError("DUPLICATE_CONTEXT_ITEM_ID")

        critical_item_ids = tuple(candidate.item_id for candidate in candidates if candidate.critical)
        capacity = policy.input_capacity
        raw_tokens = sum(candidate.token_count for candidate in candidates)
        ratio = raw_tokens / capacity
        working = candidates
        dropped: set[str] = set()
        modes: list[str] = []

        if ratio >= policy.soft_threshold:
            working, structural_dropped = ContextCompiler._structural_compact(working)
            dropped.update(structural_dropped)
            modes.append("structural")

        if ratio >= policy.hard_threshold or sum(item.token_count for item in working) > capacity:
            projected: list[ContextCandidate] = []
            used_extractive = False
            for item in working:
                replacement = item.extractive_projection()
                if replacement is not item:
                    used_extractive = True
                projected.append(replacement)
            working = tuple(projected)
            if used_extractive:
                modes.append("extractive")

        critical_tokens = sum(item.token_count for item in working if item.critical)
        if critical_tokens > capacity:
            raise ContextCompilerError("CRITICAL_CONTEXT_EXCEEDS_BUDGET")

        if sum(item.token_count for item in working) > capacity:
            selected_ids = {item.item_id for item in working if item.critical}
            used = critical_tokens
            noncritical = sorted(
                (item for item in working if not item.critical),
                key=lambda item: (-item.priority, item.token_count, item.item_id),
            )
            for item in noncritical:
                if used + item.token_count <= capacity:
                    selected_ids.add(item.item_id)
                    used += item.token_count
                else:
                    dropped.add(item.item_id)
            working = tuple(item for item in working if item.item_id in selected_ids)
            if "structural" not in modes:
                modes.append("structural")

        if set(critical_item_ids) & dropped:
            raise ContextCompilerError("CRITICAL_CONTEXT_DROPPED")

        result = CompiledContext(
            items=working,
            dropped_item_ids=tuple(sorted(dropped)),
            critical_item_ids=critical_item_ids,
            raw_tokens=raw_tokens,
            compiled_tokens=sum(item.token_count for item in working),
            input_capacity=capacity,
            compaction_modes=tuple(modes),
            checkpoint_required=ratio >= policy.hard_threshold,
            rehydration_required=ratio >= policy.emergency_threshold,
            source_index=tuple(
                (candidate.item_id, candidate.source_refs)
                for candidate in candidates
            ),
        )
        result.validate()
        return result
