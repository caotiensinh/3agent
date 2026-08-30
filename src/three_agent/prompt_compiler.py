from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass
from typing import Any

PROMPT_COMPILATION_SCHEMA = "workspace-prompt-compilation/v1"
PROMPT_COMPILER_VERSION = "workspace-prompt-compiler/deterministic-v1"
MAX_PROMPT_CHARS = 256_000

_FENCE_RE = re.compile(r"^\s*(```|~~~)")


class PromptCompilationError(ValueError):
    """The local user prompt cannot be compiled safely."""


@dataclass(frozen=True)
class PromptCompilation:
    """Deterministic, local-only prompt compilation result.

    `compiled_text` is deliberately excluded from `metadata()` so the immutable
    receipt can be persisted without creating another copy of confidential text.
    The original prompt remains authoritative in the local task row.
    """

    compiled_text: str
    original_sha256: str
    compiled_sha256: str
    original_chars: int
    compiled_chars: int
    original_utf8_bytes: int
    compiled_utf8_bytes: int
    duplicate_blocks_removed: int
    repeated_block_occurrences: int
    schema_version: str = PROMPT_COMPILATION_SCHEMA
    compiler_version: str = PROMPT_COMPILER_VERSION

    @property
    def byte_reduction(self) -> int:
        return max(0, self.original_utf8_bytes - self.compiled_utf8_bytes)

    @property
    def byte_reduction_percent(self) -> float:
        if self.original_utf8_bytes <= 0:
            return 0.0
        return round((self.byte_reduction / self.original_utf8_bytes) * 100.0, 3)

    def metadata(self) -> dict[str, Any]:
        payload = asdict(self)
        payload.pop("compiled_text", None)
        payload["byte_reduction"] = self.byte_reduction
        payload["byte_reduction_percent"] = self.byte_reduction_percent
        # Do not turn a byte/character delta into an invented tokenizer claim.
        payload["token_savings_measured"] = False
        payload["raw_prompt_copied_to_receipt"] = False
        return payload


@dataclass(frozen=True)
class _PromptBlock:
    text: str
    fenced: bool


class PromptCompiler:
    """Compile user text conservatively before local model use.

    Security/semantic rules:
    - no LLM is used;
    - credential values are NOT redacted on the local path;
    - fenced code/data blocks are byte-text preserved apart from CRLF -> LF;
    - prose order is preserved;
    - only exact duplicate prose blocks are compacted;
    - repetition emphasis is retained with a short deterministic repeat marker;
    - no user content is promoted to system/developer authority.
    """

    @staticmethod
    def _digest(value: str) -> str:
        return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_newlines(value: str) -> str:
        return value.replace("\r\n", "\n").replace("\r", "\n")

    @classmethod
    def _blocks(cls, value: str) -> list[_PromptBlock]:
        lines = cls._normalize_newlines(value).split("\n")
        blocks: list[_PromptBlock] = []
        current: list[str] = []
        in_fence = False
        fence_token = ""
        current_fenced = False

        def flush() -> None:
            nonlocal current, current_fenced
            if not current:
                return
            text = "\n".join(current)
            if not current_fenced:
                text = "\n".join(line.rstrip() for line in current).strip()
            if text:
                blocks.append(_PromptBlock(text=text, fenced=current_fenced))
            current = []
            current_fenced = False

        for line in lines:
            match = _FENCE_RE.match(line)
            if in_fence:
                current.append(line)
                if match and match.group(1) == fence_token:
                    in_fence = False
                    flush()
                continue

            if match:
                flush()
                in_fence = True
                fence_token = match.group(1)
                current_fenced = True
                current.append(line)
                continue

            if not line.strip():
                flush()
                continue
            current.append(line)

        flush()
        return blocks

    @classmethod
    def compile(cls, value: str) -> PromptCompilation:
        original = str(value or "")
        if not original.strip():
            raise PromptCompilationError("User prompt cannot be empty")
        if len(original) > MAX_PROMPT_CHARS:
            raise PromptCompilationError(
                f"User prompt exceeds local compiler limit ({MAX_PROMPT_CHARS} characters)"
            )

        normalized = cls._normalize_newlines(original).strip("\n")
        blocks = cls._blocks(normalized)
        if not blocks:
            raise PromptCompilationError("User prompt contains no usable content")

        counts: dict[str, int] = {}
        for block in blocks:
            if not block.fenced:
                counts[block.text] = counts.get(block.text, 0) + 1

        seen: set[str] = set()
        output: list[str] = []
        duplicate_blocks_removed = 0
        repeated_occurrences = 0
        for block in blocks:
            if block.fenced:
                output.append(block.text)
                continue
            count = counts.get(block.text, 1)
            if block.text in seen:
                duplicate_blocks_removed += 1
                repeated_occurrences += 1
                continue
            seen.add(block.text)
            output.append(block.text)
            if count > 1:
                # Repetition can be emphasis. Preserve that signal without paying
                # the cost of resending the same potentially long paragraph.
                output.append(f"[WORKSPACE_REPEAT identical_block_count={count}]")

        compiled = "\n\n".join(output).strip()
        if not compiled:
            raise PromptCompilationError("Prompt compiler produced empty output")

        original_bytes = len(normalized.encode("utf-8"))
        compiled_bytes = len(compiled.encode("utf-8"))
        # Compilation is an optimization, never an excuse to inflate a short task.
        # If the repeat marker makes the representation larger, keep normalized raw.
        if compiled_bytes >= original_bytes:
            compiled = normalized
            duplicate_blocks_removed = 0
            repeated_occurrences = 0
            compiled_bytes = original_bytes

        return PromptCompilation(
            compiled_text=compiled,
            original_sha256=cls._digest(original),
            compiled_sha256=cls._digest(compiled),
            original_chars=len(original),
            compiled_chars=len(compiled),
            original_utf8_bytes=len(original.encode("utf-8")),
            compiled_utf8_bytes=compiled_bytes,
            duplicate_blocks_removed=duplicate_blocks_removed,
            repeated_block_occurrences=repeated_occurrences,
        )


def compile_prompt_for_task(store: Any, task_id: str) -> PromptCompilation:
    """Recompile local task text and verify any immutable bound receipt."""
    task = store.get_task(task_id)
    result = PromptCompiler.compile(task.request)
    record = store.prompt_compilation_for_task(task_id)
    if record is not None:
        if str(record.get("compiler_version") or "") != result.compiler_version:
            raise PromptCompilationError("Bound prompt compiler version does not match runtime")
        if str(record.get("original_sha256") or "") != result.original_sha256:
            raise PromptCompilationError("Original prompt changed after compilation was bound")
        if str(record.get("compiled_sha256") or "") != result.compiled_sha256:
            raise PromptCompilationError("Compiled prompt digest does not match bound receipt")
    return result
