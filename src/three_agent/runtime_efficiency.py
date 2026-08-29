from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_OBJECT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": True,
}

_ZERO_WIDTH = {"\u200b", "\u200c", "\u200d", "\u2060", "\ufeff"}
_INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("ignore_previous", re.compile(r"(?i)\bignore\s+(all\s+)?previous\s+instructions?\b")),
    ("role_system", re.compile(r"(?i)\bsystem\s*:\s*")),
    ("role_developer", re.compile(r"(?i)\bdeveloper\s*:\s*")),
    ("identity_override", re.compile(r"(?i)\byou\s+are\s+now\b")),
    ("instruction_bypass", re.compile(r"(?i)\bdo\s+not\s+follow\s+(the\s+)?(system|developer|user)\b")),
)


class StructuredOutputValidationError(ValueError):
    """A decoded value violates the deterministic JSON-schema subset."""


@dataclass(frozen=True)
class PromptEnvelope:
    """Stable-prefix prompt representation used for reuse telemetry.

    The rendered text is intentionally byte-compatible with the legacy prompt
    format. Only the bookkeeping changes: the static system/tool prefix is
    separated from the request-specific suffix so repeated-prefix opportunity can
    be measured without retaining raw prompt content.
    """

    stable_prefix: str
    dynamic_suffix: str
    template_version: str
    trust_domain: str

    @property
    def text(self) -> str:
        return self.stable_prefix + self.dynamic_suffix

    @property
    def prefix_sha256(self) -> str:
        return hashlib.sha256(self.stable_prefix.encode("utf-8")).hexdigest()

    def metadata(self) -> dict[str, Any]:
        return {
            "template_version": self.template_version,
            "trust_domain": self.trust_domain,
            "prefix_sha256": f"sha256:{self.prefix_sha256}",
            "stable_prefix_chars": len(self.stable_prefix),
            "stable_prefix_bytes": len(self.stable_prefix.encode("utf-8")),
            "dynamic_suffix_chars": len(self.dynamic_suffix),
            "dynamic_suffix_bytes": len(self.dynamic_suffix.encode("utf-8")),
        }


def build_prompt_envelope(
    system_prompt: str,
    user_prompt: str,
    *,
    template_version: str = "workspace.prompt.v1",
    trust_domain: str = "workspace-local",
) -> PromptEnvelope:
    if not template_version.strip():
        raise ValueError("template_version is required")
    if not trust_domain.strip():
        raise ValueError("trust_domain is required")
    # Keep this byte-for-byte equivalent to the historical request body.
    stable_prefix = f"SYSTEM:\n{system_prompt}\n\nUSER:\n"
    return PromptEnvelope(
        stable_prefix=stable_prefix,
        dynamic_suffix=user_prompt,
        template_version=template_version.strip(),
        trust_domain=trust_domain.strip(),
    )


def schema_fingerprint(schema: dict[str, Any]) -> str:
    encoded = json.dumps(
        schema,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "null":
        return value is None
    return True


def validate_json_schema_subset(value: Any, schema: dict[str, Any], path: str = "$") -> None:
    """Validate the JSON-schema features WorkSpace currently emits.

    Ollama performs decoder-time schema enforcement. This local validator is an
    independent deterministic postcondition for the common subset used by the
    project; it deliberately does not pretend to implement the entire JSON Schema
    specification.
    """

    if not isinstance(schema, dict):
        raise StructuredOutputValidationError(f"{path}: schema must be an object")

    if "enum" in schema and value not in schema["enum"]:
        raise StructuredOutputValidationError(f"{path}: value is not in enum")

    expected = schema.get("type")
    if isinstance(expected, list):
        if not any(isinstance(item, str) and _type_matches(value, item) for item in expected):
            raise StructuredOutputValidationError(f"{path}: value does not match allowed types")
    elif isinstance(expected, str) and not _type_matches(value, expected):
        raise StructuredOutputValidationError(f"{path}: expected {expected}")

    if isinstance(value, dict):
        required = schema.get("required", [])
        if isinstance(required, list):
            missing = [name for name in required if isinstance(name, str) and name not in value]
            if missing:
                raise StructuredOutputValidationError(
                    f"{path}: missing required properties: {', '.join(missing)}"
                )
        properties = schema.get("properties", {})
        if isinstance(properties, dict):
            for key, subschema in properties.items():
                if key in value and isinstance(subschema, dict):
                    validate_json_schema_subset(value[key], subschema, f"{path}.{key}")
        if schema.get("additionalProperties") is False and isinstance(properties, dict):
            extra = sorted(set(value) - set(properties))
            if extra:
                raise StructuredOutputValidationError(
                    f"{path}: additional properties are forbidden: {', '.join(extra)}"
                )

    if isinstance(value, list):
        min_items = schema.get("minItems")
        max_items = schema.get("maxItems")
        if isinstance(min_items, int) and len(value) < min_items:
            raise StructuredOutputValidationError(f"{path}: too few array items")
        if isinstance(max_items, int) and len(value) > max_items:
            raise StructuredOutputValidationError(f"{path}: too many array items")
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for index, item in enumerate(value):
                validate_json_schema_subset(item, item_schema, f"{path}[{index}]")

    if isinstance(value, str):
        min_length = schema.get("minLength")
        max_length = schema.get("maxLength")
        if isinstance(min_length, int) and len(value) < min_length:
            raise StructuredOutputValidationError(f"{path}: string is too short")
        if isinstance(max_length, int) and len(value) > max_length:
            raise StructuredOutputValidationError(f"{path}: string is too long")


def _normalize_untrusted_text(text: str) -> tuple[str, str, tuple[str, ...]]:
    original = str(text or "")
    normalized = unicodedata.normalize("NFKC", original)
    hidden_count = sum(normalized.count(ch) for ch in _ZERO_WIDTH)
    for ch in _ZERO_WIDTH:
        normalized = normalized.replace(ch, "")
    normalized = normalized.replace("\x00", "")
    normalized = "".join(
        ch for ch in normalized
        if ch in {"\n", "\r", "\t"} or unicodedata.category(ch) != "Cc"
    )

    signals = [name for name, pattern in _INJECTION_PATTERNS if pattern.search(normalized)]
    if hidden_count:
        signals.append(f"hidden_unicode:{hidden_count}")
    risk = "high" if len(signals) >= 2 or hidden_count >= 8 else ("medium" if signals else "low")
    return normalized, risk, tuple(signals)


def sanitize_untrusted_payload(value: Any) -> tuple[Any, tuple[dict[str, Any], ...]]:
    """Normalize data crossing an agent/retrieval handoff without executing it.

    The function preserves suspicious text as data; it does not obey, remove, or
    reinterpret embedded instructions. Findings are separate machine-readable
    metadata so authorization remains outside the model.
    """

    findings: list[dict[str, Any]] = []

    def walk(item: Any, path: str, depth: int) -> Any:
        if depth > 32:
            raise ValueError("untrusted handoff exceeds maximum nesting depth")
        if isinstance(item, str):
            cleaned, risk, signals = _normalize_untrusted_text(item)
            if risk != "low":
                findings.append({"path": path, "risk": risk, "signals": list(signals)})
            return cleaned
        if isinstance(item, list):
            return [walk(child, f"{path}[{index}]", depth + 1) for index, child in enumerate(item)]
        if isinstance(item, tuple):
            return tuple(walk(child, f"{path}[{index}]", depth + 1) for index, child in enumerate(item))
        if isinstance(item, dict):
            return {
                key: walk(child, f"{path}.{key}", depth + 1)
                for key, child in item.items()
            }
        return item

    return walk(value, "$", 0), tuple(findings)


class InferenceTelemetryRecorder:
    """Metadata-only inference telemetry.

    Raw prompts, model responses, retrieved documents, and tool output are never
    written by this recorder. The prefix hash is sufficient to measure reuse
    opportunity while keeping prompt content out of the audit log.
    """

    def __init__(self, path: Path):
        self.path = Path(path)
        self._lock = threading.Lock()
        self._seen_prefixes: set[tuple[str, str, str]] = set()

    @staticmethod
    def _metric(payload: dict[str, Any] | None, key: str) -> int | None:
        if not isinstance(payload, dict):
            return None
        value = payload.get(key)
        return int(value) if isinstance(value, int) and not isinstance(value, bool) else None

    def record(
        self,
        *,
        model: str,
        envelope: PromptEnvelope,
        structured: bool,
        schema_id: str | None,
        payload: dict[str, Any] | None,
        success: bool,
        wall_duration_ms: float,
        error_type: str | None = None,
    ) -> None:
        prefix_key = (model, envelope.trust_domain, envelope.prefix_sha256)
        with self._lock:
            reuse_candidate = prefix_key in self._seen_prefixes
            self._seen_prefixes.add(prefix_key)
            event = {
                "schema_version": "workspace-inference-telemetry/v1",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "model": model,
                "success": bool(success),
                "error_type": error_type,
                "structured": bool(structured),
                "structured_schema_id": schema_id,
                "prompt": envelope.metadata(),
                "prefix_reuse_candidate": reuse_candidate,
                "usage": {
                    "prompt_eval_count": self._metric(payload, "prompt_eval_count"),
                    "eval_count": self._metric(payload, "eval_count"),
                    "total_duration_ns": self._metric(payload, "total_duration"),
                    "load_duration_ns": self._metric(payload, "load_duration"),
                    "prompt_eval_duration_ns": self._metric(payload, "prompt_eval_duration"),
                    "eval_duration_ns": self._metric(payload, "eval_duration"),
                    "wall_duration_ms": round(max(0.0, wall_duration_ms), 3),
                },
            }
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, ensure_ascii=False, sort_keys=True) + "\n")


_DEFAULT_RECORDER_LOCK = threading.Lock()
_DEFAULT_RECORDERS: dict[str, InferenceTelemetryRecorder] = {}


def telemetry_recorder_from_env() -> InferenceTelemetryRecorder | None:
    """Return one process-wide recorder for the configured metadata log path."""

    configured = os.getenv("WORKSPACE_INFERENCE_TELEMETRY", "").strip()
    if not configured:
        return None
    path = str(Path(configured).expanduser())
    with _DEFAULT_RECORDER_LOCK:
        recorder = _DEFAULT_RECORDERS.get(path)
        if recorder is None:
            recorder = InferenceTelemetryRecorder(Path(path))
            _DEFAULT_RECORDERS[path] = recorder
        return recorder
