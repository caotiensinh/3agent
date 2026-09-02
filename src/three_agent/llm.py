from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.request import Request, urlopen

from .config import LLMConfig
from .resource_budget import ResourceAdmissionError, ResourceBudgetManager
from .runtime_efficiency import (
    DEFAULT_OBJECT_SCHEMA,
    InferenceTelemetryRecorder,
    StructuredOutputValidationError,
    build_prompt_envelope,
    schema_fingerprint,
    telemetry_recorder_from_env,
    validate_json_schema_subset,
)


class LocalLLMError(RuntimeError):
    pass


_OLLAMA_GRAMMAR_INCOMPATIBLE_LIMIT_KEYS = frozenset(
    {"minLength", "maxLength", "minItems", "maxItems"}
)
_THINK_BLOCK_RE = re.compile(
    r"<think(?:\s[^>]*)?>.*?</think\s*>",
    flags=re.IGNORECASE | re.DOTALL,
)
_THINK_TAG_RE = re.compile(r"</?think(?:\s[^>]*)?>", flags=re.IGNORECASE)
_JSON_FENCE_RE = re.compile(
    r"```(?P<label>[A-Za-z0-9_+./-]*)[ \t]*\r?\n(?P<body>.*?)```",
    flags=re.DOTALL,
)
_JSON_FENCE_LABELS = frozenset({"json", "application/json"})


def _ollama_transport_schema(schema: dict[str, Any]) -> dict[str, Any]:
    """Return an Ollama-grammar-compatible copy of an authoritative schema.

    Hardware evidence on Ollama 0.33.1 shows that the research synthesis schema
    fails grammar compilation when JSON-Schema string/array length constraints
    are embedded in the decoder grammar. Those constraints remain authoritative:
    they are stripped only from the transport copy and are still enforced by
    ``validate_json_schema_subset`` against the original schema after decoding.

    No required property, type, enum, additionalProperties rule, or nested shape
    is removed here. The input object is never mutated.
    """

    def sanitize(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: sanitize(item)
                for key, item in value.items()
                if key not in _OLLAMA_GRAMMAR_INCOMPATIBLE_LIMIT_KEYS
            }
        if isinstance(value, list):
            return [sanitize(item) for item in value]
        return value

    return sanitize(schema)


def _parse_json_object_exact(candidate: str) -> dict[str, Any]:
    parsed = json.loads(candidate.strip())
    if not isinstance(parsed, dict):
        raise LocalLLMError("Local LLM JSON response must be an object")
    return parsed


def _balanced_json_object_candidates(text: str):
    """Yield lexical top-level object spans without descending into bad outers.

    This deliberately does not repair JSON. The scanner only finds balanced
    object-shaped spans while respecting JSON string escaping; ``json.loads``
    remains the authority on whether each span is valid JSON.
    """

    start: int | None = None
    depth = 0
    in_string = False
    escaped = False

    for index, char in enumerate(text):
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                yield text[start : index + 1]
                start = None


def _valid_json_objects_from_text(text: str) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    for candidate in _balanced_json_object_candidates(text):
        try:
            parsed = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            objects.append(parsed)
    return objects


def _extract_json_object(text: str) -> dict[str, Any]:
    """Extract one deterministic JSON object from a structured model response.

    Qwen-family models can emit complete ``<think>`` wrappers or Markdown around
    an otherwise valid structured response. Those wrappers are treated as
    transport noise, not as authority to repair or reinterpret malformed JSON.
    Multiple valid final objects are rejected as ambiguous.
    """

    candidate = text.strip()
    try:
        return _parse_json_object_exact(candidate)
    except json.JSONDecodeError:
        pass

    cleaned = _THINK_BLOCK_RE.sub("", candidate).strip()
    if _THINK_TAG_RE.search(cleaned):
        raise LocalLLMError("Local LLM returned an unterminated thinking wrapper")

    if cleaned != candidate:
        try:
            return _parse_json_object_exact(cleaned)
        except json.JSONDecodeError:
            pass

    fence_matches = list(_JSON_FENCE_RE.finditer(cleaned))
    json_fenced_objects: list[dict[str, Any]] = []
    for match in fence_matches:
        label = match.group("label").strip().lower()
        if label not in _JSON_FENCE_LABELS:
            continue
        try:
            parsed = _parse_json_object_exact(match.group("body"))
        except (json.JSONDecodeError, LocalLLMError):
            continue
        json_fenced_objects.append(parsed)

    if len(json_fenced_objects) > 1:
        raise LocalLLMError("Local LLM returned multiple JSON objects")
    if json_fenced_objects:
        return json_fenced_objects[0]

    if len(fence_matches) == 1:
        match = fence_matches[0]
        label = match.group("label").strip().lower()
        if (
            match.start() == 0
            and match.end() == len(cleaned)
            and label in {"", *_JSON_FENCE_LABELS}
        ):
            try:
                return _parse_json_object_exact(match.group("body"))
            except json.JSONDecodeError:
                pass

    had_object_start = "{" in cleaned
    prose_only = _JSON_FENCE_RE.sub(" ", cleaned)
    objects = _valid_json_objects_from_text(prose_only)
    if len(objects) > 1:
        raise LocalLLMError("Local LLM returned multiple JSON objects")
    if objects:
        return objects[0]

    if had_object_start:
        raise LocalLLMError("Local LLM returned invalid JSON")
    raise LocalLLMError("Local LLM did not return a JSON object")


class OllamaClient:
    def __init__(
        self,
        config: LLMConfig,
        resource_manager: ResourceBudgetManager | None = None,
        telemetry: InferenceTelemetryRecorder | None = None,
    ):
        self.config = config
        self.resource_manager = resource_manager
        self.telemetry = telemetry or telemetry_recorder_from_env()

    def _request(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        json_mode: bool = False,
        format_schema: dict[str, Any] | None = None,
        schema_id: str | None = None,
        think: bool = False,
        num_predict: int = 4096,
        temperature: float | None = None,
        trust_domain: str = "workspace-local",
        template_version: str = "workspace.prompt.v1",
    ) -> dict[str, Any]:
        if not self.config.model:
            raise LocalLLMError("LOCAL_LLM_MODEL is empty; set it before a --live run")

        envelope = build_prompt_envelope(
            system_prompt,
            user_prompt,
            template_version=template_version,
            trust_domain=trust_domain,
        )
        request_body: dict[str, Any] = {
            "model": self.config.model,
            "prompt": envelope.text,
            "stream": False,
            "think": think,
            "keep_alive": self.config.keep_alive,
            "options": {"num_predict": num_predict},
        }
        if temperature is not None:
            request_body["options"]["temperature"] = float(temperature)
        if json_mode:
            authoritative_schema = format_schema or DEFAULT_OBJECT_SCHEMA
            request_body["format"] = _ollama_transport_schema(authoritative_schema)
            # Ollama recommends a low temperature for deterministic structured output.
            request_body["options"]["temperature"] = 0

        body = json.dumps(request_body, ensure_ascii=False).encode("utf-8")
        req = Request(
            f"{self.config.base_url}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        def execute() -> dict[str, Any]:
            started = time.monotonic()
            try:
                with urlopen(req, timeout=self.config.timeout_seconds) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            except Exception as exc:
                if self.telemetry is not None:
                    self.telemetry.record(
                        model=self.config.model,
                        envelope=envelope,
                        structured=json_mode,
                        schema_id=schema_id,
                        payload=None,
                        success=False,
                        wall_duration_ms=(time.monotonic() - started) * 1000.0,
                        error_type=type(exc).__name__,
                    )
                raise LocalLLMError(f"Local LLM request failed for model {self.config.model}: {exc}") from exc
            if not isinstance(payload, dict):
                if self.telemetry is not None:
                    self.telemetry.record(
                        model=self.config.model,
                        envelope=envelope,
                        structured=json_mode,
                        schema_id=schema_id,
                        payload=None,
                        success=False,
                        wall_duration_ms=(time.monotonic() - started) * 1000.0,
                        error_type="InvalidPayload",
                    )
                raise LocalLLMError("Local LLM returned an invalid payload")
            if self.telemetry is not None:
                self.telemetry.record(
                    model=self.config.model,
                    envelope=envelope,
                    structured=json_mode,
                    schema_id=schema_id,
                    payload=payload,
                    success=True,
                    wall_duration_ms=(time.monotonic() - started) * 1000.0,
                )
            return payload

        if self.resource_manager is None:
            return execute()
        try:
            with self.resource_manager.admit(self.config.model):
                return execute()
        except ResourceAdmissionError:
            raise

    @staticmethod
    def _response_text(payload: dict[str, Any], *, structured: bool = False) -> str:
        text = payload.get("response")
        if not isinstance(text, str) or not text.strip():
            if structured:
                raise LocalLLMError("Local LLM returned an empty structured response")
            thinking = payload.get("thinking")
            detail = ""
            if isinstance(thinking, str) and thinking.strip():
                detail = " (model produced thinking output but no final response)"
            raise LocalLLMError(f"Local LLM returned an empty response{detail}")
        return text.strip()

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        think: bool = False,
        num_predict: int = 4096,
        temperature: float | None = None,
        trust_domain: str = "workspace-local",
        template_version: str = "workspace.prompt.v1",
    ) -> str:
        payload = self._request(
            system_prompt,
            user_prompt,
            json_mode=False,
            think=think,
            num_predict=num_predict,
            temperature=temperature,
            trust_domain=trust_domain,
            template_version=template_version,
        )
        return self._response_text(payload)

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        schema: dict[str, Any] | None = None,
        schema_id: str | None = None,
        think: bool = False,
        num_predict: int = 4096,
        trust_domain: str = "workspace-local",
        template_version: str = "workspace.prompt.v1",
    ) -> dict[str, Any]:
        """Generate one schema-constrained JSON object with no model-based repair retry.

        A generic object schema is used when the caller has not yet supplied a
        task-specific schema. Callers can progressively tighten the contract
        without changing the transport API.
        """

        effective_schema = schema or DEFAULT_OBJECT_SCHEMA
        effective_schema_id = schema_id or f"sha256:{schema_fingerprint(effective_schema)}"
        payload = self._request(
            system_prompt,
            user_prompt,
            json_mode=True,
            format_schema=effective_schema,
            schema_id=effective_schema_id,
            think=think,
            num_predict=num_predict,
            trust_domain=trust_domain,
            template_version=template_version,
        )
        text = self._response_text(payload, structured=True)
        parsed = _extract_json_object(text)
        try:
            validate_json_schema_subset(parsed, effective_schema)
        except StructuredOutputValidationError as exc:
            raise LocalLLMError(f"Local LLM structured response failed deterministic validation: {exc}") from exc
        return parsed

    def unload(self) -> None:
        """Ask Ollama to release this model from VRAM without generating output."""
        if not self.config.model:
            return
        body = json.dumps(
            {"model": self.config.model, "prompt": "", "stream": False, "keep_alive": 0},
            ensure_ascii=False,
        ).encode("utf-8")
        req = Request(
            f"{self.config.base_url}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urlopen(req, timeout=min(self.config.timeout_seconds, 60)) as response:
                response.read()
        except Exception:
            # Lifecycle cleanup must never turn a completed agent stage into a failure.
            return


class AdaptiveOllamaClient:
    """Role-scoped model client with bounded deep-model escalation.

    ResourceAdmissionError is deliberately not treated as an LLM failure: when
    the resource manager says a candidate would exceed the safe budget, the
    router must not retry with a larger model and make resource pressure worse.
    """

    def __init__(
        self,
        primary: OllamaClient,
        *,
        deep: OllamaClient | None = None,
        deep_escalation: bool = True,
        deep_prompt_chars: int = 14000,
        role: str = "general",
    ):
        self.primary = primary
        self.deep = deep
        self.deep_escalation = deep_escalation
        self.deep_prompt_chars = max(2000, deep_prompt_chars)
        self.role = role
        self.config = primary.config

    def _deep_is_distinct(self) -> bool:
        return bool(
            self.deep
            and self.deep.config.model
            and self.deep.config.model != self.primary.config.model
        )

    def _prefer_deep(self, user_prompt: str) -> bool:
        return (
            self.role == "research"
            and self.deep_escalation
            and self._deep_is_distinct()
            and len(user_prompt) >= self.deep_prompt_chars
        )

    def _call(self, method: str, system_prompt: str, user_prompt: str, **kwargs):
        primary_method = getattr(self.primary, method)
        deep_method = getattr(self.deep, method) if self.deep else None

        if self._prefer_deep(user_prompt) and deep_method is not None:
            try:
                return deep_method(system_prompt, user_prompt, **kwargs)
            except ResourceAdmissionError:
                # A deep model that cannot fit may fall back to the smaller primary.
                return primary_method(system_prompt, user_prompt, **kwargs)
            except LocalLLMError:
                return primary_method(system_prompt, user_prompt, **kwargs)

        try:
            return primary_method(system_prompt, user_prompt, **kwargs)
        except ResourceAdmissionError:
            # Never escalate a resource-budget denial to a potentially larger model.
            raise
        except LocalLLMError:
            if self.deep_escalation and self._deep_is_distinct() and deep_method is not None:
                return deep_method(system_prompt, user_prompt, **kwargs)
            raise

    def generate(self, system_prompt: str, user_prompt: str, **kwargs) -> str:
        return self._call("generate", system_prompt, user_prompt, **kwargs)

    def generate_json(self, system_prompt: str, user_prompt: str, **kwargs) -> dict[str, Any]:
        return self._call("generate_json", system_prompt, user_prompt, **kwargs)

    def unload(self) -> None:
        # Explicit unload remains available to workflow stages, but it is no
        # longer required after every stage. Residency is governed by budget.
        self.primary.unload()
        if self._deep_is_distinct() and self.deep is not None:
            self.deep.unload()
