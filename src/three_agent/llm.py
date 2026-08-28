from __future__ import annotations

import json
import re
from typing import Any
from urllib.request import Request, urlopen

from .config import LLMConfig
from .resource_budget import ResourceAdmissionError, ResourceBudgetManager


class LocalLLMError(RuntimeError):
    pass


def _extract_json_object(text: str) -> dict[str, Any]:
    candidate = text.strip()
    if candidate.startswith("```"):
        candidate = re.sub(r"^```(?:json)?\s*", "", candidate, flags=re.IGNORECASE)
        candidate = re.sub(r"\s*```$", "", candidate)
    try:
        parsed = json.loads(candidate)
    except json.JSONDecodeError:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start < 0 or end <= start:
            raise LocalLLMError("Local LLM did not return a JSON object")
        try:
            parsed = json.loads(candidate[start : end + 1])
        except json.JSONDecodeError as exc:
            raise LocalLLMError(f"Local LLM returned invalid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise LocalLLMError("Local LLM JSON response must be an object")
    return parsed


class OllamaClient:
    def __init__(self, config: LLMConfig, resource_manager: ResourceBudgetManager | None = None):
        self.config = config
        self.resource_manager = resource_manager

    def _request(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        json_mode: bool = False,
        think: bool = False,
        num_predict: int = 4096,
    ) -> dict[str, Any]:
        if not self.config.model:
            raise LocalLLMError("LOCAL_LLM_MODEL is empty; set it before a --live run")

        request_body: dict[str, Any] = {
            "model": self.config.model,
            "prompt": f"SYSTEM:\n{system_prompt}\n\nUSER:\n{user_prompt}",
            "stream": False,
            "think": think,
            "keep_alive": self.config.keep_alive,
            "options": {"num_predict": num_predict},
        }
        if json_mode:
            request_body["format"] = "json"

        body = json.dumps(request_body, ensure_ascii=False).encode("utf-8")
        req = Request(
            f"{self.config.base_url}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        def execute() -> dict[str, Any]:
            try:
                with urlopen(req, timeout=self.config.timeout_seconds) as response:
                    payload = json.loads(response.read().decode("utf-8"))
            except Exception as exc:
                raise LocalLLMError(f"Local LLM request failed for model {self.config.model}: {exc}") from exc
            if not isinstance(payload, dict):
                raise LocalLLMError("Local LLM returned an invalid payload")
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

    def _repair_json(
        self,
        malformed_text: str,
        first_error: Exception,
        *,
        num_predict: int,
    ) -> dict[str, Any]:
        candidate = malformed_text[:32000]
        truncated = len(malformed_text) > len(candidate)
        repair_system = (
            "You are a deterministic JSON syntax repair utility. "
            "Return exactly one valid JSON object and nothing else. "
            "Do not add new facts, claims, citations, source IDs, keys, or interpretations. "
            "Preserve complete values from the candidate. If the candidate is truncated or "
            "ends inside an incomplete trailing item, discard only that incomplete trailing item "
            "and close the surrounding JSON arrays/objects correctly."
        )
        repair_prompt = (
            "Repair the JSON syntax of the candidate below.\n"
            f"Parser error: {first_error}\n"
            f"Candidate was externally truncated for repair input: {str(truncated).lower()}\n"
            "--- BEGIN MALFORMED JSON ---\n"
            f"{candidate}\n"
            "--- END MALFORMED JSON ---"
        )
        payload = self._request(
            repair_system,
            repair_prompt,
            json_mode=True,
            think=False,
            num_predict=max(2048, min(num_predict, 6144)),
        )
        repaired_text = self._response_text(payload, structured=True)
        return _extract_json_object(repaired_text)

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        think: bool = False,
        num_predict: int = 4096,
    ) -> str:
        payload = self._request(
            system_prompt,
            user_prompt,
            json_mode=False,
            think=think,
            num_predict=num_predict,
        )
        return self._response_text(payload)

    def generate_json(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        think: bool = False,
        num_predict: int = 4096,
    ) -> dict[str, Any]:
        payload = self._request(
            system_prompt,
            user_prompt,
            json_mode=True,
            think=think,
            num_predict=num_predict,
        )
        text = self._response_text(payload, structured=True)
        try:
            return _extract_json_object(text)
        except LocalLLMError as first_error:
            try:
                return self._repair_json(text, first_error, num_predict=num_predict)
            except Exception as repair_error:
                raise LocalLLMError(
                    "Local LLM returned invalid JSON and the automatic repair retry also failed: "
                    f"first={first_error}; repair={repair_error}"
                ) from repair_error

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
