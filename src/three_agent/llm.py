from __future__ import annotations

import json
import re
from typing import Any
from urllib.request import Request, urlopen

from .config import LLMConfig


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
    def __init__(self, config: LLMConfig):
        self.config = config

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
        try:
            with urlopen(req, timeout=self.config.timeout_seconds) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except Exception as exc:
            raise LocalLLMError(f"Local LLM request failed: {exc}") from exc
        if not isinstance(payload, dict):
            raise LocalLLMError("Local LLM returned an invalid payload")
        return payload

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
        text = payload.get("response")
        if not isinstance(text, str) or not text.strip():
            thinking = payload.get("thinking")
            detail = ""
            if isinstance(thinking, str) and thinking.strip():
                detail = " (model produced thinking output but no final response)"
            raise LocalLLMError(f"Local LLM returned an empty response{detail}")
        return text.strip()

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
        text = payload.get("response")
        if not isinstance(text, str) or not text.strip():
            raise LocalLLMError("Local LLM returned an empty structured response")
        return _extract_json_object(text)
