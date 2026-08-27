from __future__ import annotations

import json
from urllib.request import Request, urlopen

from .config import LLMConfig


class LocalLLMError(RuntimeError):
    pass


class OllamaClient:
    def __init__(self, config: LLMConfig):
        self.config = config

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        if not self.config.model:
            raise LocalLLMError("LOCAL_LLM_MODEL is empty; set it before a --live run")
        body = json.dumps(
            {
                "model": self.config.model,
                "prompt": f"SYSTEM:\n{system_prompt}\n\nUSER:\n{user_prompt}",
                "stream": False,
            }
        ).encode("utf-8")
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
        text = payload.get("response")
        if not isinstance(text, str) or not text.strip():
            raise LocalLLMError("Local LLM returned an empty response")
        return text.strip()
