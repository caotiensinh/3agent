from __future__ import annotations

from pathlib import Path

from ..llm import OllamaClient


class BaseAgent:
    agent_id = "base"
    profile_file = ""

    def __init__(self, profile_root: Path, llm: OllamaClient):
        self.profile_root = Path(profile_root)
        self.llm = llm

    def profile(self) -> str:
        return (self.profile_root / self.profile_file).read_text(encoding="utf-8")
