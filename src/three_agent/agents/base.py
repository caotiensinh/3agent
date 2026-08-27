from __future__ import annotations

from pathlib import Path

from ..llm import OllamaClient
from ..skills import ApprovedSkillLoader


class BaseAgent:
    agent_id = "base"
    profile_file = ""
    skill_names: tuple[str, ...] = ()

    def __init__(self, profile_root: Path, llm: OllamaClient):
        self.profile_root = Path(profile_root)
        self.llm = llm
        self.skill_loader = ApprovedSkillLoader(self.profile_root.parent / "skills")

    def profile(self) -> str:
        base = (self.profile_root / self.profile_file).read_text(encoding="utf-8").rstrip()
        if not self.skill_names:
            return base
        blocks = self.skill_loader.load_for_agent(self.agent_id, self.skill_names)
        if not blocks:
            return base
        return base + "\n\n# Approved local skills\n\n" + "\n\n".join(blocks)
