from __future__ import annotations

from pathlib import Path

from ..llm import OllamaClient
from ..skills import ApprovedSkillLoader
from ..structured_output_policy import StructuredOutputPolicyClient


_DEFAULT_AGENT_SKILLS: dict[str, tuple[str, ...]] = {
    "research": (
        "research-web-trust",
        "research-source-credibility",
        "research-evidence-synthesis",
        "research-data-quality",
    ),
    "presentation": ("presentation-evidence-boundary",),
    "daily_report": ("daily-report-evidence",),
}


class BaseAgent:
    agent_id = "base"
    profile_file = ""
    skill_names: tuple[str, ...] | None = None

    def __init__(self, profile_root: Path, llm: OllamaClient):
        self.profile_root = Path(profile_root)
        self.llm = StructuredOutputPolicyClient(llm, agent_id=self.agent_id)
        self.skill_loader = ApprovedSkillLoader(self.profile_root.parent / "skills")

    def profile(self) -> str:
        base = (self.profile_root / self.profile_file).read_text(encoding="utf-8").rstrip()
        names = self.skill_names if self.skill_names is not None else _DEFAULT_AGENT_SKILLS.get(self.agent_id, ())
        if not names:
            return base

        # A missing registry means no reviewed local skills are available in this
        # environment. This follows the loader's `no-registry-no-skills` policy
        # and is important for isolated test fixtures. Once a registry exists,
        # approval, agent scope, instruction-only policy and SHA-256 integrity
        # remain strict hard gates inside ApprovedSkillLoader.
        if not self.skill_loader.registry_path.exists():
            return base

        blocks = self.skill_loader.load_for_agent(self.agent_id, names)
        if not blocks:
            return base
        return base + "\n\n# Approved local skills\n\n" + "\n\n".join(blocks)
