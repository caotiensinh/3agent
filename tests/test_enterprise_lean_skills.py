import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.agents.base import _DEFAULT_AGENT_SKILLS
from three_agent.skills import (
    MAX_LOADED_SKILL_BYTES,
    MAX_SKILL_BYTES,
    MAX_SKILLS_PER_LOAD,
    ApprovedSkillLoader,
    SkillSecurityError,
)


class EnterpriseLeanSkillTests(unittest.TestCase):
    def _roots(self, tmp: str) -> tuple[Path, Path]:
        project = Path(tmp) / "project"
        root = project / "skills"
        (project / "docs").mkdir(parents=True)
        root.mkdir(parents=True)
        (project / "docs" / "review.md").write_text("# Reviewed\n", encoding="utf-8")
        return project, root

    @staticmethod
    def _skill_text(name: str, body: str) -> str:
        return (
            "---\n"
            f"name: {name}\n"
            "description: Compact reviewed skill.\n"
            "license: Project-internal\n"
            "---\n\n"
            f"# {name}\n\n{body}\n"
        )

    def _write_registry(self, root: Path, bodies: dict[str, str]) -> None:
        entries = {}
        for name, body in bodies.items():
            text = self._skill_text(name, body)
            skill_dir = root / name
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text(text, encoding="utf-8")
            entries[name] = {
                "enabled": True,
                "agent_ids": ["research"],
                "instruction_only": True,
                "network_access": False,
                "credential_access": False,
                "persistent_self_modify": False,
                "external_code_vendored": False,
                "sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                "review": "docs/review.md",
                "provenance": ["project-owned:test"],
            }
        payload = {
            "schema_version": 1,
            "policy": "approved-local-instruction-only",
            "enterprise_baseline": {
                "enterprise_tier": "E2",
                "profile": "enterprise-confidential-lean",
                "instruction_only": True,
                "network_access": False,
                "credential_access": False,
                "persistent_self_modify": False,
                "external_code_vendored": False,
                "raw_sensitive_logging": False,
                "model_authority": "advisory",
                "max_skill_bytes": MAX_SKILL_BYTES,
                "max_skills_per_load": MAX_SKILLS_PER_LOAD,
                "max_loaded_skill_bytes": MAX_LOADED_SKILL_BYTES,
            },
            "skills": entries,
        }
        (root / "registry.json").write_text(json.dumps(payload), encoding="utf-8")

    def test_default_prompt_disclosure_is_minimal(self):
        self.assertEqual(_DEFAULT_AGENT_SKILLS["research"], ("research-web-trust",))
        self.assertEqual(_DEFAULT_AGENT_SKILLS["presentation"], ())
        self.assertEqual(_DEFAULT_AGENT_SKILLS["daily_report"], ())

    def test_rejects_more_than_two_skills_per_model_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            self._write_registry(
                root,
                {"skill-one": "one", "skill-two": "two", "skill-three": "three"},
            )
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).load_for_agent(
                    "research", ["skill-one", "skill-two", "skill-three"]
                )

    def test_rejects_oversized_single_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            self._write_registry(root, {"large-skill": "x" * MAX_SKILL_BYTES})
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).load_for_agent("research", ["large-skill"])

    def test_rejects_loaded_skill_prompt_budget_overflow(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            # Each skill remains under its individual file limit, but the two
            # loaded procedure bodies exceed the aggregate prompt budget.
            body = "x" * 2100
            self._write_registry(root, {"skill-one": body, "skill-two": body})
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).load_for_agent(
                    "research", ["skill-one", "skill-two"]
                )

    def test_rejects_weakened_enterprise_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            self._write_registry(root, {"test-skill": "safe"})
            payload = json.loads((root / "registry.json").read_text(encoding="utf-8"))
            payload["enterprise_baseline"]["network_access"] = True
            (root / "registry.json").write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).audit_registry()

    def test_default_workflow_skill_payload_reduced_by_at_least_75_percent(self):
        root = Path(__file__).resolve().parents[1] / "skills"

        def body_size(name: str) -> int:
            text = (root / name / "SKILL.md").read_text(encoding="utf-8")
            end = text.find("\n---\n", 4)
            self.assertGreater(end, 0)
            return len(text[end + 5 :].strip().encode("utf-8"))

        legacy_research = sum(
            body_size(name)
            for name in (
                "research-web-trust",
                "research-source-credibility",
                "research-evidence-synthesis",
                "research-data-quality",
            )
        )
        legacy_typical = (
            3 * legacy_research
            + body_size("presentation-evidence-boundary")
            + body_size("daily-report-evidence")
        )
        optimized_typical = 3 * body_size("research-web-trust")

        # Typical live workflow has three Research model calls, one Presentation
        # planning call and one Daily Report generation call. This is instruction
        # payload only, not a claim about tokenizer-specific token counts.
        self.assertLessEqual(optimized_typical * 4, legacy_typical)

    def test_repository_registry_full_audit_is_valid(self):
        root = Path(__file__).resolve().parents[1] / "skills"
        audited = ApprovedSkillLoader(root).audit_registry()
        self.assertIn("enterprise-delivery", audited)
        self.assertIn("security-engineering", audited)
        self.assertIn("verified-completion", audited)


if __name__ == "__main__":
    unittest.main()
