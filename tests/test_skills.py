import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.agents.base import BaseAgent
from three_agent.skills import ApprovedSkillLoader, SkillSecurityError


class ApprovedSkillLoaderTests(unittest.TestCase):
    def _roots(self, tmp: str) -> tuple[Path, Path]:
        project = Path(tmp) / "project"
        root = project / "skills"
        (project / "docs").mkdir(parents=True)
        root.mkdir(parents=True)
        (project / "docs" / "review.md").write_text("# Reviewed\n", encoding="utf-8")
        return project, root

    def _write_skill(self, root: Path, name: str, agent_id: str = "research", **overrides) -> Path:
        skill_dir = root / name
        skill_dir.mkdir(parents=True)
        content = (
            "---\n"
            f"name: {name}\n"
            "description: Test reviewed skill.\n"
            "license: Project-internal\n"
            "---\n\n"
            "# Test Skill\n\nUse only reviewed local evidence.\n"
        )
        path = skill_dir / "SKILL.md"
        path.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        entry = {
            "enabled": True,
            "agent_ids": [agent_id],
            "instruction_only": True,
            "network_access": False,
            "credential_access": False,
            "persistent_self_modify": False,
            "external_code_vendored": False,
            "sha256": digest,
            "review": "docs/review.md",
            "provenance": ["public/example@deadbeef:SKILL.md"],
        }
        entry.update(overrides)
        registry = {
            "schema_version": 1,
            "policy": "approved-local-instruction-only",
            "skills": {name: entry},
        }
        (root / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
        return path

    def test_loads_approved_instruction_only_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            self._write_skill(root, "test-skill")
            blocks = ApprovedSkillLoader(root).load_for_agent("research", ["test-skill"])
            self.assertEqual(len(blocks), 1)
            self.assertIn("Use only reviewed local evidence", blocks[0])

    def test_rejects_modified_skill_after_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            path = self._write_skill(root, "test-skill")
            path.write_text(path.read_text(encoding="utf-8") + "UNREVIEWED CHANGE\n", encoding="utf-8")
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).load_for_agent("research", ["test-skill"])

    def test_rejects_skill_for_wrong_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            self._write_skill(root, "test-skill", agent_id="presentation")
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).load_for_agent("research", ["test-skill"])

    def test_rejects_unreviewed_executable_scripts(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            self._write_skill(root, "test-skill")
            scripts = root / "test-skill" / "scripts"
            scripts.mkdir()
            (scripts / "run.sh").write_text("#!/bin/sh\n", encoding="utf-8")
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).load_for_agent("research", ["test-skill"])

    def test_rejects_missing_security_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            project, root = self._roots(tmp)
            self._write_skill(root, "test-skill")
            (project / "docs" / "review.md").unlink()
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).load_for_agent("research", ["test-skill"])

    def test_rejects_direct_network_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            self._write_skill(root, "test-skill", network_access=True)
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).load_for_agent("research", ["test-skill"])

    def test_rejects_credential_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            self._write_skill(root, "test-skill", credential_access=True)
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).load_for_agent("research", ["test-skill"])

    def test_rejects_persistent_self_modification(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            self._write_skill(root, "test-skill", persistent_self_modify=True)
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).load_for_agent("research", ["test-skill"])

    def test_rejects_vendored_executable_authority(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, root = self._roots(tmp)
            self._write_skill(root, "test-skill", external_code_vendored=True)
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillLoader(root).load_for_agent("research", ["test-skill"])

    def test_repository_registry_hashes_and_reviews_are_valid(self):
        root = Path(__file__).resolve().parents[1] / "skills"
        loader = ApprovedSkillLoader(root)
        self.assertEqual(len(loader.load_for_agent("research", ["research-evidence-synthesis", "research-data-quality"])), 2)
        self.assertEqual(len(loader.load_for_agent("presentation", ["presentation-evidence-boundary"])), 1)
        self.assertEqual(len(loader.load_for_agent("daily_report", ["daily-report-evidence"])), 1)

    def test_base_agent_uses_base_profile_when_registry_is_absent(self):
        class TestResearchAgent(BaseAgent):
            agent_id = "research"
            profile_file = "agent_research.md"

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            profiles = root / "profiles"
            profiles.mkdir()
            (profiles / "agent_research.md").write_text("BASE PROFILE\n", encoding="utf-8")
            agent = TestResearchAgent(profiles, object())
            self.assertEqual(agent.profile(), "BASE PROFILE")


if __name__ == "__main__":
    unittest.main()
