import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.skill_catalog import ApprovedSkillCatalog
from three_agent.skills import SkillSecurityError


class ApprovedSkillCatalogTests(unittest.TestCase):
    def _fixture(
        self,
        tmp: str,
        *,
        agent_ids: tuple[str, ...] = ("research",),
        enabled: bool = True,
    ) -> tuple[Path, Path]:
        project = Path(tmp) / "project"
        root = project / "skills"
        docs = project / "docs"
        docs.mkdir(parents=True)
        root.mkdir(parents=True)
        (docs / "review.md").write_text("# Reviewed\n", encoding="utf-8")

        name = "network-diagnosis"
        skill_dir = root / name
        skill_dir.mkdir()
        content = (
            "---\n"
            f"name: {name}\n"
            "description: Diagnose network evidence using reviewed read-only procedures.\n"
            "license: Project-internal\n"
            "---\n\n"
            "# Network Diagnosis\n\n"
            "Use only verified evidence and stop when evidence is insufficient.\n"
        )
        path = skill_dir / "SKILL.md"
        path.write_text(content, encoding="utf-8")
        digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
        registry = {
            "schema_version": 1,
            "policy": "approved-local-instruction-only",
            "skills": {
                name: {
                    "enabled": enabled,
                    "agent_ids": list(agent_ids),
                    "instruction_only": True,
                    "network_access": False,
                    "credential_access": False,
                    "persistent_self_modify": False,
                    "external_code_vendored": False,
                    "sha256": digest,
                    "review": "docs/review.md",
                    "provenance": ["project-owned:test-fixture"],
                    "enterprise_tier": "E2",
                    "risk_class": "medium",
                }
            },
        }
        (root / "registry.json").write_text(json.dumps(registry), encoding="utf-8")
        return root, path

    def test_list_returns_compact_metadata_without_skill_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._fixture(tmp)
            rows = ApprovedSkillCatalog(root).list_for_agent("research")
            self.assertEqual(len(rows), 1)
            row = rows[0]
            self.assertEqual(row.name, "network-diagnosis")
            self.assertIn("Diagnose network evidence", row.description)
            self.assertEqual(row.enterprise_tier, "E2")
            self.assertEqual(row.risk_class, "medium")
            self.assertEqual(row.provenance_count, 1)
            self.assertNotIn("Use only verified evidence", json.dumps(row.to_dict()))

    def test_list_omits_skill_not_approved_for_agent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._fixture(tmp, agent_ids=("presentation",))
            self.assertEqual(ApprovedSkillCatalog(root).list_for_agent("research"), ())

    def test_list_omits_disabled_skill(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._fixture(tmp, enabled=False)
            self.assertEqual(ApprovedSkillCatalog(root).list_for_agent("research"), ())

    def test_list_fails_closed_when_reviewed_bytes_are_modified(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, path = self._fixture(tmp)
            path.write_text(
                path.read_text(encoding="utf-8") + "UNREVIEWED CHANGE\n",
                encoding="utf-8",
            )
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillCatalog(root).list_for_agent("research")

    def test_view_returns_one_approved_skill_on_demand(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._fixture(tmp)
            block = ApprovedSkillCatalog(root).view_for_agent("research", "network-diagnosis")
            self.assertIn("## Approved local skill: network-diagnosis", block)
            self.assertIn("Use only verified evidence", block)

    def test_view_cannot_bypass_agent_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, _ = self._fixture(tmp, agent_ids=("presentation",))
            with self.assertRaises(SkillSecurityError):
                ApprovedSkillCatalog(root).view_for_agent("research", "network-diagnosis")


if __name__ == "__main__":
    unittest.main()
