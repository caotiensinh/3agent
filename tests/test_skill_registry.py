from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from three_agent.skill_registry import MissingSkillError, SkillRegistry, SkillRegistryError


class SkillRegistryTests(unittest.TestCase):
    def test_repository_registry_loads_and_hides_quarantined_by_default(self) -> None:
        registry = SkillRegistry.load(ROOT / "skills" / "registry.json")
        visible = registry.records()
        self.assertTrue(visible)
        self.assertTrue(all(item.status == "approved" for item in visible))
        self.assertTrue(any(item.status == "quarantined" for item in registry.records(include_unapproved=True)))

    def test_select_is_deterministic_and_local_approved_only(self) -> None:
        registry = SkillRegistry.load(ROOT / "skills" / "registry.json")
        selected = registry.select("archive_inventory", ".zip")
        self.assertEqual(selected.skill_id, "workspace.archive.safe-inspect")
        self.assertEqual(selected.permissions.network, "none")
        self.assertEqual(selected.permissions.subprocess, "none")

    def test_quarantined_candidate_cannot_satisfy_runtime_request(self) -> None:
        registry = SkillRegistry.load(ROOT / "skills" / "registry.json")
        with self.assertRaises(MissingSkillError) as ctx:
            registry.select("ocr_text", ".jpg")
        self.assertIn("missing_skill", str(ctx.exception))

    def test_missing_capability_is_explicit(self) -> None:
        registry = SkillRegistry.load(ROOT / "skills" / "registry.json")
        with self.assertRaises(MissingSkillError):
            registry.select("execute_unknown_plugin", ".pdf")

    def test_rejects_invalid_permissions(self) -> None:
        payload = {
            "schema_version": 1,
            "skills": [{
                "id": "bad",
                "version": "1",
                "status": "approved",
                "capabilities": ["x"],
                "permissions": {"network": "internet", "subprocess": "none"},
                "provenance": {"origin": "test"}
            }]
        }
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "registry.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaises(SkillRegistryError):
                SkillRegistry.load(path)

    def test_plan_deduplicates_same_skill(self) -> None:
        registry = SkillRegistry.load(ROOT / "skills" / "registry.json")
        plan = registry.plan(["archive_inventory", "archive_expand_bounded"], ".zip")
        self.assertEqual([item.skill_id for item in plan], ["workspace.archive.safe-inspect"])


if __name__ == "__main__":
    unittest.main()
