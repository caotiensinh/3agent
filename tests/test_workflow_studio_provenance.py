from __future__ import annotations

import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "docs" / "legal" / "WORKFLOW_STUDIO_OSS_PROVENANCE.json"


class WorkflowStudioProvenanceTests(unittest.TestCase):
    def test_workflow_studio_reference_registry_is_clean_room_only(self) -> None:
        data = json.loads(REGISTRY.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], "workspace-workflow-studio-oss-provenance/v1")
        self.assertEqual(data["policy"], "clean_room_inspiration_only")
        self.assertTrue(data["sources"])
        for source in data["sources"]:
            self.assertIn(source["license"], {"MIT", "Apache-2.0"})
            self.assertTrue(source["repository"].startswith("https://github.com/"))
            self.assertTrue(source["license_source"].startswith("https://github.com/"))
            self.assertFalse(source["code_imported"])
            self.assertFalse(source["assets_imported"])
            self.assertFalse(source["dependency_added"])
            self.assertFalse(source["trademark_reused"])

    def test_workflow_studio_production_frontend_does_not_reuse_reference_branding(self) -> None:
        source = (ROOT / "src" / "three_agent" / "workspace_frontend.py").read_text(encoding="utf-8").lower()
        for mark in ("draw.io", "diagrams.net", "react flow", "logicflow", "rete.js"):
            self.assertNotIn(mark, source)

    def test_reference_projects_are_not_added_as_python_runtime_dependencies(self) -> None:
        pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
        for package in ("mxgraph", "xyflow", "logicflow", "rete", "bpmn-js"):
            self.assertNotIn(package, pyproject)


if __name__ == "__main__":
    unittest.main()
