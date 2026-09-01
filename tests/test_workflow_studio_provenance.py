from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "docs" / "legal" / "WORKFLOW_STUDIO_OSS_PROVENANCE.json"


def test_workflow_studio_reference_registry_is_clean_room_only():
    data = json.loads(REGISTRY.read_text(encoding="utf-8"))
    assert data["schema_version"] == "workspace-workflow-studio-oss-provenance/v1"
    assert data["policy"] == "clean_room_inspiration_only"
    assert data["sources"]
    for source in data["sources"]:
        assert source["license"] in {"MIT", "Apache-2.0"}
        assert source["repository"].startswith("https://github.com/")
        assert source["license_source"].startswith("https://github.com/")
        assert source["code_imported"] is False
        assert source["assets_imported"] is False
        assert source["dependency_added"] is False
        assert source["trademark_reused"] is False


def test_workflow_studio_production_frontend_does_not_reuse_reference_branding():
    source = (ROOT / "src" / "three_agent" / "workspace_frontend_v16.py").read_text(encoding="utf-8").lower()
    for mark in ("draw.io", "diagrams.net", "react flow", "logicflow", "rete.js"):
        assert mark not in source


def test_reference_projects_are_not_added_as_python_runtime_dependencies():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
    for package in ("mxgraph", "xyflow", "logicflow", "rete", "bpmn-js"):
        assert package not in pyproject
