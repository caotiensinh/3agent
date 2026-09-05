from __future__ import annotations

import hashlib
import re
import unittest
from pathlib import Path

from three_agent.workspace_frontend import WORKSPACE_HTML, _insert_after_workflow_description, config_js, config_markup

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_SHA256 = "38960166e270e464e2795ae204653d153993ebae0b3309ff2eac9b54c0ac027d"


class WorkspaceFrontendCanonicalizationTests(unittest.TestCase):
    def test_rendered_frontend_matches_effective_canonical_authority(self) -> None:
        actual = hashlib.sha256(WORKSPACE_HTML.encode("utf-8")).hexdigest()
        self.assertEqual(actual, EXPECTED_SHA256)

    def test_preserved_composition_contract_symbols_are_available(self) -> None:
        self.assertIn("securityConfigView", config_markup)
        self.assertIn("secCfgStatus", config_js)
        sample = '<textarea id="workflowDescription"></textarea><div>tail</div>'
        rendered = _insert_after_workflow_description(sample, '<div id="draft">draft</div>')
        self.assertIn('</textarea>\n<div id="draft">draft</div><div>tail</div>', rendered)

    def test_final_frontend_contains_business_document_and_security_contracts(self) -> None:
        for marker in (
            'application/pdf',
            'uploadProcessingLabel',
            'id="securityBoundaryView"',
            'id="securityConfigView"',
            'Save asset',
            'Disable asset',
            'Remove draft row',
            'expected_config_fingerprint',
            'SECURITY_ASSET_CONFIG_STALE',
            'network execution=false',
            '/api/security/assets/upsert',
            '/api/security/assets/disable',
            'secAssetCredential',
            'credential_ref',
        ):
            self.assertIn(marker, WORKSPACE_HTML)

    def test_no_physical_frontend_generation_modules_remain(self) -> None:
        package = ROOT / "src" / "three_agent"
        self.assertEqual(list(package.glob("workspace_frontend_v*.py")), [])

    def test_runtime_code_has_no_stale_frontend_generation_references(self) -> None:
        pattern = re.compile("workspace_frontend_" + r"v\d")
        stale = []
        migration = (ROOT / "scripts" / "consolidate_workspace_frontend.py").resolve()
        for base in (ROOT / "src", ROOT / "tests", ROOT / "scripts"):
            for path in base.rglob("*.py"):
                if path.resolve() == migration:
                    continue
                text = path.read_text(encoding="utf-8")
                if pattern.search(text):
                    stale.append(str(path.relative_to(ROOT)))
        self.assertEqual(stale, [])


if __name__ == "__main__":
    unittest.main()
