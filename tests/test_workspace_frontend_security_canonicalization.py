from __future__ import annotations

import unittest
from pathlib import Path


class CanonicalFrontendSecurityTest(unittest.TestCase):
    def test_versioned_security_module_is_removed(self):
        root = Path(__file__).resolve().parents[1]
        self.assertFalse((root / "src/three_agent/workspace_frontend_security_v1.py").exists())

    def test_frontend_security_chain_is_acyclic_and_preserves_overlays(self):
        from three_agent.workspace_frontend_security import WORKSPACE_HTML
        from three_agent.workspace_frontend import WORKSPACE_HTML
        from three_agent.workspace_frontend import WORKSPACE_HTML
        from three_agent.workspace_frontend_security import (
            WORKSPACE_HTML_SECURITY_V2,
            WORKSPACE_HTML_SECURITY_V3,
        )

        self.assertIn('id="securityAnalystSurface"', WORKSPACE_HTML)
        self.assertIn('id="securityAnalystSurface"', WORKSPACE_HTML)
        self.assertIn('id="securityConfigView"', WORKSPACE_HTML)
        self.assertIn('id="securitySocView"', WORKSPACE_HTML_SECURITY_V2)
        self.assertIn('id="securityConfigView"', WORKSPACE_HTML_SECURITY_V2)
        self.assertIn('id="securityBoundaryView"', WORKSPACE_HTML_SECURITY_V3)
        self.assertIn('id="securitySocView"', WORKSPACE_HTML_SECURITY_V3)


if __name__ == "__main__":
    unittest.main()
