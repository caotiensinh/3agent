import unittest

from three_agent.workspace_frontend import WORKSPACE_HTML


class WorkspaceDispatchUITests(unittest.TestCase):
    def test_dispatch_ui_preserves_external_login_and_stays_local(self):
        html = WORKSPACE_HTML
        self.assertIn('id="externalLoginList"', html)
        self.assertIn("Google", html)
        self.assertIn("GitHub", html)
        self.assertIn("LINE", html)
        self.assertIn('data-action="dispatch"', html)
        self.assertIn('id="dispatchModal"', html)
        self.assertIn('id="compileDispatch"', html)
        self.assertIn('id="runDispatch"', html)
        self.assertIn("Approve &amp; Dispatch", html)
        self.assertIn("/api/dispatch/compile", html)
        self.assertIn("p.diagram_svg", html)
        self.assertIn("p.mermaid", html)
        self.assertNotIn("mermaid.min.js", html)
        self.assertNotIn("cdn.jsdelivr.net", html)
        self.assertNotIn("unpkg.com", html)

    def test_dispatch_ui_exposes_preview_only_and_svg_safety_state(self):
        html = WORKSPACE_HTML
        self.assertIn("Preview only", html)
        self.assertIn("execution_ready", html)
        self.assertIn("≤12 nodes", html)
        self.assertIn("≤2 conceptual parallel nodes", html)
        self.assertIn("DOMParser", html)
        self.assertIn("foreignObject", html)
        self.assertIn("Diagram safety validation failed", html)


if __name__ == "__main__":
    unittest.main()
