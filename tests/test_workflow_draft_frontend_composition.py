from __future__ import annotations

import unittest

from three_agent.workspace_frontend import (
    WORKSPACE_HTML,
    _insert_after_workflow_description,
)


class WorkflowDraftFrontendCompositionTests(unittest.TestCase):
    def test_workflow_draft_library_composes_exactly_once_on_semantic_studio_anchor(self) -> None:
        html = WORKSPACE_HTML
        for element_id in (
            "workflowDescription",
            "workflowLibraryBtn",
            "workflowDraftTitle",
            "workflowDraftCreateBtn",
            "workflowDraftSaveBtn",
            "workflowDraftDuplicateBtn",
            "workflowDraftArchiveBtn",
            "workflowLibraryDrawer",
            "workflowLibrarySearch",
            "workflowLibraryView",
            "workflowDraftVersions",
        ):
            self.assertEqual(html.count(f'id="{element_id}"'), 1)

        description_end = html.index("</textarea>", html.index('id="workflowDescription"'))
        library_at = html.index('id="workflowLibraryBtn"')
        compile_at = html.index('id="workflowCompileBtn"')
        self.assertLess(description_end, library_at)
        self.assertLess(library_at, compile_at)
        self.assertIn("Draft = design only · execution authority unchanged", html)

    def test_workflow_draft_library_preserves_hardened_security_surfaces(self) -> None:
        html = WORKSPACE_HTML
        for token in (
            'data-security-tab="soc"',
            'id="securitySocView"',
            'data-security-tab="boundaries"',
            'id="securityBoundaryView"',
            'data-security-tab="configuration"',
            'id="securityConfigView"',
        ):
            with self.subTest(token=token):
                self.assertIn(token, html)

        for element_id in (
            "securitySocTab",
            "securityBoundaryTab",
            "securityConfigTab",
            "securitySocView",
            "securityBoundaryView",
            "securityConfigView",
        ):
            with self.subTest(element_id=element_id):
                self.assertEqual(html.count(f'id="{element_id}"'), 1)

    def test_workflow_draft_composition_is_copy_independent_but_shape_fail_closed(self) -> None:
        base = '<section><p>Copy can change.</p><textarea class="x" id="workflowDescription">text</textarea><button id="workflowCompileBtn">Compile</button></section>'
        composed = _insert_after_workflow_description(base, '<div id="draftLibrary">library</div>')
        self.assertEqual(composed.count('id="draftLibrary"'), 1)
        self.assertLess(composed.index('id="workflowDescription"'), composed.index('id="draftLibrary"'))

        with self.assertRaisesRegex(RuntimeError, "expected exactly one workflowDescription id"):
            _insert_after_workflow_description("<div>No workflow studio</div>", "x")
        with self.assertRaisesRegex(RuntimeError, "expected exactly one workflowDescription id"):
            _insert_after_workflow_description('<textarea id="workflowDescription"></textarea><textarea id="workflowDescription"></textarea>', "x")
        with self.assertRaisesRegex(RuntimeError, "must remain a textarea"):
            _insert_after_workflow_description('<input id="workflowDescription">', "x")


if __name__ == "__main__":
    unittest.main()
