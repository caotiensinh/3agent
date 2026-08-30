from __future__ import annotations

import unittest

from three_agent.chat_gateway_v8 import HTML_V8, ProjectKnowledgeHTTPHandler
from three_agent.chat_gateway_v9 import HTML_V9, ProjectUIHTTPHandler


class ProjectGatewayContractTests(unittest.TestCase):
    def test_project_frontend_contract_is_present(self) -> None:
        self.assertIn('id="projectsSection"', HTML_V8)
        self.assertIn('id="addProjectBtn"', HTML_V8)
        self.assertIn('id="projectsList"', HTML_V8)
        self.assertIn('id="conversationMoveAction"', HTML_V8)
        self.assertIn('id="moveProjectModal"', HTML_V8)
        self.assertIn('id="projectEditModal"', HTML_V8)
        self.assertIn('id="projectDeleteModal"', HTML_V8)
        self.assertIn("async function loadProjects()", HTML_V8)
        self.assertIn("async function moveConversationToProject", HTML_V8)
        self.assertIn("params.set('project',state.selectedProjectId)", HTML_V8)
        self.assertTrue("Chats are kept" in HTML_V8 or "chats will be kept" in HTML_V8)

    def test_project_gateway_routes_are_declared(self) -> None:
        source_get = ProjectKnowledgeHTTPHandler.do_GET.__code__.co_consts
        source_post = ProjectKnowledgeHTTPHandler.do_POST.__code__.co_consts
        flattened = " ".join(str(value) for value in (*source_get, *source_post))
        self.assertIn("/api/projects", flattened)
        self.assertIn("/api/conversations/", flattened)
        self.assertIn("project", flattened)
        self.assertIn("rename", flattened)
        self.assertIn("delete", flattened)

    def test_workspace_health_version_tracks_project_release(self) -> None:
        self.assertEqual(
            ProjectKnowledgeHTTPHandler.server_version,
            "WorkSpaceChat/0.10",
        )
        self.assertEqual(ProjectUIHTTPHandler.server_version, "WorkSpaceChat/0.10")

    def test_hardened_project_ui_can_toggle_back_to_all_chats(self) -> None:
        self.assertIn(
            "state.selectedProjectId=state.selectedProjectId===id?null:id",
            HTML_V9,
        )
        self.assertIn("editing?'Project renamed':'Project created'", HTML_V9)


if __name__ == "__main__":
    unittest.main()
