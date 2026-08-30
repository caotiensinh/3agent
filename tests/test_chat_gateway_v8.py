from __future__ import annotations

from three_agent.chat_gateway_v8 import HTML_V8, ProjectKnowledgeHTTPHandler


def test_project_frontend_contract_is_present() -> None:
    assert 'id="projectsSection"' in HTML_V8
    assert 'id="addProjectBtn"' in HTML_V8
    assert 'id="projectsList"' in HTML_V8
    assert 'id="conversationMoveAction"' in HTML_V8
    assert 'id="moveProjectModal"' in HTML_V8
    assert 'id="projectEditModal"' in HTML_V8
    assert 'id="projectDeleteModal"' in HTML_V8
    assert "async function loadProjects()" in HTML_V8
    assert "async function moveConversationToProject" in HTML_V8
    assert "params.set('project',state.selectedProjectId)" in HTML_V8
    assert "Chats are kept" in HTML_V8 or "chats will be kept" in HTML_V8


def test_project_gateway_routes_are_declared() -> None:
    source_get = ProjectKnowledgeHTTPHandler.do_GET.__code__.co_consts
    source_post = ProjectKnowledgeHTTPHandler.do_POST.__code__.co_consts
    flattened = " ".join(str(value) for value in (*source_get, *source_post))
    assert "/api/projects" in flattened
    assert "/api/conversations/" in flattened
    assert "project" in flattened
    assert "rename" in flattened
    assert "delete" in flattened


def test_workspace_health_version_tracks_project_release() -> None:
    assert ProjectKnowledgeHTTPHandler.server_version == "WorkSpaceChat/0.10"
