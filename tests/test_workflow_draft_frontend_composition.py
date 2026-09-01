from __future__ import annotations

import pytest

from three_agent.workspace_frontend_v16 import (
    WORKSPACE_HTML_V16,
    _insert_after_workflow_description,
)


def test_workflow_draft_library_composes_exactly_once_on_semantic_studio_anchor():
    html = WORKSPACE_HTML_V16
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
        assert html.count(f'id="{element_id}"') == 1

    description_end = html.index("</textarea>", html.index('id="workflowDescription"'))
    library_at = html.index('id="workflowLibraryBtn"')
    compile_at = html.index('id="workflowCompileBtn"')
    assert description_end < library_at < compile_at
    assert "Draft = design only · execution authority unchanged" in html


def test_workflow_draft_composition_is_copy_independent_but_shape_fail_closed():
    base = '<section><p>Copy can change.</p><textarea class="x" id="workflowDescription">text</textarea><button id="workflowCompileBtn">Compile</button></section>'
    composed = _insert_after_workflow_description(base, '<div id="draftLibrary">library</div>')
    assert composed.count('id="draftLibrary"') == 1
    assert composed.index('id="workflowDescription"') < composed.index('id="draftLibrary"')

    with pytest.raises(RuntimeError, match="expected exactly one workflowDescription id"):
        _insert_after_workflow_description("<div>No workflow studio</div>", "x")
    with pytest.raises(RuntimeError, match="expected exactly one workflowDescription id"):
        _insert_after_workflow_description('<textarea id="workflowDescription"></textarea><textarea id="workflowDescription"></textarea>', "x")
    with pytest.raises(RuntimeError, match="must remain a textarea"):
        _insert_after_workflow_description('<input id="workflowDescription">', "x")
