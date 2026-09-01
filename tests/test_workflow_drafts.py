from __future__ import annotations

import re

import pytest

from three_agent.workflow_drafts import (
    WorkflowDraftConflict,
    WorkflowDraftError,
    WorkflowDraftNotFound,
    WorkflowDraftStore,
)

OWNER_A = "a" * 64
OWNER_B = "b" * 64
ACTOR_A = "usr_" + "1" * 16


def _contract(title: str = "Daily review") -> dict:
    return {
        "title": title,
        "objective": "Review approved internal evidence and produce a bounded report.",
        "trigger": "manual",
        "risk_level": "low",
        "data_class": "internal",
        "nodes": [
            {"id": "input", "label": "Approved input", "kind": "input", "action": "input", "depends_on": [], "condition": "", "approval_required": False},
            {"id": "research", "label": "Research", "kind": "agent", "action": "research", "depends_on": ["input"], "condition": "", "approval_required": False},
            {"id": "output", "label": "Report", "kind": "output", "action": "output", "depends_on": ["research"], "condition": "", "approval_required": False},
        ],
        "outputs": ["Internal report"],
        "warnings": [],
    }


@pytest.fixture()
def store(tmp_path):
    value = WorkflowDraftStore(tmp_path / "workspace.db")
    value.initialize()
    return value


def test_owner_scoped_revision_lifecycle_and_immutable_versions(store):
    first = store.create(OWNER_A, ACTOR_A, title="", description="Build a daily internal review.", contract=_contract(), origin="workspace_ai")
    assert re.fullmatch(r"wfd_[a-f0-9]{16}", first["draft_id"])
    assert first["revision"] == 1
    assert first["execution_authorized"] is False
    assert first["execution_mode"] == "design_only"

    updated = store.save(OWNER_A, ACTOR_A, first["draft_id"], expected_revision=first["revision"], expected_content_sha256=first["content_sha256"], title="Daily review v2", description=first["description"], contract=_contract("Daily review v2"), origin="human")
    assert updated["revision"] == 2
    assert updated["content_sha256"] != first["content_sha256"]

    with pytest.raises(WorkflowDraftConflict, match="stale workflow revision"):
        store.save(OWNER_A, ACTOR_A, first["draft_id"], expected_revision=1, expected_content_sha256=first["content_sha256"], title="stale", description="stale", contract=_contract("stale"))

    archived = store.set_archived(OWNER_A, ACTOR_A, first["draft_id"], archived=True)
    assert archived["status"] == "archived"
    with pytest.raises(WorkflowDraftConflict, match="restored before editing"):
        store.save(OWNER_A, ACTOR_A, first["draft_id"], expected_revision=2, expected_content_sha256=updated["content_sha256"], title="blocked", description="", contract=_contract("blocked"))

    restored = store.set_archived(OWNER_A, ACTOR_A, first["draft_id"], archived=False)
    assert restored["status"] == "active"
    copy = store.duplicate(OWNER_A, ACTOR_A, first["draft_id"])
    assert copy["draft_id"] != first["draft_id"]
    assert copy["lineage_parent_draft_id"] == first["draft_id"]
    assert copy["lineage_parent_revision"] == 2

    versions = store.versions(OWNER_A, first["draft_id"])
    assert [item["revision"] for item in versions] == [2, 1]
    assert versions[1]["content_sha256"] == first["content_sha256"]
    operations = [item["operation"] for item in store.audit(OWNER_A, first["draft_id"])]
    assert operations == ["restore", "archive", "save", "create"]
    assert all("contract" not in item and "description" not in item for item in store.audit(OWNER_A, first["draft_id"]))

    with pytest.raises(WorkflowDraftNotFound):
        store.get(OWNER_B, first["draft_id"])
    with pytest.raises(WorkflowDraftNotFound):
        store.versions(OWNER_B, first["draft_id"])


def test_idempotent_save_does_not_inflate_revision(store):
    first = store.create(OWNER_A, ACTOR_A, title="Daily review", description="same", contract=_contract(), origin="workspace_ai")
    same = store.save(OWNER_A, ACTOR_A, first["draft_id"], expected_revision=1, expected_content_sha256=first["content_sha256"], title=first["title"], description=first["description"], contract=first["contract"], origin="human")
    assert same["revision"] == 1
    assert len(store.versions(OWNER_A, first["draft_id"])) == 1


def test_search_treats_sql_wildcards_as_literal(store):
    literal = store.create(OWNER_A, ACTOR_A, title="Percent % workflow", description="literal wildcard", contract=_contract("Percent % workflow"))
    store.create(OWNER_A, ACTOR_A, title="Ordinary workflow", description="no wildcard here", contract=_contract("Ordinary workflow"))
    rows = store.list(OWNER_A, query="%")
    assert [item["draft_id"] for item in rows] == [literal["draft_id"]]


def test_invalid_contract_fails_closed_without_persisting(store):
    with pytest.raises(WorkflowDraftError):
        store.create(OWNER_A, ACTOR_A, title="invalid", description="invalid", contract={"title": "not a V4 workflow"})
    assert store.list(OWNER_A) == []
