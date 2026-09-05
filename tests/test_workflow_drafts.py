from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path

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


class WorkflowDraftStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.store = WorkflowDraftStore(Path(self._tmp.name) / "workspace.db")
        self.store.initialize()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_owner_scoped_revision_lifecycle_and_immutable_versions(self) -> None:
        first = self.store.create(OWNER_A, ACTOR_A, title="", description="Build a daily internal review.", contract=_contract(), origin="workspace_ai")
        self.assertIsNotNone(re.fullmatch(r"wfd_[a-f0-9]{16}", first["draft_id"]))
        self.assertEqual(first["revision"], 1)
        self.assertFalse(first["execution_authorized"])
        self.assertEqual(first["execution_mode"], "design_only")

        updated = self.store.save(OWNER_A, ACTOR_A, first["draft_id"], expected_revision=first["revision"], expected_content_sha256=first["content_sha256"], title="Daily review v2", description=first["description"], contract=_contract("Daily review v2"), origin="human")
        self.assertEqual(updated["revision"], 2)
        self.assertNotEqual(updated["content_sha256"], first["content_sha256"])

        with self.assertRaisesRegex(WorkflowDraftConflict, "stale workflow revision"):
            self.store.save(OWNER_A, ACTOR_A, first["draft_id"], expected_revision=1, expected_content_sha256=first["content_sha256"], title="stale", description="stale", contract=_contract("stale"))

        archived = self.store.set_archived(OWNER_A, ACTOR_A, first["draft_id"], archived=True)
        self.assertEqual(archived["status"], "archived")
        with self.assertRaisesRegex(WorkflowDraftConflict, "restored before editing"):
            self.store.save(OWNER_A, ACTOR_A, first["draft_id"], expected_revision=2, expected_content_sha256=updated["content_sha256"], title="blocked", description="", contract=_contract("blocked"))

        restored = self.store.set_archived(OWNER_A, ACTOR_A, first["draft_id"], archived=False)
        self.assertEqual(restored["status"], "active")
        copy = self.store.duplicate(OWNER_A, ACTOR_A, first["draft_id"])
        self.assertNotEqual(copy["draft_id"], first["draft_id"])
        self.assertEqual(copy["lineage_parent_draft_id"], first["draft_id"])
        self.assertEqual(copy["lineage_parent_revision"], 2)

        versions = self.store.versions(OWNER_A, first["draft_id"])
        self.assertEqual([item["revision"] for item in versions], [2, 1])
        self.assertEqual(versions[1]["content_sha256"], first["content_sha256"])
        operations = [item["operation"] for item in self.store.audit(OWNER_A, first["draft_id"])]
        self.assertEqual(operations, ["restore", "archive", "save", "create"])
        self.assertTrue(all("contract" not in item and "description" not in item for item in self.store.audit(OWNER_A, first["draft_id"])))

        with self.assertRaises(WorkflowDraftNotFound):
            self.store.get(OWNER_B, first["draft_id"])
        with self.assertRaises(WorkflowDraftNotFound):
            self.store.versions(OWNER_B, first["draft_id"])

    def test_idempotent_save_does_not_inflate_revision(self) -> None:
        first = self.store.create(OWNER_A, ACTOR_A, title="Daily review", description="same", contract=_contract(), origin="workspace_ai")
        same = self.store.save(OWNER_A, ACTOR_A, first["draft_id"], expected_revision=1, expected_content_sha256=first["content_sha256"], title=first["title"], description=first["description"], contract=first["contract"], origin="human")
        self.assertEqual(same["revision"], 1)
        self.assertEqual(len(self.store.versions(OWNER_A, first["draft_id"])), 1)

    def test_search_treats_sql_wildcards_as_literal(self) -> None:
        literal = self.store.create(OWNER_A, ACTOR_A, title="Percent % workflow", description="literal wildcard", contract=_contract("Percent % workflow"))
        self.store.create(OWNER_A, ACTOR_A, title="Ordinary workflow", description="no wildcard here", contract=_contract("Ordinary workflow"))
        rows = self.store.list(OWNER_A, query="%")
        self.assertEqual([item["draft_id"] for item in rows], [literal["draft_id"]])

    def test_invalid_contract_fails_closed_without_persisting(self) -> None:
        with self.assertRaises(WorkflowDraftError):
            self.store.create(OWNER_A, ACTOR_A, title="invalid", description="invalid", contract={"title": "not a V4 workflow"})
        self.assertEqual(self.store.list(OWNER_A), [])


if __name__ == "__main__":
    unittest.main()
