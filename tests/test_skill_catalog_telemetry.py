from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.skill_catalog import ApprovedSkillCatalog
from three_agent.skill_catalog_telemetry import (
    ACTION_LISTED,
    ACTION_SELECTED,
    ACTION_VIEWED,
    SKILL_CATALOG_TELEMETRY_SCHEMA,
    SkillCatalogTelemetry,
)
from three_agent.skills import SkillSecurityError
from three_agent.store import TaskStore


class SkillCatalogTelemetryTests(unittest.TestCase):
    @staticmethod
    def _fixture(
        root: Path,
        *,
        invalid_optional_metadata: bool = False,
        skill_count: int = 1,
    ):
        project = root / "project"
        skills_root = project / "skills"
        docs = project / "docs"
        skills_root.mkdir(parents=True)
        docs.mkdir(parents=True)
        (docs / "review.md").write_text("# Reviewed\n", encoding="utf-8")

        body_marker = "BODY-ONLY-SECRET-MARKER"
        description_marker = "Forensicmarker"
        entries: dict[str, dict] = {}
        digests: dict[str, str] = {}
        names: list[str] = []
        for index in range(skill_count):
            name = "network-diagnosis" if index == 0 else f"network-diagnosis-{index:02d}"
            names.append(name)
            content = (
                "---\n"
                f"name: {name}\n"
                f"description: {description_marker} evidence-first network diagnosis {index}.\n"
                "license: Project-internal\n"
                "---\n\n"
                "# Network Diagnosis\n\n"
                f"Use verified evidence only. {body_marker}-{index}\n"
            )
            skill_dir = skills_root / name
            skill_dir.mkdir()
            (skill_dir / "SKILL.md").write_text(content, encoding="utf-8")
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            digests[name] = digest
            entries[name] = {
                "enabled": True,
                "agent_ids": ["research"],
                "instruction_only": True,
                "network_access": False,
                "credential_access": False,
                "persistent_self_modify": False,
                "external_code_vendored": False,
                "sha256": digest,
                "review": "docs/review.md",
                "provenance": [f"project-owned:telemetry-fixture:{index}"],
                "enterprise_tier": "E2",
                "risk_class": "medium",
                "category": ["invalid"] if invalid_optional_metadata else "diagnostics",
                "domain": "network",
                "tags": ["evidence", "network"],
            }
        (skills_root / "registry.json").write_text(
            json.dumps(
                {
                    "schema_version": 1,
                    "policy": "approved-local-instruction-only",
                    "skills": entries,
                },
                sort_keys=True,
            ),
            encoding="utf-8",
        )

        task_store = TaskStore(root / "tasks.db")
        task_store.initialize()
        task = task_store.create_task("Telemetry", "RAW-REQUEST-MUST-NOT-APPEAR")
        telemetry = SkillCatalogTelemetry(ApprovedSkillCatalog(skills_root), task_store)
        return (
            telemetry,
            task_store,
            task.task_id,
            tuple(names),
            digests,
            description_marker,
            body_marker,
        )

    @staticmethod
    def _events(store: TaskStore, task_id: str, action: str):
        with store.connect() as conn:
            return conn.execute(
                "SELECT * FROM activities WHERE task_id = ? AND action = ? ORDER BY id",
                (task_id, action),
            ).fetchall()

    def test_list_records_count_and_set_digest_without_skill_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            telemetry, store, task_id, _names, _digests, description_marker, body_marker = self._fixture(
                Path(tmp)
            )
            rows = telemetry.list_for_agent(task_id, "research")
            self.assertEqual(len(rows), 1)

            events = self._events(store, task_id, ACTION_LISTED)
            self.assertEqual(len(events), 1)
            payload = json.loads(str(events[0]["details"]))
            self.assertEqual(payload["schema_version"], SKILL_CATALOG_TELEMETRY_SCHEMA)
            self.assertEqual(payload["surface"], "list")
            self.assertEqual(payload["count"], 1)
            self.assertRegex(payload["skill_set_sha256"], r"^[0-9a-f]{64}$")
            self.assertNotIn("skills", payload)
            serialized = str(events[0]["details"])
            self.assertNotIn(description_marker, serialized)
            self.assertNotIn(body_marker, serialized)
            self.assertNotIn("RAW-REQUEST-MUST-NOT-APPEAR", serialized)

    def test_sixteen_item_list_stays_within_activity_budget_and_digest_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            telemetry, store, task_id, _names, _digests, _description, _body = self._fixture(
                Path(tmp), skill_count=16
            )
            first = telemetry.list_for_agent(task_id, "research")
            second = telemetry.list_for_agent(task_id, "research")
            self.assertEqual(len(first), 16)
            self.assertEqual(len(second), 16)

            events = self._events(store, task_id, ACTION_LISTED)
            self.assertEqual(len(events), 2)
            first_payload = json.loads(str(events[0]["details"]))
            second_payload = json.loads(str(events[1]["details"]))
            self.assertEqual(first_payload["count"], 16)
            self.assertEqual(
                first_payload["skill_set_sha256"],
                second_payload["skill_set_sha256"],
            )
            self.assertLessEqual(len(str(events[0]["details"])), 800)
            self.assertNotIn("skills", first_payload)

    def test_search_does_not_log_query_or_description(self):
        with tempfile.TemporaryDirectory() as tmp:
            telemetry, store, task_id, _names, _digests, description_marker, body_marker = self._fixture(
                Path(tmp)
            )
            rows = telemetry.search_for_agent(
                task_id,
                "research",
                query=description_marker,
                domain="network",
            )
            self.assertEqual(len(rows), 1)
            event = self._events(store, task_id, ACTION_LISTED)[0]
            payload = json.loads(str(event["details"]))
            self.assertEqual(payload["surface"], "search")
            self.assertRegex(payload["skill_set_sha256"], r"^[0-9a-f]{64}$")
            serialized = str(event["details"])
            self.assertNotIn(description_marker, serialized)
            self.assertNotIn(body_marker, serialized)

    def test_view_records_only_exact_production_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            telemetry, store, task_id, names, digests, description_marker, body_marker = self._fixture(
                Path(tmp)
            )
            name = names[0]
            block = telemetry.view_for_agent(task_id, "research", name)
            self.assertIn(body_marker, block)

            event = self._events(store, task_id, ACTION_VIEWED)[0]
            payload = json.loads(str(event["details"]))
            self.assertEqual(payload["surface"], "view")
            self.assertEqual(payload["count"], 1)
            self.assertEqual(payload["skills"][0]["production_sha256"], digests[name])
            serialized = str(event["details"])
            self.assertNotIn(description_marker, serialized)
            self.assertNotIn(body_marker, serialized)

    def test_failed_view_emits_no_view_event(self):
        with tempfile.TemporaryDirectory() as tmp:
            telemetry, store, task_id, names, _digests, _description, _body = self._fixture(Path(tmp))
            with self.assertRaises(SkillSecurityError):
                telemetry.view_for_agent(task_id, "presentation", names[0])
            self.assertEqual(self._events(store, task_id, ACTION_VIEWED), [])

    def test_runtime_identity_resolution_uses_audited_registry_not_optional_search_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            telemetry, _store, _task_id, names, digests, _description, _body = self._fixture(
                Path(tmp), invalid_optional_metadata=True
            )
            name = names[0]
            identities = telemetry.identities_for_names("research", (name,))
            self.assertEqual(len(identities), 1)
            self.assertEqual(identities[0].name, name)
            self.assertEqual(identities[0].production_sha256, digests[name])

    def test_selected_event_is_task_bound_and_metadata_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            telemetry, store, task_id, names, digests, description_marker, body_marker = self._fixture(
                Path(tmp)
            )
            name = names[0]
            identities = telemetry.identities_for_names("research", (name,))
            telemetry.record_selected(task_id, "research", identities)

            event = self._events(store, task_id, ACTION_SELECTED)[0]
            self.assertEqual(str(event["agent_id"]), "research")
            payload = json.loads(str(event["details"]))
            self.assertEqual(payload["surface"], "runtime_selection")
            self.assertEqual(payload["count"], 1)
            self.assertEqual(
                payload["skills"],
                [{"name": name, "production_sha256": digests[name]}],
            )
            serialized = str(event["details"])
            self.assertNotIn(description_marker, serialized)
            self.assertNotIn(body_marker, serialized)
            self.assertNotIn("RAW-REQUEST-MUST-NOT-APPEAR", serialized)


if __name__ == "__main__":
    unittest.main()
