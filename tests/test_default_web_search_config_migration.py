from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "migrate_default_web_search_config.py"
SPEC = importlib.util.spec_from_file_location("workspace_web_search_migration", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MIGRATION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MIGRATION)


def old_generated_payload(*, adaptive_enabled: bool | None = None) -> dict:
    payload = {
        "product_name": "WorkSpace",
        "environment": "test",
        "confidentiality_mode": "development-test",
        "test_mode_full_access": True,
        "internet_gateway": {
            "enabled": True,
            "mode": "legacy_test",
            "public_search_enabled": False,
            "allow_all_outbound_in_test": True,
            "audit_log": "data/activity/internet.jsonl",
        },
        "execution_gateway": {
            "enabled": True,
            "allow_all_commands_in_test": True,
            "audit_log": "data/activity/execution.jsonl",
        },
        "database": "data/workspace.db",
    }
    if adaptive_enabled is not None:
        payload["adaptive_learning"] = {
            "enabled": adaptive_enabled,
            "domain": "network_security",
            "store_path": "data/adaptive/learning.db",
            "checkpoint_journal_path": "data/adaptive/checkpoint.jsonl",
            "checkpoint_key_env": "WORKSPACE_ADAPTIVE_CHECKPOINT_KEY",
        }
    return payload


class DefaultWebSearchConfigMigrationTests(unittest.TestCase):
    def test_stock_generated_default_keeps_dedicated_public_research_zone(self):
        migrated, changed, reason = MIGRATION.migrate_payload(old_generated_payload())

        self.assertTrue(changed)
        self.assertEqual(reason, "migrated-generated-default")
        self.assertEqual(migrated["environment"], "public-research-zone")
        self.assertEqual(migrated["confidentiality_mode"], "public-research")
        self.assertFalse(migrated["test_mode_full_access"])
        self.assertTrue(migrated["internet_gateway"]["public_search_enabled"])
        self.assertEqual(migrated["internet_gateway"]["mode"], "strict")
        self.assertFalse(migrated["internet_gateway"]["allow_all_outbound_in_test"])
        self.assertFalse(migrated["execution_gateway"]["allow_all_commands_in_test"])

    def test_enabled_adaptive_learning_uses_public_mode_without_restoring_test_authority(self):
        original = old_generated_payload(adaptive_enabled=True)
        migrated, changed, reason = MIGRATION.migrate_payload(original)

        self.assertTrue(changed)
        self.assertEqual(reason, "migrated-generated-default-adaptive-compatible")
        self.assertEqual(migrated["environment"], original["environment"])
        self.assertEqual(migrated["confidentiality_mode"], "public")
        self.assertTrue(migrated["adaptive_learning"]["enabled"])
        self.assertFalse(migrated["test_mode_full_access"])
        self.assertTrue(migrated["internet_gateway"]["public_search_enabled"])
        self.assertEqual(migrated["internet_gateway"]["mode"], "strict")
        self.assertFalse(migrated["internet_gateway"]["allow_all_outbound_in_test"])
        self.assertFalse(migrated["execution_gateway"]["allow_all_commands_in_test"])

    def test_disabled_adaptive_learning_does_not_leave_public_research_zone(self):
        migrated, changed, _ = MIGRATION.migrate_payload(
            old_generated_payload(adaptive_enabled=False)
        )
        self.assertTrue(changed)
        self.assertEqual(migrated["confidentiality_mode"], "public-research")
        self.assertEqual(migrated["environment"], "public-research-zone")

    def test_prior_buggy_migration_is_repaired_only_with_matching_provenance(self):
        original = old_generated_payload(adaptive_enabled=True)
        buggy = MIGRATION._apply_secure_web_search(
            original, adaptive_compatible=False
        )

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "local.json"
            provenance = path.with_name(path.name + ".pre-public-research.bak")
            path.write_text(json.dumps(buggy), encoding="utf-8")
            provenance.write_text(json.dumps(original), encoding="utf-8")

            changed, reason, repair_backup = MIGRATION.migrate_file(path)
            repaired = json.loads(path.read_text(encoding="utf-8"))

            self.assertTrue(changed)
            self.assertEqual(reason, "repaired-adaptive-public-research-conflict")
            self.assertIsNotNone(repair_backup)
            self.assertTrue(repair_backup.is_file())
            self.assertEqual(repaired["environment"], "test")
            self.assertEqual(repaired["confidentiality_mode"], "public")
            self.assertTrue(repaired["adaptive_learning"]["enabled"])
            self.assertEqual(repaired["internet_gateway"]["mode"], "strict")
            self.assertTrue(repaired["internet_gateway"]["public_search_enabled"])
            self.assertFalse(repaired["internet_gateway"]["allow_all_outbound_in_test"])
            self.assertFalse(repaired["execution_gateway"]["allow_all_commands_in_test"])

    def test_prior_buggy_migration_without_backup_fails_closed(self):
        original = old_generated_payload(adaptive_enabled=True)
        buggy = MIGRATION._apply_secure_web_search(
            original, adaptive_compatible=False
        )

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "local.json"
            path.write_text(json.dumps(buggy), encoding="utf-8")

            changed, reason, backup = MIGRATION.migrate_file(path)

            self.assertFalse(changed)
            self.assertEqual(reason, "adaptive-repair-provenance-missing")
            self.assertIsNone(backup)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), buggy)

    def test_prior_buggy_migration_with_adaptive_mismatch_fails_closed(self):
        original = old_generated_payload(adaptive_enabled=True)
        buggy = MIGRATION._apply_secure_web_search(
            original, adaptive_compatible=False
        )
        buggy["adaptive_learning"]["domain"] = "different_domain"

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "local.json"
            provenance = path.with_name(path.name + ".pre-public-research.bak")
            path.write_text(json.dumps(buggy), encoding="utf-8")
            provenance.write_text(json.dumps(original), encoding="utf-8")

            changed, reason, backup = MIGRATION.migrate_file(path)

            self.assertFalse(changed)
            self.assertEqual(reason, "adaptive-repair-provenance-mismatch")
            self.assertIsNone(backup)


if __name__ == "__main__":
    unittest.main()
