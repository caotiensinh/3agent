from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

from three_agent.chat_gateway import workspace_ui_capabilities
from three_agent.config import load_config


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_PROFILE = ROOT / "config" / "local.public-research.example.json"
MIGRATOR_PATH = ROOT / "scripts" / "migrate_default_web_search_config.py"


def load_migrator():
    spec = importlib.util.spec_from_file_location("migrate_default_web_search_config", MIGRATOR_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load Web Search config migrator")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DefaultWebSearchPolicyTests(unittest.TestCase):
    def test_new_local_profile_enables_chat_web_search_with_strict_egress(self):
        config = load_config(str(DEFAULT_PROFILE))
        capability = workspace_ui_capabilities(config)["features"]["web_search"]

        self.assertTrue(capability["enabled"])
        self.assertEqual(capability["state_label"], "Ready")
        self.assertEqual(config.confidentiality_mode, "public-research")
        self.assertFalse(config.test_mode_full_access)
        self.assertEqual(config.internet_gateway.mode, "strict")
        self.assertTrue(config.internet_gateway.public_search_enabled)
        self.assertFalse(config.internet_gateway.allow_all)
        self.assertTrue(config.internet_gateway.direct_egress)
        self.assertEqual(config.internet_gateway.allowed_content_hosts, ())
        self.assertEqual(
            config.internet_gateway.allowed_search_hosts,
            ("html.duckduckgo.com", "lite.duckduckgo.com", "www.bing.com"),
        )

    def test_legacy_generated_default_migrates_without_changing_model_or_paths(self):
        migrator = load_migrator()
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "local.json"
            old = json.loads((ROOT / "config" / "test.example.json").read_text(encoding="utf-8"))
            old["llm"]["model"] = "qwen-test"
            old["database_path"] = "custom-data/tasks.db"
            config_path.write_text(json.dumps(old), encoding="utf-8")

            changed, reason, backup = migrator.migrate_file(config_path)
            self.assertTrue(changed)
            self.assertEqual(reason, "migrated-generated-default")
            self.assertIsNotNone(backup)
            self.assertTrue(backup.is_file())

            migrated = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(migrated["environment"], "local")
            self.assertEqual(migrated["confidentiality_mode"], "public-research")
            self.assertFalse(migrated["test_mode_full_access"])
            self.assertEqual(migrated["internet_gateway"]["mode"], "strict")
            self.assertTrue(migrated["internet_gateway"]["public_search_enabled"])
            self.assertFalse(migrated["internet_gateway"]["allow_all_outbound_in_test"])
            self.assertTrue(migrated["internet_gateway"]["direct_egress"])
            self.assertEqual(migrated["internet_gateway"]["allowed_content_hosts"], [])
            self.assertFalse(migrated["execution_gateway"]["allow_all_commands_in_test"])
            self.assertEqual(migrated["llm"]["model"], "qwen-test")
            self.assertEqual(migrated["database_path"], "custom-data/tasks.db")

            config = load_config(str(config_path))
            self.assertTrue(workspace_ui_capabilities(config)["features"]["web_search"]["enabled"])

    def test_migration_is_idempotent(self):
        migrator = load_migrator()
        with tempfile.TemporaryDirectory() as tmp:
            config_path = Path(tmp) / "local.json"
            config_path.write_text(
                (ROOT / "config" / "test.example.json").read_text(encoding="utf-8"),
                encoding="utf-8",
            )
            first_changed, _, backup = migrator.migrate_file(config_path)
            first_payload = config_path.read_text(encoding="utf-8")
            second_changed, reason, second_backup = migrator.migrate_file(config_path)

            self.assertTrue(first_changed)
            self.assertFalse(second_changed)
            self.assertEqual(reason, "custom-or-already-migrated")
            self.assertIsNone(second_backup)
            self.assertEqual(config_path.read_text(encoding="utf-8"), first_payload)
            self.assertTrue(backup.is_file())

    def test_custom_and_confidential_configs_are_never_auto_migrated(self):
        migrator = load_migrator()
        with tempfile.TemporaryDirectory() as tmp:
            for name, mutate in (
                ("custom.json", lambda data: data["internet_gateway"].update({"public_search_enabled": True})),
                ("confidential.json", lambda data: data.update({"confidentiality_mode": "confidential"})),
            ):
                config_path = Path(tmp) / name
                payload = json.loads((ROOT / "config" / "test.example.json").read_text(encoding="utf-8"))
                mutate(payload)
                config_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
                before = config_path.read_bytes()

                changed, reason, backup = migrator.migrate_file(config_path)

                self.assertFalse(changed)
                self.assertEqual(reason, "custom-or-already-migrated")
                self.assertIsNone(backup)
                self.assertEqual(config_path.read_bytes(), before)

    def test_bootstraps_seed_secure_profile_and_ubuntu_update_runs_migration(self):
        bootstrap_sh = (ROOT / "scripts" / "bootstrap.sh").read_text(encoding="utf-8")
        bootstrap_ps1 = (ROOT / "scripts" / "bootstrap.ps1").read_text(encoding="utf-8")
        ubuntu_update = (ROOT / "scripts" / "update_workspace_ubuntu.sh").read_text(encoding="utf-8")

        self.assertIn("config/local.public-research.example.json", bootstrap_sh)
        self.assertIn("config\\local.public-research.example.json", bootstrap_ps1)
        self.assertNotIn('cp "${INSTALL_DIR}/config/test.example.json" "$CONFIG_PATH"', bootstrap_sh)
        self.assertNotIn("config\\test.example.json') $ConfigPath", bootstrap_ps1)
        self.assertIn("migrate_default_web_search_config.py", bootstrap_sh)
        self.assertIn("migrate_default_web_search_config.py", bootstrap_ps1)
        self.assertIn("migrate_default_web_search_config.py", ubuntu_update)


if __name__ == "__main__":
    unittest.main()
