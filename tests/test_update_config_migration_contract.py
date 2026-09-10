from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "scripts" / "update_code_safe.sh"


class UpdateConfigMigrationContractTests(unittest.TestCase):
    def test_candidate_config_repair_runs_before_smoke_verification(self):
        text = UPDATER.read_text(encoding="utf-8")
        main = text.split("main() {", 1)[1]

        self.assertIn(
            'ensure_config "$active"\n    migrate_config "$active"\n    verify_release "$active"',
            main,
        )
        self.assertIn(
            'build_release "$release"\n  migrate_config "$release"\n  verify_release "$release"',
            main,
        )

    def test_updater_uses_candidate_repair_only_script(self):
        text = UPDATER.read_text(encoding="utf-8")

        self.assertIn(
            'migration_script="${release}/scripts/migrate_default_web_search_config.py"',
            text,
        )
        self.assertIn(
            '"${release}/.venv/bin/python" "$migration_script" --config "$CONFIG_PATH" --repair-only',
            text,
        )

    def test_activation_remains_after_verification(self):
        text = UPDATER.read_text(encoding="utf-8")
        main = text.split("main() {", 1)[1]

        self.assertLess(
            main.index('verify_release "$release"'),
            main.index('activate_release "$release" "$target_sha"'),
        )


if __name__ == "__main__":
    unittest.main()
