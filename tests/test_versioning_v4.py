from __future__ import annotations

import tomllib
import unittest
from pathlib import Path

from three_agent.version import (
    DISPLAY_VERSION,
    PACKAGE_VERSION,
    RELEASE_GENERATION,
    VERSION_SCHEME,
)


class WorkSpaceV4VersioningTests(unittest.TestCase):
    def test_product_version_is_ver_0_0_2(self):
        self.assertEqual(DISPLAY_VERSION, "ver.0.0.2")
        self.assertEqual(RELEASE_GENERATION, "v4")
        self.assertEqual(VERSION_SCHEME, "workspace-release/v2")

    def test_pep440_epoch_preserves_upgrade_order_but_is_not_display_label(self):
        self.assertEqual(PACKAGE_VERSION, "1!0.0.2")
        self.assertNotIn("1!", DISPLAY_VERSION)

    def test_pyproject_matches_package_version_and_preserves_both_acceptance_clis(self):
        root = Path(__file__).resolve().parents[1]
        data = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        project = data["project"]
        scripts = project["scripts"]
        self.assertEqual(project["version"], PACKAGE_VERSION)
        self.assertEqual(scripts["workspace-chat"], "three_agent.chat_gateway_v22:main")
        self.assertEqual(scripts["three-agent-chat"], "three_agent.chat_gateway_v22:main")
        self.assertEqual(
            scripts["workspace-chat-acceptance"],
            "three_agent.chat_acceptance:main",
        )
        self.assertEqual(
            scripts["workspace-chat-multiturn-acceptance"],
            "three_agent.chat_multiturn_acceptance_v2:main",
        )
        self.assertTrue((root / "src/three_agent/chat_gateway_v17.py").is_file())
        self.assertTrue((root / "src/three_agent/chat_gateway_v18.py").is_file())
        self.assertTrue((root / "src/three_agent/chat_gateway_v19.py").is_file())
        self.assertTrue((root / "src/three_agent/chat_gateway_v20.py").is_file())
        self.assertTrue((root / "src/three_agent/chat_gateway_v21.py").is_file())
        self.assertTrue((root / "src/three_agent/chat_gateway_v22.py").is_file())
        self.assertTrue((root / "src/three_agent/workspace_frontend_v18.py").is_file())


if __name__ == "__main__":
    unittest.main()
