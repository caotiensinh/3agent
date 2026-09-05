import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class WorkSpaceZoneConfigTests(unittest.TestCase):
    def load(self, name: str) -> dict:
        return json.loads((ROOT / "config" / name).read_text(encoding="utf-8"))

    def test_confidential_core_keeps_public_search_fail_closed_without_direct_egress(self):
        config = self.load("workspace.secure.json")
        self.assertEqual(config["product_name"], "WorkSpace")
        self.assertEqual(config["confidentiality_mode"], "confidential")
        self.assertFalse(config["test_mode_full_access"])
        gateway = config["internet_gateway"]
        self.assertFalse(gateway["public_search_enabled"])
        self.assertEqual(gateway["mode"], "strict")
        self.assertEqual(gateway["egress_policy"], "workspace.internet-egress/v1")
        self.assertEqual(gateway["egress_mode"], "sanitized")
        self.assertTrue(gateway["user_warning_on_transform"])
        self.assertFalse(gateway["allow_all_outbound_in_test"])
        self.assertFalse(gateway["direct_egress"])
        self.assertTrue(gateway["allowed_search_hosts"])

    def test_public_research_uses_separate_data_root_and_no_shell_gateway(self):
        config = self.load("workspace.public-research.json")
        self.assertEqual(config["confidentiality_mode"], "public-research")
        self.assertTrue(config["database_path"].startswith("/var/lib/workspace-public/"))
        self.assertTrue(config["artifact_root"].startswith("/var/lib/workspace-public/"))
        self.assertNotIn("/var/lib/workspace/", config["database_path"])
        self.assertNotIn("/var/lib/workspace/", config["artifact_root"])
        self.assertTrue(config["internet_gateway"]["public_search_enabled"])
        self.assertFalse(config["internet_gateway"]["direct_egress"])
        self.assertFalse(config["execution_gateway"]["enabled"])
        self.assertFalse(config["github"]["enabled"])


if __name__ == "__main__":
    unittest.main()
