from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from three_agent.network_dataset_policy import NetworkDatasetManager

ROOT = Path(__file__).resolve().parents[1]


def _manager_with_temp_roots(root: Path) -> NetworkDatasetManager:
    policy = json.loads(
        (ROOT / "config/network-data-policy.json").read_text(encoding="utf-8")
    )
    registry = json.loads(
        (ROOT / "config/network-datasets.registry.json").read_text(encoding="utf-8")
    )
    policy["paths"] = {
        "incoming_cache_root": str(root / "incoming"),
        "normalized_staging_root": str(root / "normalized"),
        "experience_root": str(root / "experience"),
        "candidate_skill_root": str(root / "skills"),
        "research_root": str(root / "research"),
        "provenance_root": str(root / "provenance"),
    }
    policy_path = root / "policy.json"
    registry_path = root / "registry.json"
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    return NetworkDatasetManager.load(
        policy_path=policy_path,
        registry_path=registry_path,
    )


def _checked_in_ctu_record() -> dict:
    registry = json.loads(
        (ROOT / "config/network-datasets.registry.json").read_text(encoding="utf-8")
    )
    matches = [item for item in registry["datasets"] if item.get("id") == "ctu-13"]
    if len(matches) != 1:
        raise AssertionError("checked-in registry must contain exactly one ctu-13 record")
    return matches[0]


class NetworkSecurityIntelligenceRegistryTests(unittest.TestCase):
    def test_ctu13_flow_variant_is_enterprise_training_approved(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = _manager_with_temp_roots(Path(tmp))
            plan = manager.plan(
                "ctu-13",
                purpose="training",
                variant="bidirectional-netflow",
                estimated_bytes=1024,
                object_count=1,
            )
            record = manager.datasets["ctu-13"]
            self.assertEqual(record.status, "enterprise_approved")
            self.assertIs(record.commercial_use, True)
            self.assertEqual(plan.acquisition_mode, "public_https")
            self.assertEqual(plan.allowlisted_hosts, ("mcfp.felk.cvut.cz",))
            self.assertIn(
                "/publicDatasets/CTU-Malware-Capture-Botnet-",
                plan.allowlisted_path_prefixes,
            )
            self.assertEqual(plan.destination_class, "training_staging")

    def test_ctu13_registry_does_not_admit_executable_or_archive_variant(self):
        # This assertion is about the checked-in registry itself and therefore
        # must not depend on POSIX deployment roots being valid on the test OS.
        record = _checked_in_ctu_record()
        self.assertEqual(set(record["variants"]), {"bidirectional-netflow"})
        formats = set(map(str, record.get("formats", [])))
        self.assertEqual(formats, {"binetflow"})
        self.assertNotIn("exe", formats)
        self.assertNotIn("archive", formats)
        self.assertNotIn("pcap", formats)


if __name__ == "__main__":
    unittest.main()
