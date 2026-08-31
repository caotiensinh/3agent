from __future__ import annotations

import unittest
from pathlib import Path

from three_agent.network_dataset_policy import NetworkDatasetManager

ROOT = Path(__file__).resolve().parents[1]


class NetworkSecurityIntelligenceRegistryTests(unittest.TestCase):
    def test_ctu13_flow_variant_is_enterprise_training_approved(self):
        manager = NetworkDatasetManager.load(
            policy_path=ROOT / "config/network-data-policy.json",
            registry_path=ROOT / "config/network-datasets.registry.json",
        )
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
        self.assertIn("/publicDatasets/CTU-Malware-Capture-Botnet-", plan.allowlisted_path_prefixes)
        self.assertEqual(plan.destination_class, "training_staging")

    def test_ctu13_registry_does_not_admit_executable_or_archive_variant(self):
        manager = NetworkDatasetManager.load(
            policy_path=ROOT / "config/network-data-policy.json",
            registry_path=ROOT / "config/network-datasets.registry.json",
        )
        record = manager.datasets["ctu-13"]
        self.assertEqual(set(record.variants), {"bidirectional-netflow"})
        formats = set(map(str, record.raw.get("formats", [])))
        self.assertEqual(formats, {"binetflow"})
        self.assertNotIn("exe", formats)
        self.assertNotIn("archive", formats)
        self.assertNotIn("pcap", formats)


if __name__ == "__main__":
    unittest.main()
