from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from three_agent.network_dataset_policy import NetworkDatasetManager
from three_agent.network_public_corpus_acquisition import (
    PublicCorpusAcquisitionError,
    PublicCorpusFetcher,
)

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_IP_RESULT = [(2, 1, 6, "", ("93.184.216.34", 443))]
GOOD_URL = (
    "https://mcfp.felk.cvut.cz/publicDatasets/"
    "CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture.binetflow"
)
BAD_EXECUTABLE_URL = (
    "https://mcfp.felk.cvut.cz/publicDatasets/"
    "CTU-Malware-Capture-Botnet-42/botnet-capture-20110810-neris.exe"
)


class NeverOpen:
    def __init__(self):
        self.calls = 0

    def open(self, request, timeout=0):
        self.calls += 1
        raise AssertionError("network opener must not be reached for suffix-denied input")


def _manager_with_temp_roots(root: Path) -> NetworkDatasetManager:
    policy = json.loads((ROOT / "config/network-data-policy.json").read_text(encoding="utf-8"))
    registry = json.loads((ROOT / "config/network-datasets.registry.json").read_text(encoding="utf-8"))
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
    return NetworkDatasetManager.load(policy_path=policy_path, registry_path=registry_path)


def _checked_in_ctu_record() -> dict:
    registry = json.loads(
        (ROOT / "config/network-datasets.registry.json").read_text(encoding="utf-8")
    )
    matches = [item for item in registry["datasets"] if item.get("id") == "ctu-13"]
    if len(matches) != 1:
        raise AssertionError("checked-in registry must contain exactly one ctu-13 record")
    return matches[0]


class PublicCorpusSuffixPolicyTests(unittest.TestCase):
    def test_checked_in_ctu_registry_allows_only_binetflow_source_suffix(self):
        # This is a registry-shape assertion. Do not instantiate the Linux
        # deployment policy merely to inspect portable registry metadata.
        acquisition = _checked_in_ctu_record()["acquisition"]
        self.assertEqual(acquisition["allowlisted_source_suffixes"], [".binetflow"])

    def test_ctu_executable_url_is_denied_before_network_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = _manager_with_temp_roots(Path(tmp))
            plan = manager.plan(
                "ctu-13",
                purpose="training",
                variant="bidirectional-netflow",
                estimated_bytes=1024,
                object_count=1,
            )
            opener = NeverOpen()
            fetcher = PublicCorpusFetcher(
                manager,
                resolver=lambda *args, **kwargs: PUBLIC_IP_RESULT,
                opener=opener,
            )
            with self.assertRaisesRegex(PublicCorpusAcquisitionError, "SOURCE_SUFFIX_DENIED"):
                fetcher.fetch(
                    plan=plan,
                    source_url=BAD_EXECUTABLE_URL,
                    output_name="capture.binetflow",
                )
            self.assertEqual(opener.calls, 0)

    def test_ctu_non_binetflow_output_name_is_denied_before_network_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = _manager_with_temp_roots(Path(tmp))
            plan = manager.plan(
                "ctu-13",
                purpose="training",
                variant="bidirectional-netflow",
                estimated_bytes=1024,
                object_count=1,
            )
            opener = NeverOpen()
            fetcher = PublicCorpusFetcher(
                manager,
                resolver=lambda *args, **kwargs: PUBLIC_IP_RESULT,
                opener=opener,
            )
            with self.assertRaisesRegex(PublicCorpusAcquisitionError, "OUTPUT_SUFFIX_DENIED"):
                fetcher.fetch(
                    plan=plan,
                    source_url=GOOD_URL,
                    output_name="capture.exe",
                )
            self.assertEqual(opener.calls, 0)


if __name__ == "__main__":
    unittest.main()
