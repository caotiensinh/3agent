from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime
from pathlib import Path

from three_agent.network_corpus_adapter import EvidenceRecord
from three_agent.network_dataset_policy import NetworkDatasetManager
from three_agent.network_public_corpus_acquisition import (
    PublicCorpusAcquisitionError,
    PublicCorpusFetcher,
)
from three_agent.network_security_intelligence import (
    NetworkSecurityIntelligenceAnalyzer,
    NetworkSecurityIntelligenceConfig,
    NetworkSecurityIntelligenceError,
)

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_IP_RESULT = [(2, 1, 6, "", ("93.184.216.34", 443))]


class NeverOpen:
    def __init__(self):
        self.calls = 0

    def open(self, request, timeout=0):
        self.calls += 1
        raise AssertionError("network opener must not be reached for denied input")


def _manager(root: Path) -> NetworkDatasetManager:
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


def _non_flow(ordinal: int) -> EvidenceRecord:
    return EvidenceRecord.build(
        dataset_id="lanl-comprehensive",
        source_domain="authentication",
        source_object_ref="lanl/auth-fixture.txt",
        source_sha256="sha256:" + "f" * 64,
        adapter_version="fixture/0.1",
        record_ordinal=ordinal,
        timestamp=datetime(2026, 9, 1, 0, 0, ordinal).isoformat(),
        asset_refs=[f"host-{ordinal}"],
        account_refs=[f"user-{ordinal}"],
        network_refs=[],
        event_family="authentication",
        event_type="login",
        observation_fields={"result": "success"},
        provenance_ref="prov://fixture/non-flow",
    )


class FinalBoundaryTests(unittest.TestCase):
    def test_analyzer_budget_counts_non_flow_input_too(self):
        analyzer = NetworkSecurityIntelligenceAnalyzer(
            NetworkSecurityIntelligenceConfig(max_records=2)
        )
        with self.assertRaisesRegex(
            NetworkSecurityIntelligenceError, "analysis input record budget exceeded"
        ):
            analyzer.analyze([_non_flow(0), _non_flow(1), _non_flow(2)])

    def test_percent_encoded_dot_traversal_is_denied_before_network_open(self):
        encoded_traversal_url = (
            "https://mcfp.felk.cvut.cz/publicDatasets/"
            "CTU-Malware-Capture-Botnet-42/%2e%2e/escape.binetflow"
        )
        with tempfile.TemporaryDirectory() as tmp:
            manager = _manager(Path(tmp))
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
            with self.assertRaisesRegex(
                PublicCorpusAcquisitionError, "SOURCE_PATH_TRAVERSAL_DENIED"
            ):
                fetcher.fetch(
                    plan=plan,
                    source_url=encoded_traversal_url,
                    output_name="escape.binetflow",
                )
            self.assertEqual(opener.calls, 0)


if __name__ == "__main__":
    unittest.main()
