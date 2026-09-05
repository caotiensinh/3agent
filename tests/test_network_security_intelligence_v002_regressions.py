from __future__ import annotations

import csv
import hashlib
import inspect
import tempfile
import unittest
from pathlib import Path

from three_agent.network_corpus_adapter import AdapterInputContract
from three_agent.network_ctu13_adapter import (
    CTU13_ADAPTER_VERSION,
    CTU13_COLUMNS,
    CTU13BidirectionalFlowAdapter,
)
from three_agent.network_public_corpus_acquisition import (
    PublicCorpusAcquisitionError,
    PublicCorpusFetcher,
)
import three_agent.network_public_corpus_acquisition as acquisition_module


def _contract(payload: bytes) -> AdapterInputContract:
    return AdapterInputContract.from_dict(
        {
            "dataset_id": "ctu-13",
            "variant": "bidirectional-netflow",
            "source_object_ref": "ctu13/self-flow.binetflow",
            "source_sha256": "sha256:" + hashlib.sha256(payload).hexdigest(),
            "actual_source_size_bytes": len(payload),
            "max_plan_bytes": len(payload) + 1024,
            "acquisition_plan_fingerprint": "sha256:" + "a" * 64,
            "registry_fingerprint": "sha256:" + "b" * 64,
            "policy_fingerprint": "sha256:" + "c" * 64,
            "provenance_ref": "prov://ctu13/self-flow",
            "adapter_version": CTU13_ADAPTER_VERSION,
        }
    )


class NetworkSecurityIntelligenceV002RegressionTests(unittest.TestCase):
    def test_ctu_self_flow_deduplicates_asset_refs_instead_of_failing_stream(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "self.binetflow"
            values = {
                "StartTime": "2011/08/10 09:46:53.047277",
                "Dur": "0.1",
                "Proto": "tcp",
                "SrcAddr": "147.32.84.170",
                "Sport": "12345",
                "Dir": "->",
                "DstAddr": "147.32.84.170",
                "Dport": "8080",
                "State": "S_RA",
                "sTos": "0",
                "dTos": "0",
                "TotPkts": "2",
                "TotBytes": "100",
                "SrcBytes": "50",
                "Label": "flow=Normal",
            }
            with path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle, lineterminator="\n")
                writer.writerow(CTU13_COLUMNS)
                writer.writerow([values[column] for column in CTU13_COLUMNS])
            payload = path.read_bytes()
            adapter = CTU13BidirectionalFlowAdapter()
            inspection = adapter.inspect(path, authorized_root=root, contract=_contract(payload))
            item = list(adapter.iterate(path, inspection=inspection))[0]
            self.assertEqual(item.evidence.asset_refs, ("147.32.84.170",))

    def test_atomic_stage_commit_refuses_target_created_after_precheck(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            part = root / ".candidate.part"
            target = root / "candidate.binetflow"
            part.write_bytes(b"new-public-corpus-bytes")
            target.write_bytes(b"concurrent-writer-wins")
            with self.assertRaisesRegex(PublicCorpusAcquisitionError, "DESTINATION_EXISTS"):
                PublicCorpusFetcher._commit_no_overwrite(part, target)
            self.assertEqual(target.read_bytes(), b"concurrent-writer-wins")
            self.assertEqual(part.read_bytes(), b"new-public-corpus-bytes")

    def test_operator_fetcher_never_uses_replace_overwrite_commit(self):
        source = inspect.getsource(acquisition_module)
        self.assertNotIn("os.replace", source)
        self.assertIn("os.link", source)
        self.assertIn("follow_symlinks=False", source)


if __name__ == "__main__":
    unittest.main()
