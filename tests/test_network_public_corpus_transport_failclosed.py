from __future__ import annotations

import http.client
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.network_public_corpus_acquisition import (
    PublicCorpusAcquisitionError,
    PublicCorpusFetcher,
)

SOURCE_URL = (
    "https://mcfp.felk.cvut.cz/publicDatasets/"
    "CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow"
)
PUBLIC_IP_RESULT = [(2, 1, 6, "", ("93.184.216.34", 443))]


class _Plan:
    dataset_id = "ctu-13"
    variant = "bidirectional-netflow"
    purpose = "training"
    estimated_bytes = 1024
    object_count = 1
    full_sync = False
    registry_fingerprint = "registry-v1"
    policy_fingerprint = "policy-v1"
    allowlisted_hosts = ("mcfp.felk.cvut.cz",)
    allowlisted_path_prefixes = ("/publicDatasets/CTU-Malware-Capture-Botnet-",)

    def as_dict(self):
        return {
            "dataset_id": self.dataset_id,
            "variant": self.variant,
            "purpose": self.purpose,
        }


class _InterruptedResponse:
    def __init__(self):
        self.headers = {}
        self.read_calls = 0

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def geturl(self) -> str:
        return SOURCE_URL

    def read(self, size: int) -> bytes:
        self.read_calls += 1
        if self.read_calls == 1:
            return b"partial-flow-data"
        raise http.client.IncompleteRead(b"", 32)


class _Opener:
    def __init__(self):
        self.response = _InterruptedResponse()
        self.calls = 0

    def open(self, request, timeout=0):
        self.calls += 1
        return self.response


def _manager(root: Path, *, deny_private: bool = True):
    policy = SimpleNamespace(
        raw={
            "network": {
                "https_only": True,
                "allow_redirects": True,
                "max_redirects": 3,
                "deny_private_special_destinations": deny_private,
                "credentials_allowed": False,
                "caller_headers_allowed": False,
            }
        },
        incoming_cache_root=root / "incoming",
    )
    dataset = SimpleNamespace(
        raw={
            "acquisition": {
                "allowlisted_source_suffixes": [".binetflow"],
            }
        }
    )
    return SimpleNamespace(
        policy=policy,
        policy_fingerprint="policy-v1",
        registry_fingerprint="registry-v1",
        datasets={"ctu-13": dataset},
    )


class PublicCorpusTransportFailClosedTests(unittest.TestCase):
    def test_policy_cannot_disable_private_special_destination_denial(self):
        with tempfile.TemporaryDirectory() as tmp:
            manager = _manager(Path(tmp), deny_private=False)
            with self.assertRaisesRegex(PublicCorpusAcquisitionError, "NETWORK_POLICY_INVALID"):
                PublicCorpusFetcher(manager)

    def test_http_protocol_failure_removes_partial_staging_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = _manager(root)
            opener = _Opener()
            fetcher = PublicCorpusFetcher(
                manager,
                resolver=lambda *args, **kwargs: PUBLIC_IP_RESULT,
                opener=opener,
            )
            with self.assertRaisesRegex(PublicCorpusAcquisitionError, "FETCH_FAILED"):
                fetcher.fetch(
                    plan=_Plan(),
                    source_url=SOURCE_URL,
                    output_name="fail.binetflow",
                )

            target_dir = root / "incoming" / "ctu-13" / "bidirectional-netflow"
            self.assertFalse((target_dir / "fail.binetflow").exists())
            self.assertFalse((target_dir / f".fail.binetflow.part.{os.getpid()}").exists())
            self.assertEqual(opener.calls, 1)


if __name__ == "__main__":
    unittest.main()
