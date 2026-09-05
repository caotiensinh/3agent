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

PUBLIC_A = [(2, 1, 6, "", ("93.184.216.34", 443))]
PUBLIC_B = [(2, 1, 6, "", ("8.8.8.8", 443))]
PRIVATE = [(2, 1, 6, "", ("127.0.0.1", 443))]
SOURCE_URL = (
    "https://mcfp.felk.cvut.cz/publicDatasets/"
    "CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow"
)


class SequenceResolver:
    def __init__(self, answers):
        self.answers = list(answers)
        self.calls = 0

    def __call__(self, *args, **kwargs):
        index = min(self.calls, len(self.answers) - 1)
        self.calls += 1
        return self.answers[index]


class FakeHTTPResponse:
    def __init__(self, payload: bytes):
        self.status = 200
        self.headers = {"Content-Length": str(len(payload))}
        self._payload = payload
        self._offset = 0
        self.closed = False

    def getheader(self, name: str):
        return self.headers.get(name)

    def read(self, size: int = -1) -> bytes:
        if self._offset >= len(self._payload):
            return b""
        if size < 0:
            size = len(self._payload) - self._offset
        chunk = self._payload[self._offset:self._offset + size]
        self._offset += len(chunk)
        return chunk

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    def __init__(self, response: FakeHTTPResponse):
        self.response = response
        self.requests = []
        self.closed = False

    def request(self, method: str, target: str, headers=None) -> None:
        self.requests.append((method, target, dict(headers or {})))

    def getresponse(self) -> FakeHTTPResponse:
        return self.response

    def close(self) -> None:
        self.closed = True


class RecordingConnectionFactory:
    def __init__(self, payload: bytes = b"fixture\n"):
        self.payload = payload
        self.calls = []
        self.connections = []

    def __call__(self, host: str, pinned_ip: str, *, timeout: float):
        self.calls.append((host, pinned_ip, timeout))
        connection = FakeConnection(FakeHTTPResponse(self.payload))
        self.connections.append(connection)
        return connection


def _manager(root: Path) -> NetworkDatasetManager:
    policy_path = root / "policy.json"
    registry_path = root / "registry.json"
    policy_path.write_text(
        json.dumps(
            {
                "schema_version": "workspace-network-data-policy/v1",
                "paths": {
                    "incoming_cache_root": str(root / "incoming"),
                    "normalized_staging_root": str(root / "normalized"),
                    "experience_root": str(root / "experience"),
                    "candidate_skill_root": str(root / "skills"),
                    "research_root": str(root / "research"),
                    "provenance_root": str(root / "provenance"),
                },
                "cache": {
                    "max_bytes": 1024 * 1024,
                    "max_job_bytes": 1024 * 1024,
                    "max_objects_per_job": 4,
                    "allow_full_sync": False,
                    "raw_retention": "ephemeral",
                    "normalized_retention": "until_experience_extracted",
                    "eviction_policy": "lru_unpinned",
                },
                "promotion": {
                    "required_digest": "sha256",
                    "enterprise_allowed_statuses": ["enterprise_approved"],
                    "research_allowed_statuses": ["enterprise_approved", "research_only"],
                    "deny_statuses": ["review_required", "blocked"],
                    "durable_outputs": ["experience_case", "evidence_pattern", "provenance"],
                    "raw_logs_durable": False,
                    "normalized_events_durable": False,
                    "candidate_skills_auto_approve": False,
                    "minimum_independent_cases_for_pattern": 2,
                },
                "network": {
                    "methods": ["GET", "HEAD"],
                    "https_only": True,
                    "allow_redirects": True,
                    "max_redirects": 3,
                    "deny_private_special_destinations": True,
                    "credentials_allowed": False,
                    "caller_headers_allowed": False,
                },
            }
        ),
        encoding="utf-8",
    )
    registry_path.write_text(
        json.dumps(
            {
                "schema_version": "workspace-network-dataset-registry/v1",
                "datasets": [
                    {
                        "id": "ctu-13",
                        "name": "CTU-13 Botnet Dataset",
                        "status": "enterprise_approved",
                        "license": {
                            "commercial_use": True,
                            "source": "https://www.stratosphereips.org/datasets-overview/",
                        },
                        "acquisition": {
                            "mode": "public_https",
                            "allowlisted_hosts": ["mcfp.felk.cvut.cz"],
                            "allowlisted_path_prefixes": [
                                "/publicDatasets/CTU-Malware-Capture-Botnet-"
                            ],
                            "allowlisted_source_suffixes": [".binetflow"],
                            "credentials": False,
                        },
                        "variants": {
                            "bidirectional-netflow": {
                                "purpose": ["training"],
                                "recommended": True,
                            }
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return NetworkDatasetManager.load(policy_path=policy_path, registry_path=registry_path)


def _plan(manager: NetworkDatasetManager):
    return manager.plan(
        "ctu-13",
        purpose="training",
        estimated_bytes=1024,
        object_count=1,
        variant="bidirectional-netflow",
        full_sync=False,
    )


class PublicCorpusDNSPinningTests(unittest.TestCase):
    def test_dns_rebinding_to_private_address_is_denied_before_tcp_connect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = _manager(root)
            resolver = SequenceResolver([PUBLIC_A, PRIVATE])
            connections = RecordingConnectionFactory()
            fetcher = PublicCorpusFetcher(
                manager,
                resolver=resolver,
                connection_factory=connections,
            )
            with self.assertRaisesRegex(
                PublicCorpusAcquisitionError,
                "PRIVATE_SPECIAL_DESTINATION_DENIED",
            ):
                fetcher.fetch(
                    plan=_plan(manager),
                    source_url=SOURCE_URL,
                    output_name="scenario42.binetflow",
                )
            self.assertEqual(connections.calls, [])
            self.assertFalse(
                (root / "incoming" / "ctu-13" / "bidirectional-netflow" / "scenario42.binetflow").exists()
            )

    def test_transport_connects_to_the_address_from_its_own_public_dns_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = _manager(root)
            resolver = SequenceResolver([PUBLIC_A, PUBLIC_B, PUBLIC_B])
            connections = RecordingConnectionFactory(payload=b"flow-data\n")
            fetcher = PublicCorpusFetcher(
                manager,
                resolver=resolver,
                connection_factory=connections,
            )
            receipt = fetcher.fetch(
                plan=_plan(manager),
                source_url=SOURCE_URL,
                output_name="scenario42.binetflow",
            )
            self.assertGreaterEqual(resolver.calls, 3)
            self.assertEqual(
                connections.calls,
                [("mcfp.felk.cvut.cz", "8.8.8.8", 30)],
            )
            self.assertEqual(Path(receipt.destination_path).read_bytes(), b"flow-data\n")


if __name__ == "__main__":
    unittest.main()
