from __future__ import annotations

import ast
import inspect
import json
import tempfile
import unittest
from pathlib import Path

import three_agent.network_public_corpus_acquisition as acquisition_module
from three_agent.network_dataset_policy import NetworkDatasetManager
from three_agent.network_public_corpus_acquisition import (
    PublicCorpusAcquisitionError,
    PublicCorpusFetcher,
)

PUBLIC_IP_RESULT = [(2, 1, 6, "", ("93.184.216.34", 443))]


class FakeResponse:
    def __init__(self, payload: bytes, url: str, *, announced: int | None = None):
        self.payload = payload
        self.url = url
        self.offset = 0
        self.headers = {}
        if announced is not None:
            self.headers["Content-Length"] = str(announced)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def geturl(self) -> str:
        return self.url

    def read(self, size: int) -> bytes:
        if self.offset >= len(self.payload):
            return b""
        chunk = self.payload[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


class FakeOpener:
    def __init__(self, response: FakeResponse):
        self.response = response
        self.requests = []

    def open(self, request, timeout=0):
        self.requests.append((request, timeout))
        return self.response


def _write_config(root: Path) -> tuple[Path, Path]:
    policy_path = root / "policy.json"
    registry_path = root / "registry.json"
    policy = {
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
    registry = {
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
                    "allowlisted_path_prefixes": ["/publicDatasets/CTU-Malware-Capture-Botnet-"],
                    "credentials": False,
                },
                "variants": {
                    "bidirectional-netflow": {
                        "purpose": ["experience_extraction", "training", "evaluation", "research"],
                        "recommended": True,
                    }
                },
            }
        ],
    }
    policy_path.write_text(json.dumps(policy), encoding="utf-8")
    registry_path.write_text(json.dumps(registry), encoding="utf-8")
    return policy_path, registry_path


def _manager(root: Path) -> NetworkDatasetManager:
    policy, registry = _write_config(root)
    return NetworkDatasetManager.load(policy_path=policy, registry_path=registry)


class PublicCorpusAcquisitionTests(unittest.TestCase):
    source_url = (
        "https://mcfp.felk.cvut.cz/publicDatasets/"
        "CTU-Malware-Capture-Botnet-42/detailed-bidirectional-flow-labels/capture20110810.binetflow"
    )

    def _plan(self, manager: NetworkDatasetManager, estimated_bytes: int = 1024):
        return manager.plan(
            "ctu-13",
            purpose="training",
            estimated_bytes=estimated_bytes,
            object_count=1,
            variant="bidirectional-netflow",
            full_sync=False,
        )

    def test_fetch_stages_one_bounded_object_and_returns_hash_receipt(self):
        payload = b"StartTime,Dur,Proto\nfixture\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = _manager(root)
            response = FakeResponse(payload, self.source_url, announced=len(payload))
            opener = FakeOpener(response)
            fetcher = PublicCorpusFetcher(manager, resolver=lambda *args, **kwargs: PUBLIC_IP_RESULT, opener=opener)
            receipt = fetcher.fetch(plan=self._plan(manager), source_url=self.source_url, output_name="scenario42.binetflow")
            self.assertEqual(receipt.dataset_id, "ctu-13")
            self.assertEqual(receipt.purpose, "training")
            self.assertEqual(receipt.source_size_bytes, len(payload))
            self.assertTrue(receipt.source_sha256.startswith("sha256:"))
            staged = Path(receipt.destination_path)
            self.assertEqual(staged.read_bytes(), payload)
            self.assertIn(str(root / "incoming"), str(staged))
            request, timeout = opener.requests[0]
            self.assertEqual(request.get_method(), "GET")
            self.assertEqual(timeout, 30)
            self.assertIsNone(request.headers.get("Authorization"))

    def test_private_or_special_dns_destination_is_rejected_before_open(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = _manager(root)
            opener = FakeOpener(FakeResponse(b"x", self.source_url))
            fetcher = PublicCorpusFetcher(
                manager,
                resolver=lambda *args, **kwargs: [(2, 1, 6, "", ("127.0.0.1", 443))],
                opener=opener,
            )
            with self.assertRaisesRegex(PublicCorpusAcquisitionError, "PRIVATE_SPECIAL_DESTINATION_DENIED"):
                fetcher.fetch(plan=self._plan(manager), source_url=self.source_url, output_name="x.binetflow")
            self.assertEqual(opener.requests, [])

    def test_http_userinfo_query_wrong_host_and_wrong_path_fail_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = _manager(root)
            fetcher = PublicCorpusFetcher(
                manager,
                resolver=lambda *args, **kwargs: PUBLIC_IP_RESULT,
                opener=FakeOpener(FakeResponse(b"x", self.source_url)),
            )
            bad_urls = (
                self.source_url.replace("https://", "http://"),
                self.source_url.replace("https://", "https://user:pass@"),
                self.source_url + "?token=secret",
                self.source_url.replace("mcfp.felk.cvut.cz", "example.com"),
                "https://mcfp.felk.cvut.cz/not-reviewed/file.binetflow",
            )
            for url in bad_urls:
                with self.subTest(url=url):
                    with self.assertRaises(PublicCorpusAcquisitionError):
                        fetcher.fetch(plan=self._plan(manager), source_url=url, output_name="x.binetflow")

    def test_streamed_or_announced_size_above_plan_is_rejected_and_partial_file_removed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = _manager(root)
            for response in (
                FakeResponse(b"01234567890", self.source_url, announced=11),
                FakeResponse(b"01234567890", self.source_url, announced=None),
            ):
                with self.subTest(announced=response.headers.get("Content-Length")):
                    fetcher = PublicCorpusFetcher(
                        manager,
                        resolver=lambda *args, **kwargs: PUBLIC_IP_RESULT,
                        opener=FakeOpener(response),
                    )
                    with self.assertRaisesRegex(PublicCorpusAcquisitionError, "SOURCE_BYTE_BUDGET_EXCEEDED"):
                        fetcher.fetch(plan=self._plan(manager, estimated_bytes=10), source_url=self.source_url, output_name="too-big.binetflow")
                    self.assertFalse((root / "incoming" / "ctu-13" / "bidirectional-netflow" / "too-big.binetflow").exists())
                    response.offset = 0

    def test_existing_destination_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manager = _manager(root)
            target_dir = root / "incoming" / "ctu-13" / "bidirectional-netflow"
            target_dir.mkdir(parents=True)
            target = target_dir / "existing.binetflow"
            target.write_bytes(b"original")
            fetcher = PublicCorpusFetcher(
                manager,
                resolver=lambda *args, **kwargs: PUBLIC_IP_RESULT,
                opener=FakeOpener(FakeResponse(b"new", self.source_url)),
            )
            with self.assertRaisesRegex(PublicCorpusAcquisitionError, "DESTINATION_EXISTS"):
                fetcher.fetch(plan=self._plan(manager), source_url=self.source_url, output_name=target.name)
            self.assertEqual(target.read_bytes(), b"original")


class PublicCorpusAcquisitionAuthorityTests(unittest.TestCase):
    def test_operator_fetcher_has_no_model_subprocess_package_or_archive_execution_authority(self):
        text = inspect.getsource(acquisition_module)
        tree = ast.parse(text)
        imported_roots: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported_roots.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported_roots.add(node.module.split(".", 1)[0])
        self.assertFalse(imported_roots & {"subprocess", "requests", "openai", "ollama", "tarfile", "zipfile"})
        for forbidden in ("Authorization", "Bearer ", "exec(", "eval(", "extractall", "unpack_archive"):
            self.assertNotIn(forbidden, text)
        self.assertIn("urllib.request", text)
        self.assertIn("ipaddress", text)


if __name__ == "__main__":
    unittest.main()
