import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from three_agent.local_ai_runtime import (
    LOCAL_AI_STATUS_SCHEMA,
    LocalAIRuntimeError,
    LocalAIRuntimeRegistry,
    LocalAIRuntimeSpec,
    LocalAIStatusService,
    default_local_ai_runtime_registry,
)
from three_agent.model_artifacts import ApprovedModelManifest, write_provision_receipt


class FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def read(self, size=-1):
        if size is None or size < 0:
            return self.payload
        return self.payload[:size]


class LocalAIRuntimeBoundaryTests(unittest.TestCase):
    def test_ollama_accepts_loopback_origins_only(self):
        for endpoint in (
            "http://127.0.0.1:11434",
            "http://127.77.3.4:11434/",
            "http://localhost:11434",
            "http://[::1]:11434",
        ):
            spec = LocalAIRuntimeSpec("ollama-local", "ollama", endpoint)
            self.assertTrue(spec.endpoint.startswith("http"))

    def test_public_and_private_lan_runtime_endpoints_fail_closed(self):
        for endpoint in (
            "http://8.8.8.8:11434",
            "http://192.168.1.20:11434",
            "http://10.0.0.5:8000",
            "http://172.16.5.10:8000",
            "https://example.com",
            "http://localhost.example.com:11434",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaisesRegex(LocalAIRuntimeError, "loopback"):
                    LocalAIRuntimeSpec("unsafe", "ollama", endpoint)

    def test_runtime_origin_rejects_credentials_path_query_and_fragment(self):
        for endpoint in (
            "http://user:pass@localhost:11434",
            "http://localhost:11434/api",
            "http://localhost:11434/?model=x",
            "http://localhost:11434/#fragment",
        ):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(LocalAIRuntimeError):
                    LocalAIRuntimeSpec("unsafe", "ollama", endpoint)

    def test_registry_rejects_duplicate_runtime_ids(self):
        registry = LocalAIRuntimeRegistry(
            [LocalAIRuntimeSpec("hf-local", "huggingface_local")]
        )
        with self.assertRaisesRegex(LocalAIRuntimeError, "duplicate"):
            registry.register(LocalAIRuntimeSpec("hf-local", "huggingface_local"))

    def test_health_timeout_is_bounded(self):
        registry = LocalAIRuntimeRegistry()
        for timeout in (0, 0.09, 10.1, 100):
            with self.subTest(timeout=timeout):
                with self.assertRaisesRegex(LocalAIRuntimeError, "timeout"):
                    LocalAIStatusService(registry, timeout_seconds=timeout)


class LocalAIStatusServiceTests(unittest.TestCase):
    def test_ollama_status_uses_get_tags_and_never_grants_authority(self):
        calls = []

        def opener(request, timeout):
            calls.append((request.full_url, request.get_method(), timeout))
            return FakeResponse(
                json.dumps(
                    {
                        "models": [
                            {"name": "qwen3.6:35b"},
                            {"model": "foundation-sec:8b"},
                        ]
                    }
                ).encode()
            )

        registry = LocalAIRuntimeRegistry(
            [
                LocalAIRuntimeSpec(
                    "ollama-local",
                    "ollama",
                    "http://127.0.0.1:11434",
                    ("qwen3.6:35b", "missing:1b"),
                )
            ]
        )
        snapshot = LocalAIStatusService(registry, opener=opener).snapshot()
        self.assertEqual(snapshot["schema_version"], LOCAL_AI_STATUS_SCHEMA)
        self.assertEqual(calls, [("http://127.0.0.1:11434/api/tags", "GET", 2.0)])
        self.assertFalse(snapshot["runtime_download"])
        self.assertFalse(snapshot["grants_model_authority"])
        self.assertFalse(snapshot["grants_capability_authority"])
        self.assertEqual(snapshot["authority"], "observation")
        statuses = {item["model_id"]: item for item in snapshot["models"]}
        self.assertTrue(statuses["qwen3.6:35b"]["available"])
        self.assertFalse(statuses["missing:1b"]["available"])
        self.assertTrue(all(not item["runtime_authority"] for item in snapshot["models"]))

    def test_missing_ollama_is_reported_unavailable_not_raised(self):
        def opener(_request, _timeout):
            raise ConnectionRefusedError("offline")

        registry = LocalAIRuntimeRegistry(
            [
                LocalAIRuntimeSpec(
                    "ollama-local",
                    "ollama",
                    "http://localhost:11434",
                    ("qwen3.6:35b",),
                )
            ]
        )
        snapshot = LocalAIStatusService(registry, opener=opener).snapshot()
        runtime = snapshot["runtimes"][0]
        self.assertFalse(runtime["healthy"])
        self.assertFalse(runtime["available"])
        self.assertEqual(runtime["reason_code"], "RUNTIME_UNAVAILABLE")
        self.assertEqual(snapshot["models"][0]["reason_code"], "RUNTIME_UNAVAILABLE")

    def test_empty_approved_manifest_is_healthy_but_has_no_available_models(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "models.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "workspace.model-manifest/v1",
                        "runtime_download": False,
                        "models": [],
                    }
                ),
                encoding="utf-8",
            )
            registry = LocalAIRuntimeRegistry(
                [LocalAIRuntimeSpec("hf-local", "huggingface_local")]
            )
            snapshot = LocalAIStatusService(
                registry,
                manifest_path=manifest,
                model_store=root / "store",
            ).snapshot()
            runtime = snapshot["runtimes"][0]
            self.assertTrue(runtime["healthy"])
            self.assertFalse(runtime["available"])
            self.assertEqual(runtime["reason_code"], "NO_APPROVED_MODELS")
            self.assertEqual(snapshot["models"], [])

    def test_approved_but_missing_hf_model_is_not_downloaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"weights"
            manifest_path = root / "models.json"
            manifest_path.write_text(
                json.dumps(
                    {
                        "schema": "workspace.model-manifest/v1",
                        "runtime_download": False,
                        "models": [
                            {
                                "id": "securebert",
                                "provider": "huggingface",
                                "repo_id": "Example/SecureBERT",
                                "revision": "a" * 40,
                                "local_subdir": "securebert",
                                "capabilities": ["retrieval.embedding"],
                                "license": "apache-2.0",
                                "artifacts": [
                                    {
                                        "path": "model.safetensors",
                                        "sha256": hashlib.sha256(data).hexdigest(),
                                        "size_bytes": len(data),
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            registry = LocalAIRuntimeRegistry(
                [LocalAIRuntimeSpec("hf-local", "huggingface_local")]
            )
            snapshot = LocalAIStatusService(
                registry,
                manifest_path=manifest_path,
                model_store=root / "missing-store",
            ).snapshot()
            self.assertEqual(snapshot["models"][0]["model_id"], "securebert")
            self.assertFalse(snapshot["models"][0]["installed"])
            self.assertEqual(
                snapshot["models"][0]["reason_code"],
                "MODEL_NOT_PROVISIONED_OR_INVALID",
            )
            self.assertFalse((root / "missing-store").exists())

    def test_integrity_verified_hf_model_is_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            data = b"verified-safe-weights"
            manifest_path = root / "models.json"
            payload = {
                "schema": "workspace.model-manifest/v1",
                "runtime_download": False,
                "models": [
                    {
                        "id": "securebert",
                        "provider": "huggingface",
                        "repo_id": "Example/SecureBERT",
                        "revision": "b" * 40,
                        "local_subdir": "securebert",
                        "capabilities": ["retrieval.embedding"],
                        "license": "apache-2.0",
                        "artifacts": [
                            {
                                "path": "model.safetensors",
                                "sha256": hashlib.sha256(data).hexdigest(),
                                "size_bytes": len(data),
                            }
                        ],
                    }
                ],
            }
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")
            manifest = ApprovedModelManifest.load(manifest_path)
            model_root = root / "store" / "securebert"
            model_root.mkdir(parents=True)
            (model_root / "model.safetensors").write_bytes(data)
            write_provision_receipt(manifest, manifest.models[0], model_root)

            registry = LocalAIRuntimeRegistry(
                [LocalAIRuntimeSpec("hf-local", "huggingface_local")]
            )
            snapshot = LocalAIStatusService(
                registry,
                manifest_path=manifest_path,
                model_store=root / "store",
            ).snapshot()
            self.assertTrue(snapshot["runtimes"][0]["available"])
            self.assertTrue(snapshot["models"][0]["available"])
            self.assertEqual(snapshot["models"][0]["reason_code"], "MODEL_AVAILABLE")

    def test_invalid_manifest_fails_closed_as_status(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            manifest = root / "models.json"
            manifest.write_text('{"runtime_download": true}', encoding="utf-8")
            registry = LocalAIRuntimeRegistry(
                [LocalAIRuntimeSpec("hf-local", "huggingface_local")]
            )
            snapshot = LocalAIStatusService(registry, manifest_path=manifest).snapshot()
            runtime = snapshot["runtimes"][0]
            self.assertFalse(runtime["healthy"])
            self.assertFalse(runtime["available"])
            self.assertEqual(runtime["reason_code"], "MODEL_MANIFEST_INVALID")

    def test_default_registry_is_derived_from_trusted_config_only(self):
        config = SimpleNamespace(
            llm=SimpleNamespace(
                provider="ollama",
                base_url="http://127.0.0.1:11434",
                model="qwen3.6:35b",
            ),
            model_policy=SimpleNamespace(
                enabled=True,
                fast_model="qwen3.6:35b",
                research_model="foundation-sec:8b",
                presentation_model="qwen3.6:35b",
                report_model="qwen3.6:35b",
                deep_model="foundation-sec-reasoning:8b",
            ),
        )
        specs = default_local_ai_runtime_registry(config).specs()
        self.assertEqual([item.runtime_id for item in specs], ["huggingface-local", "ollama-local"])
        ollama = specs[1]
        self.assertEqual(
            ollama.configured_models,
            ("qwen3.6:35b", "foundation-sec:8b", "foundation-sec-reasoning:8b"),
        )

    def test_runtime_module_contains_no_model_acquisition_or_pull_path(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "three_agent"
            / "local_ai_runtime.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "huggingface_hub",
            "snapshot_download",
            "hf_hub_download",
            "/api/pull",
            "/api/create",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("/api/tags", source)


if __name__ == "__main__":
    unittest.main()
