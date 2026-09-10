import tempfile
import unittest
from pathlib import Path

from three_agent.local_embedding import (
    LocalEmbeddingAdapter,
    LocalSentenceTransformerBackend,
)
from three_agent.model_residency import ModelResidencyConfig, ModelResidencyManager


class FakeResolver:
    def __init__(self, path: Path):
        self.path = path
        self.calls = []

    def resolve(self, model_id: str) -> Path:
        self.calls.append(model_id)
        return self.path


class FakeEmbeddingModel:
    def __init__(self):
        self.query_calls = []
        self.document_calls = []
        self.to_calls = []

    def encode_query(self, inputs, **kwargs):
        self.query_calls.append((list(inputs), dict(kwargs)))
        return [[1.0, 0.0] for _ in inputs]

    def encode_document(self, inputs, **kwargs):
        self.document_calls.append((list(inputs), dict(kwargs)))
        return [[0.0, 1.0] for _ in inputs]

    def to(self, device):
        self.to_calls.append(device)
        return self


class LocalEmbeddingAdapterTests(unittest.TestCase):
    def prepare(self, root: Path, *, idle_ttl_seconds=120.0):
        verified = root / "verified-model"
        verified.mkdir()
        resolver = FakeResolver(verified)
        loaded_paths = []
        model = FakeEmbeddingModel()

        def loader(path: Path):
            loaded_paths.append(path)
            return model

        backend = LocalSentenceTransformerBackend(resolver, loader=loader)
        residency = ModelResidencyManager(
            backend,
            ModelResidencyConfig(idle_ttl_seconds=idle_ttl_seconds),
            lock_root=root / "locks",
        )
        adapter = LocalEmbeddingAdapter(
            resolver,
            backend=backend,
            residency=residency,
            dimensions=256,
            batch_size=8,
        )
        return adapter, resolver, backend, model, loaded_paths, verified

    def test_loader_receives_only_resolver_verified_local_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            adapter, resolver, backend, _, loaded_paths, verified = self.prepare(root)
            adapter.encode_queries(["router fault"])
            self.assertEqual(resolver.calls, ["qwen3-embedding-0.6b"])
            self.assertEqual(loaded_paths, [verified.resolve()])
            self.assertEqual(
                backend.loaded_path("qwen3-embedding-0.6b"),
                verified.resolve(),
            )

    def test_queries_use_query_api_with_normalization_and_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter, _, _, model, _, _ = self.prepare(Path(tmp))
            result = adapter.encode_queries(["switch loop", "camera offline"])
            self.assertEqual(result, [[1.0, 0.0], [1.0, 0.0]])
            inputs, kwargs = model.query_calls[0]
            self.assertEqual(inputs, ["switch loop", "camera offline"])
            self.assertEqual(kwargs["batch_size"], 8)
            self.assertTrue(kwargs["normalize_embeddings"])
            self.assertEqual(kwargs["truncate_dim"], 256)
            self.assertFalse(kwargs["show_progress_bar"])
            self.assertTrue(kwargs["convert_to_numpy"])
            self.assertEqual(model.document_calls, [])

    def test_documents_use_document_api_without_query_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter, _, _, model, _, _ = self.prepare(Path(tmp))
            result = adapter.encode_documents(["PoE budget exceeded"])
            self.assertEqual(result, [[0.0, 1.0]])
            inputs, kwargs = model.document_calls[0]
            self.assertEqual(inputs, ["PoE budget exceeded"])
            self.assertTrue(kwargs["normalize_embeddings"])
            self.assertEqual(kwargs["truncate_dim"], 256)
            self.assertEqual(model.query_calls, [])

    def test_model_is_reused_until_residency_evicts_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter, resolver, backend, model, loaded_paths, _ = self.prepare(
                Path(tmp), idle_ttl_seconds=0.0
            )
            adapter.encode_queries(["first"])
            adapter.encode_documents(["second"])
            self.assertEqual(len(loaded_paths), 1)
            self.assertEqual(len(resolver.calls), 1)
            self.assertEqual(backend.resident_models(), {"qwen3-embedding-0.6b"})
            self.assertEqual(adapter.evict_idle(), ("qwen3-embedding-0.6b",))
            self.assertEqual(backend.resident_models(), set())
            self.assertEqual(model.to_calls, ["cpu"])

    def test_snapshot_declares_runtime_download_forbidden(self):
        with tempfile.TemporaryDirectory() as tmp:
            adapter, *_ = self.prepare(Path(tmp))
            snapshot = adapter.snapshot()
            self.assertFalse(snapshot["runtime_download"])
            self.assertEqual(snapshot["embedding_model_id"], "qwen3-embedding-0.6b")
            self.assertEqual(snapshot["embedding_dimensions"], 256)

    def test_invalid_dimensions_and_empty_inputs_fail_before_loading(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            verified = root / "verified"
            verified.mkdir()
            resolver = FakeResolver(verified)
            backend = LocalSentenceTransformerBackend(
                resolver,
                loader=lambda _: FakeEmbeddingModel(),
            )
            with self.assertRaisesRegex(ValueError, "dimensions"):
                LocalEmbeddingAdapter(resolver, backend=backend, dimensions=31)
            adapter = LocalEmbeddingAdapter(resolver, backend=backend)
            with self.assertRaisesRegex(ValueError, "at least one input"):
                adapter.encode_queries([])
            with self.assertRaisesRegex(ValueError, "empty text"):
                adapter.encode_documents(["valid", "  "])
            self.assertEqual(resolver.calls, [])

    def test_mismatched_residency_backend_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            verified = root / "verified"
            verified.mkdir()
            resolver = FakeResolver(verified)
            backend_a = LocalSentenceTransformerBackend(
                resolver, loader=lambda _: FakeEmbeddingModel()
            )
            backend_b = LocalSentenceTransformerBackend(
                resolver, loader=lambda _: FakeEmbeddingModel()
            )
            residency = ModelResidencyManager(backend_b, lock_root=root / "locks")
            with self.assertRaisesRegex(ValueError, "same backend"):
                LocalEmbeddingAdapter(
                    resolver,
                    backend=backend_a,
                    residency=residency,
                )

    def test_runtime_source_contains_no_remote_model_acquisition(self):
        source = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "three_agent"
            / "local_embedding.py"
        ).read_text(encoding="utf-8")
        for forbidden in (
            "huggingface_hub",
            "snapshot_download",
            "requests.",
            "urllib.request",
            "urlopen(",
            "hf_hub_download",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("local_files_only=True", source)
        self.assertIn("trust_remote_code=False", source)


if __name__ == "__main__":
    unittest.main()
