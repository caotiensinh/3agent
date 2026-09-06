import hashlib
import importlib.util
import json
import socket
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
ACCEPT_SCRIPT = REPO_ROOT / "scripts" / "accept_hf_model_candidate.py"
REVISION = "a" * 40
MODEL_ID = "qwen3-embedding-0.6b"


def _load_acceptance_module():
    spec = importlib.util.spec_from_file_location(
        "workspace_model_candidate_acceptance",
        ACCEPT_SCRIPT,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load candidate acceptance runner")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ACCEPT = _load_acceptance_module()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _prepare_snapshot(root: Path):
    snapshot = root / "snapshot"
    snapshot.mkdir()
    files = {
        "config.json": b"{}",
        "model.safetensors": b"weights",
    }
    for relative, data in files.items():
        path = snapshot / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    evidence = {
        "schema": "workspace.model-candidate-evidence/v1",
        "status": "candidate_only",
        "source": "huggingface",
        "repo_id": "Example/EmbeddingModel",
        "revision": REVISION,
        "runtime_download": False,
        "artifacts": [
            {
                "path": relative,
                "sha256": _sha256(data),
                "size_bytes": len(data),
            }
            for relative, data in sorted(files.items())
        ],
        "approval": {
            "approved": False,
            "reason": "candidate evidence only",
        },
    }
    return snapshot, evidence


class FakeEmbeddingModel:
    def __init__(self, *, normalized=True, attempt_network=False):
        self.normalized = normalized
        self.attempt_network = attempt_network
        self.to_calls = []

    def _vectors(self, inputs, kwargs):
        if self.attempt_network:
            sock = socket.socket()
            try:
                sock.connect(("127.0.0.1", 9))
            finally:
                sock.close()
        dimensions = int(kwargs["truncate_dim"])
        if self.normalized:
            vector = [1.0] + [0.0] * (dimensions - 1)
        else:
            vector = [1.0] * dimensions
        return [list(vector) for _ in inputs]

    def encode_query(self, inputs, **kwargs):
        return self._vectors(inputs, kwargs)

    def encode_document(self, inputs, **kwargs):
        return self._vectors(inputs, kwargs)

    def to(self, device):
        self.to_calls.append(device)
        return self


class CandidateEvidenceTests(unittest.TestCase):
    def test_candidate_evidence_cannot_arrive_preapproved(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, raw = _prepare_snapshot(Path(tmp))
            raw["approval"]["approved"] = True
            with self.assertRaisesRegex(
                ACCEPT.CandidateAcceptanceError,
                "must not already grant approval",
            ):
                ACCEPT.parse_candidate_evidence(raw)

    def test_candidate_evidence_requires_exact_revision_and_safe_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            _, raw = _prepare_snapshot(Path(tmp))
            raw["revision"] = "main"
            with self.assertRaisesRegex(ACCEPT.CandidateAcceptanceError, "40-character"):
                ACCEPT.parse_candidate_evidence(raw)

            _, raw = _prepare_snapshot(Path(tmp) / "second")
            raw["artifacts"][0]["path"] = "../config.json"
            with self.assertRaisesRegex(ACCEPT.CandidateAcceptanceError, "unsafe"):
                ACCEPT.parse_candidate_evidence(raw)


class CandidateRuntimeAcceptanceTests(unittest.TestCase):
    def test_happy_path_proves_offline_embedding_and_residency_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, raw = _prepare_snapshot(root)
            evidence = ACCEPT.parse_candidate_evidence(raw)
            loaded_paths = []
            models = []

            def loader(path):
                loaded_paths.append(path)
                model = FakeEmbeddingModel()
                models.append(model)
                return model

            payload = ACCEPT.accept_candidate(
                evidence=evidence,
                snapshot_root=snapshot,
                model_id=MODEL_ID,
                dimensions=32,
                batch_size=2,
                queries=["router fault", "camera offline"],
                documents=["uplink packet loss", "PoE budget exceeded"],
                loader=loader,
            )

            self.assertEqual(payload["schema"], "workspace.model-candidate-acceptance/v1")
            self.assertEqual(payload["status"], "runtime_acceptance_pass")
            self.assertFalse(payload["approval"]["approved"])
            self.assertFalse(payload["runtime"]["runtime_download"])
            self.assertEqual(payload["runtime"]["HF_HUB_OFFLINE"], "1")
            self.assertEqual(payload["runtime"]["TRANSFORMERS_OFFLINE"], "1")
            self.assertEqual(payload["runtime"]["python_socket_attempts"], 0)
            self.assertTrue(payload["checks"]["residency_eviction"])
            self.assertGreaterEqual(payload["checks"]["integrity_resolve_calls"], 2)
            self.assertEqual(payload["checks"]["query_embedding"]["dimensions"], 32)
            self.assertEqual(payload["checks"]["document_embedding"]["dimensions"], 32)
            self.assertEqual(len(loaded_paths), 2)
            self.assertEqual(loaded_paths, [snapshot.resolve(), snapshot.resolve()])
            self.assertEqual(models[0].to_calls, ["cpu"])

    def test_tampered_candidate_bytes_fail_before_model_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, raw = _prepare_snapshot(root)
            evidence = ACCEPT.parse_candidate_evidence(raw)
            (snapshot / "model.safetensors").write_bytes(b"WEIGHTS")
            loader_calls = []

            with self.assertRaisesRegex(ACCEPT.CandidateAcceptanceError, "SHA-256 mismatch"):
                ACCEPT.accept_candidate(
                    evidence=evidence,
                    snapshot_root=snapshot,
                    model_id=MODEL_ID,
                    dimensions=32,
                    batch_size=1,
                    queries=["query"],
                    documents=["document"],
                    loader=lambda path: loader_calls.append(path) or FakeEmbeddingModel(),
                )
            self.assertEqual(loader_calls, [])

    def test_unapproved_extra_file_fails_before_model_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, raw = _prepare_snapshot(root)
            evidence = ACCEPT.parse_candidate_evidence(raw)
            (snapshot / "remote_code.py").write_text("raise SystemExit", encoding="utf-8")
            with self.assertRaisesRegex(ACCEPT.CandidateAcceptanceError, "unapproved files"):
                ACCEPT.accept_candidate(
                    evidence=evidence,
                    snapshot_root=snapshot,
                    model_id=MODEL_ID,
                    dimensions=32,
                    batch_size=1,
                    queries=["query"],
                    documents=["document"],
                    loader=lambda _: FakeEmbeddingModel(),
                )

    def test_non_normalized_embedding_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, raw = _prepare_snapshot(root)
            evidence = ACCEPT.parse_candidate_evidence(raw)
            with self.assertRaisesRegex(ACCEPT.CandidateAcceptanceError, "not normalized"):
                ACCEPT.accept_candidate(
                    evidence=evidence,
                    snapshot_root=snapshot,
                    model_id=MODEL_ID,
                    dimensions=32,
                    batch_size=1,
                    queries=["query"],
                    documents=["document"],
                    loader=lambda _: FakeEmbeddingModel(normalized=False),
                )

    def test_runtime_socket_attempt_is_blocked(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot, raw = _prepare_snapshot(root)
            evidence = ACCEPT.parse_candidate_evidence(raw)
            with self.assertRaisesRegex(ACCEPT.CandidateAcceptanceError, "network attempt blocked"):
                ACCEPT.accept_candidate(
                    evidence=evidence,
                    snapshot_root=snapshot,
                    model_id=MODEL_ID,
                    dimensions=32,
                    batch_size=1,
                    queries=["query"],
                    documents=["document"],
                    loader=lambda _: FakeEmbeddingModel(attempt_network=True),
                )

    def test_acceptance_runner_has_no_download_or_manifest_approval_path(self):
        source = ACCEPT_SCRIPT.read_text(encoding="utf-8")
        for forbidden in (
            "huggingface_hub",
            "snapshot_download",
            "hf_hub_download",
            "models.approved.json",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn('"approved": False', source)
        self.assertIn("apply_runtime_offline_environment", source)
        self.assertIn("local_files_only", source)
        self.assertIn("trust_remote_code", source)


if __name__ == "__main__":
    unittest.main()
